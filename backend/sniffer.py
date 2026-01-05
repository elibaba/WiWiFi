from scapy.all import sniff, IP, TCP, UDP, Raw
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

    def _process_packet(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_mac = pkt.src
            payload = ""
            
            if Raw in pkt:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                except Exception:
                    pass
            
            if payload:
                analysis = analyze_payload(payload)
                save_packet(src_ip, src_mac, dst_ip, payload, analysis)

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
        
        while self.running:
            src_ip = random.choice(ips)
            dst_ip = "8.8.8.8"
            src_mac = macs[ips.index(src_ip)]
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
