from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp
import time
import sys
import random

def send_dns_query(domain, interface="wlan0", src_ip="192.168.1.100", src_mac="00:11:22:33:44:55"):
    print(f"Sending DNS query for {domain} from {src_ip} ({src_mac})...")
    pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / \
          IP(src=src_ip, dst="8.8.8.8") / \
          UDP(sport=random.randint(1024, 65535), dport=53) / \
          DNS(rd=1, qd=DNSQR(qname=domain))
    
    sendp(pkt, iface=interface, verbose=False)

if __name__ == "__main__":
    interface = "lo" # Default to loopback for safe testing
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    
    test_domains = ["google.com", "example.com", "wiwifi.test", "mybank.com"]
    
    print(f"DNS Test Script started on interface: {interface}")
    try:
        while True:
            domain = random.choice(test_domains)
            send_dns_query(domain, interface=interface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nTest script stopped.")
