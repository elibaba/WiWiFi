import subprocess
import os
import signal
import time

class HotspotManager:
    def __init__(self, interface="wlan0", ssid="WiWiFi_Free"):
        self.interface = interface
        self.ssid = ssid
        self.hostapd_proc = None
        self.dnsmasq_proc = None
        self.conf_dir = os.path.join(os.path.dirname(__file__), "conf")
        os.makedirs(self.conf_dir, exist_ok=True)

    def _generate_hostapd_conf(self):
        conf_path = os.path.join(self.conf_dir, "hostapd.conf")
        content = f"""
interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel=6
auth_algs=1
wpa=0
"""
        with open(conf_path, "w") as f:
            f.write(content.strip())
        return conf_path

    def _generate_dnsmasq_conf(self):
        conf_path = os.path.join(self.conf_dir, "dnsmasq.conf")
        content = f"""
interface={self.interface}
dhcp-range=192.168.1.50,192.168.1.150,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
"""
        with open(conf_path, "w") as f:
            f.write(content.strip())
        return conf_path

    def start(self):
        print("Starting hotspot...")
        try:
            # Set interface IP
            subprocess.run(["sudo", "ip", "addr", "add", "192.168.1.1/24", "dev", self.interface], capture_output=True)
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], capture_output=True)
            
            hostapd_conf = self._generate_hostapd_conf()
            dnsmasq_conf = self._generate_dnsmasq_conf()
            
            self.hostapd_proc = subprocess.Popen(["sudo", "hostapd", hostapd_conf], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.dnsmasq_proc = subprocess.Popen(["sudo", "dnsmasq", "-C", dnsmasq_conf, "-d"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            print("Hotspot services launched.")
            return True
        except Exception as e:
            print(f"Failed to start hotspot: {e}")
            return False

    def stop(self):
        print("Stopping hotspot...")
        if self.hostapd_proc:
            subprocess.run(["sudo", "kill", str(self.hostapd_proc.pid)], capture_output=True)
            self.hostapd_proc = None
        if self.dnsmasq_proc:
            subprocess.run(["sudo", "kill", str(self.dnsmasq_proc.pid)], capture_output=True)
            self.dnsmasq_proc = None
        
        subprocess.run(["sudo", "ip", "addr", "del", "192.168.1.1/24", "dev", self.interface], capture_output=True)
        print("Hotspot stopped.")

if __name__ == "__main__":
    manager = HotspotManager()
    manager.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop()
