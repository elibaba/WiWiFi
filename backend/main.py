from fastapi import FastAPI, Query, Body, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
from pydantic import BaseModel
import os

from .database import init_db, search_packets
from .sniffer import Sniffer
from .hotspot import HotspotManager

class DNSRule(BaseModel):
    target_ip: str
    domain: str
    spoof_ip: str

app = FastAPI(title="WiWiFi API")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
init_db()
sniffer = Sniffer(simulation=True)  # Default to simulation for safety
hotspot = HotspotManager()

@app.get("/api/packets")
async def get_packets(
    query: Optional[str] = None,
    mac: Optional[str] = None,
    ip: Optional[str] = None
):
    return search_packets(query, mac, ip)

@app.post("/api/control/sniffer/start")
async def start_sniffer(interface: str = "wlan0", simulation: bool = True):
    global sniffer
    sniffer.stop()
    sniffer = Sniffer(interface=interface, simulation=simulation)
    sniffer.start()
    return {"status": "started", "interface": interface, "simulation": simulation}

@app.post("/api/control/sniffer/stop")
async def stop_sniffer():
    sniffer.stop()
    return {"status": "stopped"}

@app.post("/api/control/hotspot/start")
async def start_hotspot(interface: str = "wlan0", ssid: str = "WiWiFi_Free"):
    success = hotspot.start()
    return {"status": "started" if success else "failed"}

@app.post("/api/control/hotspot/stop")
async def stop_hotspot():
    hotspot.stop()
    return {"status": "stopped"}

@app.get("/api/status")
async def get_status():
    return {
        "sniffer_running": sniffer.running,
        "sniffer_simulation": sniffer.simulation,
        "hotspot_running": hotspot.hostapd_proc is not None
    }

@app.get("/api/dns/rules")
async def get_dns_rules():
    rules = []
    for (ip, domain), spoof_ip in sniffer.spoof_rules.items():
        rules.append({"target_ip": ip, "domain": domain, "spoof_ip": spoof_ip})
    return rules

@app.post("/api/dns/rules")
async def add_dns_rule(rule: DNSRule):
    sniffer.add_spoof_rule(rule.target_ip, rule.domain, rule.spoof_ip)
    return {"status": "added"}

@app.delete("/api/dns/rules")
async def remove_dns_rule(target_ip: str, domain: str):
    print(f"DEBUG: Removing DNS rule for {target_ip} / {domain}")
    sniffer.remove_spoof_rule(target_ip, domain)
    return {"status": "removed"}

# Serve frontend
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
