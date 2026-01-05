# WiWiFi - Network Traffic Sniffer & Analysis Tool

WiWiFi is a powerful Python-based application designed to open an unprotected WiFi hotspot and capture/analyze network traffic passing through it. It features a modern Web UI for real-time monitoring and an "AI" component that scans for sensitive information such as PII, URLs, and names.

> [!WARNING]
> This tool is for **educational and analysis purposes only**. Use it only on hardware and networks you own or have explicit permission to test. Unauthorized interception of network traffic may be illegal.

## Features

- **Open Hotspot Creation**: Automated setup of `hostapd` and `dnsmasq` to create an unprotected WiFi access point.
- **Real-time Sniffing**: Captures IP traffic using Scapy.
- **AI Analysis Layer**: 
    - Automatically detects URLs, Email addresses, Phone numbers, and Social Security Numbers (PII).
    - Identifies potential names through pattern recognition.
- **Premium Web UI**:
    - Real-time traffic log.
    - Searchable payloads for specific phrases.
    - Filtering by Client MAC address and IP address.
    - "AI Insights" panel for floating up critical data points.
- **Simulation Mode**: Test the entire analysis and UI pipeline without requiring real WiFi hardware or root privileges.

## Project Structure

- `backend/`: FastAPI server, Sniffer logic, and Database management.
- `frontend/`: Vanilla JS/CSS Single Page Application.
- `scripts/`: Implementation scripts (setup/cleanup placeholders).
- `requirements.txt`: Python dependencies.

## Installation

### Prerequisites
- Linux OS (tested on gLinux/Rodete).
- Root privileges (for real hotspot/sniffing).
- WiFi hardware supporting AP Mode (if using for real hotspots).

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/elibaba/WiWiFi.git
   cd WiWiFi
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Run in Simulation Mode (Default)
This mode generates synthetic traffic for testing the UI and analysis logic:
```bash
export PYTHONPATH=$PYTHONPATH:.
python3 backend/main.py
```
Then navigate to `http://localhost:8000`.

### Run for Real Analysis
1. Ensure your WiFi interface (e.g., `wlan0`) is not managed by other network managers.
2. Run as root:
   ```bash
   sudo python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```
3. Use the UI to start the hotspot and sniffer on your specific interface.

## Disclaimer
The contributors to WiWiFi are not responsible for any misuse or damage caused by this tool. Use responsibly.
