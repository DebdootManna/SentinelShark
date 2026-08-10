# SentinelShark
> **Modern Desktop Network Intrusion Detection & Analysis System (NIDS)**

SentinelShark is a high-performance, modern Wireshark clone built with **Python 3.10+**, **PyQt6**, **PyShark**, and `httpx`. Tested and verified on both **macOS** and **Windows**, it dissects live network packets in real time and enriches public IP traffic with multi-provider threat intelligence and geolocation data from **VirusTotal**, **AbuseIPDB**, **IPinfo**, and **Shodan**.

![mock mode screenshot](image.png)

---

## Key Features

- **Cross-Platform Compatibility**: Fully tested, optimized, and verified on **macOS** and **Windows 10/11**.
- **Live Sniffing & PCAP / PCAPNG Import & Export**:
  - Sniff live interface traffic using line-buffered TShark subprocess streaming.
  - Export packet captures to standard `.pcap` and `.pcapng` files (100% native Wireshark compatibility).
  - Open `.pcap` / `.pcapng` files with an interactive **Threat Analysis Prompt** ("Do you want to analyze this file?").
- **Graceful Fallback & Mock Generator**: Built-in high-fidelity Mock Traffic Generator ensures SentinelShark functions out-of-the-box even when `tshark` is not installed on the host machine.
- **Quad-Provider Threat Intelligence & Geolocation**:
  - **Shodan Integration (Hybrid Fallback Chain)**: Queries host intelligence, open ports, vulnerability CVEs, CPE identifiers, hostnames, and tags via the Shodan Host API (`/shodan/host/{ip}`). Automatically falls back to the free **Shodan InternetDB API** (`https://internetdb.shodan.io/{ip}`) for free API keys or IPv6 targets to avoid HTTP 403 errors.
  - **VirusTotal Integration**: Queries malicious, suspicious, and harmless engine detection counts.
  - **AbuseIPDB Integration**: Queries Abuse Confidence Scores, total report counts, and reporting country.
  - **IPinfo Integration**: Queries hostname, organization, ASN, city, region, country, coordinates, timezone, postal code, anycast flags, and privacy indicators.
- **Smart BPF & Real-Time Search Filtering**:
  - **BPF Sanitizer**: Translates user-friendly shortcuts (`http`, `dns`, `https`, `ssh`, `8.8.8.8`) into valid BPF syntax for TShark while gracefully handling syntax errors.
  - **Live Table Filter**: Instantly filters packet rows as you type in the search bar.
- **Smart Private & IPv6 Filtering**: Automatically filters RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks, and unrouted addresses to conserve API quota.
- **Non-Blocking Asynchronous Capture Control**: Subprocess lifecycle management ensures zero main GUI thread freezing or lag when toggling capture start/stop actions.
- **Figma Dark-Mode GUI Architecture**:
  - **Toolbar Controls**: Modern sleek buttons (`Start Capture`, `Stop`, `Clear`, `Save`, `Mock ON/OFF`, `API Keys`) with active capture status indicators.
  - **Packet Table**: Color-coded rows highlighting threat severity (Red = Critical Threat, Amber = Medium Risk, Green = Safe Public IP).
  - **Packet Inspector Tree**: Interactive collapsible tree breaking down Ethernet, IP, TCP/UDP, DNS, HTTP, and TLS layers alongside multi-provider threat intelligence.
  - **Hex Dump Inspector**: Dual Hex & ASCII byte viewer with payload MD5 & SHA256 hashing.
  - **Collapsible Dashboard Right Sidebar**: Metrics grid (`TOTAL PACKETS`, `DATA TRAFFIC`, `SAFE PACKETS`, `THREATS DETECTED`), `PROTOCOL BREAKDOWN`, `THREAT INTEL API QUEUE`, and `SELECTED PACKET` summary cards equipped with header minimize/expand buttons and static font layouts.

---

## Repository Structure

```
sentinelshark/
├── README.md                  # Complete documentation
├── requirements.txt           # Dependency manifest
├── config.json.example        # Configuration template
├── run.py                     # Root execution entrypoint
├── tests/
│   └── test_sentinelshark.py  # Unit test suite
└── app/
    ├── __init__.py
    ├── main.py                # PyQt6 + qasync event loop launcher (Windows/macOS compatible)
    ├── config.py              # Configuration & API Key manager
    ├── core/
    │   ├── capture.py         # Non-blocking TShark subprocess & Mock capture worker thread
    │   ├── parser.py          # Protocol dissector & Hex/ASCII formatter
    │   ├── pcapwriter.py      # Native binary PCAP / PCAPNG file exporter
    │   └── cache.py           # In-memory TTL threat cache manager
    ├── services/
    │   ├── threatintel.py     # Async VirusTotal, AbuseIPDB, IPinfo & Shodan (InternetDB fallback) client
    │   └── queuemanager.py    # Prioritized lookup queue & rate limiter
    └── ui/
        ├── mainwindow.py      # Main application window, menu shortcuts & toolbar
        ├── styles.py          # Modern dark-mode QSS stylesheet
        └── components/
            ├── packettable.py # Color-coded packet list widget
            ├── packetdetail.py# Interactive layer dissection tree & threat inspector
            ├── hexview.py     # Hex & ASCII byte inspector
            └── statspanel.py  # Collapsible card dashboard panel
```

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- (Optional) `tshark` / `Wireshark` (Npcap on Windows) installed for live sniffing on host interfaces. If `tshark` is missing, SentinelShark automatically switches to **Mock Mode**.

### 2. Installation
```bash
# Clone repository
git clone https://github.com/DebdootManna/sentinelshark.git
cd sentinelshark

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Running the Application

```bash
# Standard Execution (Sniffs live interface or falls back to Mock Mode)
python run.py

# Elevated Execution on macOS (Required for raw /dev/bpf live interface sniffing)
sudo ./venv/bin/python run.py
```

---

## PCAP & PCAPNG File Capabilities

- **Saving Captures**: Navigate to **File -> Save Capture As...** (`Ctrl+S` / `Cmd+S`) or click **Save** on the toolbar. Saves raw packet payloads to standard `.pcap` or `.pcapng` files (100% compatible with Wireshark and TShark).
- **Opening Captures**: Navigate to **File -> Open PCAP File...** (`Ctrl+O` / `Cmd+O`).
  - Displays a prompt: *"This file has not been analyzed. Do you want to analyze it?"*
  - **Yes**: Analyzes public IP traffic with VirusTotal, AbuseIPDB, IPinfo, and Shodan threat intelligence.
  - **No**: Loads the capture without API threat lookups, leaving threat intel inspector sections un-analyzed.

---

## Threat Intelligence API Configuration

You can configure API keys via environment variables or inside the GUI:

1. **Environment Variables**:
   ```bash
   export VIRUSTOTAL_API_KEY="your_virustotal_key"
   export ABUSEIPDB_API_KEY="your_abuseipdb_key"
   export SHODAN_API_KEY="your_shodan_key"
   export IPINFO_API_KEY="your_ipinfo_key"
   ```
2. **GUI Settings Modal**:
   - Click **API Keys** on the toolbar or navigate to **Settings -> API Credentials...**
   - Enter your VirusTotal, AbuseIPDB, Shodan, and IPinfo API keys and click **Save Settings**. Credentials automatically save to `.env`.

---

## Running Unit Tests

Run the test suite to verify core components, IP filtering, BPF sanitization, in-memory TTL caching, PCAP exporter, and packet dissector logic:
```bash
python -m unittest discover tests
```

---

## Design & Aesthetics
SentinelShark features a Figma-inspired cyber dark mode (`#0F172A`, `#131C2B`, `#1E293B`) with neon cyan accents (`#22D3EE`), emerald safe indicators (`#22C55E`), amber risk warnings (`#F59E0B`), and crimson threat highlights (`#EF4444`).
