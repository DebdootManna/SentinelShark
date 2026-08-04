# SentinelShark
> **Modern Desktop Network Intrusion Detection & Analysis System (NIDS)**

SentinelShark is a high-performance, modern Wireshark clone built with **Python 3.10+**, **PyQt6**, **PyShark**, `httpx`, and **SQLite**. It dissects live network packets in real time and enriches public IP traffic with real-time threat intelligence and geolocation data from **VirusTotal**, **AbuseIPDB**, and **IPinfo**.

![mock mode screenshot](image.png)

---

## Key Features

- **Live & Offline Packet Capture**: Sniff live interface traffic using `PyShark` or analyze `.pcap` / `.pcapng` capture files.
- **Graceful Fallback & Mock Generator**: Built-in high-fidelity Mock Traffic Generator ensures SentinelShark functions out-of-the-box even when `tshark` is not installed on the system.
- **Threat Intelligence & Geolocation Enrichment**:
  - **AbuseIPDB Integration**: Queries Abuse Confidence Scores, total reports, and country codes.
  - **VirusTotal Integration**: Queries IP malicious, suspicious, and harmless engine detection counts.
  - **IPinfo Integration**: Queries and displays complete IP details (hostname, organization, ASN, city, region, country, coordinates, timezone, postal code, anycast, privacy flags, abuse contacts, carrier info, etc.).
- **Smart Non-Routable IP Filtering**: Automatically skips RFC 1918 private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, link-local, and multicast addresses to conserve API limits.
- **SQLite & In-Memory TTL Caching**: Persists threat intelligence in `threatcache.db` with configurable TTL (24-hour default) and fast in-memory LRU caching.
- **Rate Limiting & Exponential Backoff**: Async background queue manager handles rate-limiting and automatically performs exponential backoff on HTTP 429 errors.
- **High-Performance PyQt6 UI**:
  - **Packet Table**: Color-coded rows (Green = Safe, Yellow = Medium Risk, Red = Critical Threat).
  - **Packet Inspector**: Interactive collapsible tree breaking down Ethernet, IP, TCP/UDP, DNS, HTTP, and TLS layers alongside exhaustive Threat Intel and IPinfo geolocation details.
  - **Hex Dump Inspector**: Dual Hex & ASCII byte viewer with payload MD5 & SHA256 hashing.
  - **NIDS Dashboard**: Live packet counts, data throughput metrics, protocol breakdown, and API queue progress bar.

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
    ├── main.py                # PyQt6 + qasync event loop launcher
    ├── config.py              # Configuration & API Key manager
    ├── core/
    │   ├── capture.py         # PyShark & Mock capture worker thread (QThread)
    │   ├── parser.py          # Protocol dissector & Hex/ASCII formatter
    │   └── cache.py           # SQLite persistent cache & TTL manager
    ├── services/
    │   ├── threatintel.py     # Async AbuseIPDB, VirusTotal & IPinfo httpx client
    │   └── queuemanager.py    # Prioritized lookup queue & rate limiter
    └── ui/
        ├── mainwindow.py      # Main application window & toolbar
        ├── styles.py          # Modern dark-mode QSS stylesheet
        └── components/
            ├── packettable.py # Color-coded packet list widget
            ├── packetdetail.py# Interactive layer dissection tree & IPinfo inspector
            ├── hexview.py     # Hex & ASCII byte inspector
            └── statspanel.py  # Live stats dashboard
```

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- (Optional) `tshark` / `Wireshark` installed for live sniffing on host interfaces. If `tshark` is missing, SentinelShark automatically switches to **Mock Mode**.

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
python run.py
```

---

## Threat Intelligence API Configuration

You can configure API keys via environment variables or inside the GUI:

1. **Environment Variables**:
   ```bash
   export ABUSEIPDB_API_KEY="your_abuseipdb_key"
   export VIRUSTOTAL_API_KEY="your_virustotal_key"
   export IPINFO_API_KEY="your_ipinfo_key"
   ```
2. **GUI Settings Modal**:
   - Click **API Keys** on the toolbar or navigate to **Settings -> API Credentials...**
   - Enter your AbuseIPDB, VirusTotal, and IPinfo API keys and click **OK**. Settings automatically save to `.env`.

---

## Running Unit Tests

Run the test suite to verify core components, IP filtering, and SQLite caching logic:
```bash
python -m unittest discover tests
```

---

## Design & Aesthetics
SentinelShark features a slate/cyber dark mode (`#0f172a`, `#1e293b`) with neon cyan accents (`#06b6d4`), emerald safe indicators (`#10b981`), and crimson threat highlights (`#ef4444`).
