# SentinelShark EDR
> **Real-Time Endpoint Detection & Response (EDR) & Chronicle SecOps Workstation**

SentinelShark is a high-performance **Endpoint Detection and Response (EDR)** and SecOps workstation built with **Python 3.10+**, **PyQt6**, **PyShark**, and `httpx`. Inspired by **Google SecOps (Chronicle)**, SentinelShark bridges host process telemetry with network packet dissection in real time—correlating network sockets to local processes, tagging **MITRE ATT&CK** techniques, normalizing events to the **Unified Data Model (UDM)**, and enabling instant **Active Incident Response (IR)** containment.

![mock mode screenshot](image.png)

---

## Key Capabilities

### 1. Real-Time Host Process & Socket Telemetry
- **Bidirectional Socket Correlation**: Continuously maps active network sockets `(src_ip, src_port, dst_ip, dst_port)` to host process metadata:
  - Process ID (**PID**) and Parent Process ID (**PPID**)
  - Process Name & Full Command Line Arguments
  - Executable Path & SHA-256 Binary Hash
  - User Privilege Context (e.g. `root`, user, system)
- **High-Frequency Background Cache Daemon**: Operates a 200ms background polling thread combining `psutil.net_connections` with an asynchronous macOS non-root fallback (`lsof -i -n -P`), ensuring zero-latency $O(1)$ packet enrichment without slowing down packet throughput (>500 pkts/s).
- **Graceful Fallback**: Automatically categorizes unmapped, transit, or kernel connections as `System / Kernel` or `—` for seamless forensic review.

### 2. Google SecOps Unified Data Model (UDM) Normalization
- **Standardized Schema**: Converts every network security event into Google SecOps (Chronicle) UDM JSON:
  - `metadata`: Event timestamp, event type (`NETWORK_CONNECTION`), product & vendor attribution.
  - `principal`: Endpoint IP, hostname, process details (PID, PPID, binary path, SHA-256), command line, and user identity.
  - `target`: Destination IP and destination port.
  - `network`: Application protocol and direction (`OUTBOUND`).
  - `security_result`: Severity classification (`CRITICAL`, `HIGH`, `MEDIUM`, `SAFE`), tagged MITRE threat names, and summary.
- **Embedded Monospace UDM Viewer**: Live syntax-styled JSON inspection with one-click **Copy UDM JSON** to system clipboard.

### 3. MITRE ATT&CK Heuristics & LOLBin Detection
- **Living-off-the-Land Binaries (LOLBins)**: Real-time detection of dual-use binaries (`curl`, `wget`, `python`, `bash`, `sh`, `zsh`, `powershell.exe`, `cmd.exe`, `nc`, `ncat`, `socat`) communicating externally over network sockets.
- **Automated MITRE Technique Tagging**:
  - `T1059` / `T1059.004`: Command & Scripting Interpreter (Unix Shells, Python, PowerShell)
  - `T1105`: Ingress Tool Transfer (`curl`, `wget`)
  - `T1095`: Non-Application Layer Protocol (`nc`, `socat`)
  - `T1071`: Application Layer Protocol (Web, TLS/HTTPS, C2 Channels)
  - `T1071.001`: Web Protocols (Unencrypted HTTP on port 80)
  - `T1071.004`: DNS Protocol (Plaintext DNS queries on port 53)
  - `T1021.004`: SSH Remote Services (Port 22)
  - `T1571`: Non-Standard Port Communication
- **Dynamic Severity Scoring**: Events are evaluated against threat intelligence, LOLBin execution, and heuristic thresholds to compute severity (`CRITICAL`, `HIGH`, `MEDIUM`, `SAFE`).

### 4. Active Containment & Incident Response (IR Actions)
SentinelShark provides immediate containment mechanisms directly from the workstation UI, secured by confirmation dialogs and executed asynchronously via background worker threads:
- ⛔ **Kill Process**: Immediately terminates the offending process (`psutil.Process.kill()`). Built-in safety guards strictly prevent termination of protected system processes (PID 0, PID 1, and SentinelShark itself).
- 🛡️ **Block Remote IP**: Automatically inserts firewall rules to drop all outbound traffic to malicious endpoints:
  - **Linux**: `iptables -I OUTPUT -d <ip> -j DROP`
  - **macOS / Darwin**: `pfctl -t sentinelshark_blocked -T add <ip>`
- 📦 **Quarantine Binary**: Safely isolates suspicious executables into `~/.sentinelshark/quarantine/<name>.<timestamp>.quarantined` and strips all execution permissions (`chmod 000`).

### 5. Multi-Provider Threat Intelligence & Geolocation
Enriches public destination IPs against 4 major threat intelligence providers:
- **VirusTotal**: Malicious, suspicious, and harmless engine detection counts.
- **AbuseIPDB**: Abuse Confidence Scores, total report counts, and reporting country.
- **Shodan (with InternetDB Fallback)**: Open ports, CVE vulnerabilities, CPEs, and host tags.
- **IPinfo**: Geolocation, ASN, organization, city, coordinates, and privacy/anycast flags.

### 6. Chronicle SecOps Workstation UI (Figma Dark Theme)
- **11-Column Live Telemetry Table**: `[No., Time, PID, Process, Source, Destination, Protocol, Length, MITRE, Severity, Info]` with PID accent styling, LOLBin red highlighting, and severity-driven row coloring.
- **3-Panel Incident Response Layout**:
  - **Left**: **Packet Inspection** tree featuring collapsible *Threat Intelligence Summary*, *Host & Process Forensics* (command line, binary path, SHA-256, lineage `init -> parent -> child`, user), and full protocol layer dissection.
  - **Center**: **Detection Detail** panel with alert status banner, telemetry key-values, interactive UDM JSON preview, and the IR Action toolbar.
  - **Right**: **Analytics & Raw Hex Tabs** with Top Talker Processes, MITRE ATT&CK Coverage distribution, Protocol Breakdown, Threat Intel API Queue progress, and raw byte inspection.

---

## Repository Structure

```
sentinelshark/
├── README.md                      # Complete documentation
├── requirements.txt               # Dependency manifest
├── config.json.example            # Configuration template
├── run.py                         # Application launcher entrypoint
├── tests/
│   └── test_sentinelshark.py      # Unit test suite (19 tests)
└── app/
    ├── __init__.py
    ├── main.py                    # PyQt6 + qasync event loop launcher
    ├── config.py                  # Configuration & API Key manager
    ├── core/
    │   ├── telemetry_enricher.py  # Background SocketCacheDaemon & process correlation
    │   ├── secops_engine.py       # Google SecOps UDM normalizer & MITRE heuristics
    │   ├── response_engine.py     # Active containment (Kill, Block IP, Quarantine)
    │   ├── capture.py             # TShark subprocess, PyShark fallback & Mock capture
    │   ├── parser.py              # Protocol dissector & Hex/ASCII formatter
    │   ├── pcapwriter.py          # Native binary PCAP / PCAPNG file exporter
    │   └── cache.py               # In-memory TTL threat cache manager
    ├── services/
    │   ├── threatintel.py         # Async VirusTotal, AbuseIPDB, IPinfo & Shodan client
    │   └── queuemanager.py        # Prioritized lookup queue & rate limiter
    └── ui/
        ├── mainwindow.py          # 3-Panel Chronicle workstation & IR signal coordinator
        ├── styles.py              # Figma GitHub-dark QSS stylesheet
        └── components/
            ├── packettable.py     # 11-Column telemetry table with EDR indicators
            ├── detectionpanel.py  # Alert banner, UDM JSON preview & IR action bar
            ├── packetdetail.py    # Host & Process Forensics tree inspector
            ├── hexview.py         # Dual Hex & ASCII byte inspector
            └── statspanel.py      # Top processes, MITRE coverage & protocol analytics
```

---

## Quick Start

### 1. Prerequisites
- **Python 3.10+**
- (Optional) `tshark` / `Wireshark` (Npcap on Windows) for live network interface sniffing. If `tshark` is not installed, SentinelShark automatically operates in **Mock Mode** with simulated EDR telemetry.

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

### 3. Running SentinelShark

```bash
# Standard Execution (Sniffs live interface or falls back to Mock Mode)
python run.py

# Elevated Execution on macOS (Required for raw /dev/bpf live interface sniffing)
sudo ./venv/bin/python run.py
```

> [!TIP]
> To test without administrative permissions or live traffic, toggle **Mock ON** in the toolbar to run high-speed simulated network traffic with EDR host process correlations and MITRE technique tags.

---

## PCAP / PCAPNG Import & Export

- **Saving Captures**: Navigate to **File -> Save Capture As...** (`Ctrl+S` / `Cmd+S`) or click **Save** in the toolbar to export standard `.pcap` or `.pcapng` files (100% compatible with Wireshark).
- **Opening Captures**: Navigate to **File -> Open PCAP File...** (`Ctrl+O` / `Cmd+O`). Prompts to optionally run threat intelligence analysis on historical traffic.

---

## Threat Intelligence API Configuration

Configure API keys via environment variables or inside the GUI:

1. **Environment Variables**:
   ```bash
   export VIRUSTOTAL_API_KEY="your_virustotal_key"
   export ABUSEIPDB_API_KEY="your_abuseipdb_key"
   export SHODAN_API_KEY="your_shodan_key"
   export IPINFO_API_KEY="your_ipinfo_key"
   ```
2. **Workstation GUI Modal**:
   - Click **API Keys** on the toolbar or navigate to **Settings -> API Credentials...**
   - Enter your credentials and click **Save Settings** (persisted securely to `.env`).

---

## Running Unit Tests

Execute the comprehensive unit test suite:
```bash
python -m unittest discover tests
```
The test suite validates:
- Background socket cache daemon & fallback handling
- Baseline and LOLBin MITRE ATT&CK heuristic evaluations
- Google SecOps UDM event normalization
- Response engine PID protection guards and IP blocking
- Packet table 11-column mapping & left alignment
- Analytics sidebar batch processing & progress bars
- Native PCAP/PCAPNG serialization
- In-memory TTL threat caching & IP filtering

---

## Design System & Theme
Built according to the Figma design tokens:
- **Background**: `#0D1117` (GitHub Dark canvas)
- **Surface & Panels**: `#161B22` / `#21262D`
- **Borders**: `#30363D`
- **Accent / Telemetry**: `#58A6FF` (Blue)
- **Critical / Danger**: `#F85149` (Red)
- **Warning / Medium**: `#D29922` (Amber)
- **Safe**: `#2EA043` (Green)
- **Typography**: `JetBrains Mono` and system UI fonts
