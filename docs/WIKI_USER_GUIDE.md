# SentinelShark Wiki - User & Operator Guide

Welcome to the **SentinelShark User & Operator Guide**. This guide explains how to install, configure, and use SentinelShark for live network traffic sniffing, PCAP file analysis, Berkeley Packet Filtering (BPF), and threat intelligence enrichment.

---

## 🛠️ Installation & Setup

### 1. System Requirements
- **Operating System**: macOS, Linux, or Windows.
- **Python**: Python 3.10 or higher.
- **TShark / Wireshark** *(Optional)*: Recommended for live packet capture on physical network interfaces (`eth0`, `en0`, `wlan0`). If TShark is not installed, SentinelShark seamlessly runs in **Mock Capture Mode**.

### 2. Quick Setup Commands
```bash
# Clone the repository
git clone https://github.com/user/sentinelshark.git
cd sentinelshark

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch SentinelShark GUI
python run.py
```

---

## 🔑 Setting Up VirusTotal & AbuseIPDB API Keys

SentinelShark enriches public IP addresses in real time with threat intelligence.

### Method A: Via GUI (Recommended)
1. Launch SentinelShark.
2. Click **API Keys** on the toolbar (or open menu **Settings -> API Credentials...**).
3. Paste your **AbuseIPDB API Key** (v2) and **VirusTotal API Key** (v3).
4. Click **OK**. Credentials will be saved securely to `config.json`.

### Method B: Environment Variables
You can also set environment variables before launching:
```bash
export ABUSEIPDB_API_KEY="your_abuseipdb_key_here"
export VIRUSTOTAL_API_KEY="your_virustotal_key_here"
python run.py
```

---

## 📡 Capturing Network Traffic

### 1. Live Sniffing
1. Select your target network interface from the **Interface** dropdown (e.g. `en0`, `eth0`, `any`).
2. *(Optional)* Enter a Berkeley Packet Filter (BPF) string in the **BPF Filter** field.
3. Click **Start Capture**.

### 2. Common BPF Filter Examples
- Sniff HTTP traffic only: `tcp port 80`
- Sniff HTTPS traffic only: `tcp port 443`
- Sniff DNS queries only: `udp port 53`
- Sniff traffic from a specific IP: `ip src 192.168.1.100`
- Ignore SSH traffic: `not port 22`

### 3. PCAP File Analysis
1. Click **File -> Open PCAP File...** from the menu bar.
2. Select any `.pcap`, `.pcapng`, or `.cap` capture file.
3. SentinelShark will parse the file, populate the packet list, and run threat intelligence lookups on all public IP addresses found in the capture.

### 4. Mock Mode (Traffic Simulation)
If you want to test SentinelShark without active network activity or TShark installed:
1. Toggle the **Mock Mode** button on the toolbar.
2. Click **Start Capture**. SentinelShark will generate simulated network traffic, including DNS queries, HTTP GET/POST requests, and suspicious external IP connections.

---

## 🔍 Packet Inspection & Analysis

### 1. Packet List Table
- Displays packet number, timestamp, source IP, destination IP, protocol, length, info string, and threat score.
- Clicking any row loads the detailed packet breakdown into the bottom inspector panes.

### 2. Packet Detail Tree View
- Collapsible hierarchical breakdown:
  - **Frame**: General packet metadata and length.
  - **Ethernet II**: MAC source and destination addresses.
  - **Internet Protocol (IPv4/IPv6)**: Version, TTL, header length, source & destination IPs.
  - **Transport Layer (TCP/UDP)**: Ports, sequence numbers, acknowledgment numbers, flags.
  - **Application Layer**: DNS query domains, HTTP request headers, User-Agent.
  - **Threat Intelligence Node**: Highlights AbuseIPDB confidence score, VirusTotal malicious count, country of origin, and domain.

### 3. Raw Hex & ASCII Inspector
- Split 16-byte hex dump alongside readable ASCII characters.
- Displays payload MD5 and SHA256 cryptographic hashes for payload verification.

---

## 📊 NIDS Dashboard & Stat Counters
Located on the top right panel:
- **Total Packets**: Total packet count processed.
- **Data Traffic**: Cumulative bandwidth volume (KB / MB).
- **Safe Packets**: Count of clean packets (0% abuse score).
- **Threats Detected**: Count of suspicious or critical threat IPs detected.
- **Protocol Breakdown**: Distribution of TCP, UDP, HTTP, DNS, and ICMP.
- **Threat Intel API Queue**: Active progress bar showing pending REST API lookups.
