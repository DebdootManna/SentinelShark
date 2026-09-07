# SentinelShark (C++ Qt6 Windows Edition)

A high-performance, host-aware Endpoint Detection and Response (EDR) platform and network analysis workstation engineered in native **C++17** and **Qt6** for Windows.

Designed for resource-constrained malware analysis sandboxes, DFIR investigations, and live threat hunting.

---

## Key Performance Safeguards

1. **< 50MB Idle RAM Footprint**
   - No `QTableWidget` overhead; uses `QTableView` backed by a custom `QAbstractTableModel`.
   - Packets stored as lightweight POD structs (`PacketRecord`, ~400 bytes) inside a fixed-size `RingBuffer<PacketRecord, 3000>`.
   - Maximum active packet memory is capped at ~1.2 MB. Colors and styling are computed on-the-fly in `data()`, not stored per-row.

2. **Drop-Tail Lock-Free Inter-Thread Queueing**
   - Capture thread passes events to the GUI thread via a single-producer single-consumer lock-free `BoundedQueue<PacketRecord, 300>`.
   - If the GUI thread falls behind under heavy traffic spikes, the capture thread drops excess packets without blocking or growing memory.

3. **Pull-Based Batch UI Updates**
   - GUI does not process Qt signals per packet. A `QTimer` ticking at 40ms (25 FPS) drains up to 50 packets per batch, triggering atomic `beginInsertRows` / `endInsertRows` updates.

4. **Decoupled O(1) Socket Correlation**
   - Socket lookups are completely removed from the packet ingestion hot path.
   - A background thread polls Windows native APIs (`GetExtendedTcpTable` and `GetExtendedUdpTable` via `iphlpapi.lib`) every 1 second.
   - Atomically updates lock-free maps for instant O(1) 4-tuple and port-based process attribution.

5. **Lazy Dissection**
   - Heavy parsing, forensics inspection, VirusTotal query prep, and Google SecOps UDM JSON formatting are executed lazily only when the operator selects a row.

---

## Directory Structure

```
SentinelSharkCpp/
├── CMakeLists.txt              # CMake build configuration
├── SentinelSharkCpp.pro        # QMake fallback project file
├── README.md                   # Technical documentation
├── resources/
│   ├── resources.qrc           # Qt resource definition
│   ├── style.qss               # Dark-mode SOC workstation theme
│   └── SentinelShark.rc        # Windows application manifest & metadata
├── src/
│   ├── main.cpp                # Application entry point & CLI options
│   ├── capture/
│   │   ├── CaptureThread.h/.cpp       # Streaming TShark JSON capture engine
│   │   ├── MockCaptureThread.h/.cpp   # Synthetic network traffic generator
│   │   └── InterfaceScanner.h         # Network adapter enumeration & BPF sanitizer
│   ├── config/
│   │   └── AppConfig.h/.cpp           # Configuration manager (QSettings / INI)
│   ├── core/
│   │   ├── PacketRecord.h             # Compact POD struct (~400 bytes)
│   │   ├── RingBuffer.h               # Fixed-capacity ring buffer with overwrite
│   │   └── BoundedQueue.h             # Lock-free SPSC queue with drop-tail
│   ├── correlation/
│   │   ├── ProcessNameCache.h/.cpp    # Windows process metadata cache (Win32)
│   │   └── SocketPollThread.h/.cpp    # 1Hz iphlpapi TCP/UDP polling thread
│   ├── heuristics/
│   │   └── HeuristicsEngine.h/.cpp    # MITRE ATT&CK evaluator & severity scoring
│   ├── model/
│   │   ├── PacketTableModel.h/.cpp    # QAbstractTableModel for 11-column table
│   │   └── SeverityDelegate.h/.cpp    # Rounded pill badge renderer (QPainter)
│   ├── response/
│   │   └── ResponseEngine.h/.cpp      # Windows IR actions (Kill, Firewall, Quarantine)
│   ├── threatintel/
│   │   └── ThreatIntelWorker.h/.cpp   # Async REST queries (VirusTotal, AbuseIPDB, etc.)
│   ├── udm/
│   │   └── UdmNormalizer.h/.cpp       # Google SecOps UDM schema generator
│   └── ui/
│       ├── MainWindow.h/.cpp          # Primary SOC workstation interface
│       ├── InspectionPanel.h/.cpp     # Left inspection & forensics drawer
│       ├── DetectionDetailPanel.h/.cpp# Center detection & IR actions panel
│       ├── AnalyticsSidebar.h/.cpp    # Right analytics & MITRE breakdown sidebar
│       └── SettingsDialog.h/.cpp      # API keys, interface & capture config
└── third_party/
    └── nlohmann/
        └── json.hpp                   # Single-header JSON parser
```

---

## Building the Project

### Prerequisites
- **Windows 10 / 11** (x64)
- **Visual Studio 2022** (MSVC v143 toolset) or MinGW 11+
- **CMake 3.20+**
- **Qt 6.4+** (Core, Gui, Widgets, Network)
- *(Optional)* **Wireshark / TShark** installed (only needed for live packet capture; mock mode works out of the box).

### Build with CMake (CLI)

```powershell
# In PowerShell:
cd c:\Users\Win10\Desktop\SentinelShark\SentinelSharkCpp

# Configure (pointing CMAKE_PREFIX_PATH to your Qt6 installation)
cmake -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_PREFIX_PATH="C:\Qt\6.6.0\msvc2022_64" `
  -DCMAKE_BUILD_TYPE=Release

# Compile
cmake --build build --config Release --parallel

# Run
.\build\Release\SentinelShark.exe
```

### Build with Qt Creator
1. Open Qt Creator.
2. Select **Open Project** and choose `SentinelSharkCpp/CMakeLists.txt` or `SentinelSharkCpp.pro`.
3. Select your Qt 6 Desktop kit (MSVC 2022 64-bit).
4. Click **Build** and **Run**.

---

## Command Line Options

```
Usage: SentinelShark.exe [options]

Options:
  -h, --help               Displays help on commandline options.
  -v, --version            Displays version information.
  -m, --mock               Run in mock traffic generation mode (no TShark required).
  -i, --interface <iface>  Capture interface name or index (e.g. 1, "Ethernet").
  -f, --filter <filter>    BPF capture filter string (e.g. "port 443", "dns").
```

---

## Active Response Engine Capabilities

Run SentinelShark as Administrator to use remediation actions:

1. **Kill Process**:
   - Uses native `OpenProcess(PROCESS_TERMINATE)` and `TerminateProcess()`.
   - Enforces kernel-level guards: cannot target PID 0 (System Idle), PID 4 (System), or SentinelShark's own PID.

2. **Block Remote IP**:
   - Executes outbound firewall block rules via Windows Advanced Firewall:
     `netsh advfirewall firewall add rule name="SentinelShark Block <IP>" dir=out action=block remoteip=<IP>`

3. **Quarantine Binary**:
   - Resolves executable location via `QueryFullProcessImageNameW`.
   - Moves file atomically using `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` into `%LOCALAPPDATA%\SentinelShark\quarantine\`.
   - Applies restrictive security descriptor (NULL DACL via `SetNamedSecurityInfoW`) to strip execution rights.
