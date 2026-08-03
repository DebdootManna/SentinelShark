# SentinelShark Wiki - Developer & Extension Guide

Welcome to the **SentinelShark Developer & Extension Guide**. This guide provides instructions for developers looking to extend SentinelShark, add custom protocol dissectors, integrate additional Threat Intelligence feeds, or run automated unit tests.

---

## Development Environment Setup

### 1. Requirements
- Python 3.10+
- Virtual environment (`venv`)

### 2. Setting Up Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Module Overview

| Module Path | Primary Responsibility |
| :--- | :--- |
| `app/main.py` | GUI entrypoint & `qasync` event loop integration. |
| `app/config.py` | Reads environment variables and `config.json`. |
| `app/core/capture.py` | `LiveCaptureThread` QThread managing PyShark sniffing and Mock generator. |
| `app/core/parser.py` | Packet dissector (`PacketDissector`), hex formatter, and payload hashing. |
| `app/core/cache.py` | `ThreatCache` managing SQLite database (`threatcache.db`) & `cachetools.TTLCache`. |
| `app/services/threatintel.py` | Async `ThreatIntelClient` querying AbuseIPDB & VirusTotal endpoints via `httpx`. |
| `app/services/queuemanager.py` | `ThreatIntelQueueManager` handling rate limits & HTTP 429 exponential backoff. |
| `app/ui/mainwindow.py` | Main layout with Toolbar, API Modal, Splitters, Menu, and Status Bar. |
| `app/ui/styles.py` | Cyber dark-mode QSS stylesheet. |
| `app/ui/components/packettable.py` | High-performance packet list with threat color-coding. |
| `app/ui/components/packetdetail.py` | Layer dissection tree view (`QTreeWidget`). |
| `app/ui/components/hexview.py` | Hex & ASCII byte inspector with MD5/SHA256 calculations. |
| `app/ui/components/statspanel.py` | Real-time traffic metrics and threat score gauges. |

---

## Extending Threat Intelligence Feeds

To add a new Threat Intelligence provider (e.g. AlienVault OTX, Shodan, or AbuseCH):

1. Open `app/services/threatintel.py`.
2. Add an async method inside `ThreatIntelClient`:
```python
async def fetch_alienvault_otx(self, client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        resp = await client.get(url, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        return {"otx_pulses": pulses}
    except Exception as e:
        print(f"[ThreatIntel] OTX error: {e}")
        return {}
```
3. Update `lookup_ip(self, ip: str)` to invoke the new provider and merge the result dictionary.

---

## Adding Custom Protocol Dissectors

To support custom protocol layer dissection in `app/core/parser.py`:

1. Open `app/core/parser.py`.
2. Update `_build_layers_tree_pyshark(packet, ...)`:
```python
if hasattr(packet, "custom_proto"):
    tree.append({
        "name": "Custom Protocol Layer",
        "children": [
            f"Field A: {getattr(packet.custom_proto, 'field_a', 'N/A')}",
            f"Field B: {getattr(packet.custom_proto, 'field_b', 'N/A')}"
        ]
    })
```

---

## Running Unit Tests

SentinelShark uses Python's standard `unittest` framework.

### Run All Unit Tests:
```bash
./venv/bin/python -m unittest discover tests
```

### Add a New Test Case:
Add test methods inside `tests/test_sentinelshark.py`:
```python
def test_custom_dissector(self):
    pkt_dict = {"raw_bytes": b"TEST_DATA"}
    dissected = PacketDissector.dissect_dict_packet(pkt_dict)
    self.assertEqual(dissected["payload_md5"], "501a3574c86a635832a8f899d4ca9d5d")
```
