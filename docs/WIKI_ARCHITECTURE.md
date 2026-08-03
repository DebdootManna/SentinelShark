# SentinelShark Wiki - System Architecture & Design

Welcome to the **SentinelShark NIDS Architecture Wiki**. This document provides an in-depth breakdown of the system components, threading architecture, asynchronous event loop integration, Threat Intelligence processing pipeline, and database schema.

---

## System High-Level Architecture

SentinelShark is designed around a decoupled, non-blocking asynchronous architecture combining **PyQt6** for user interface rendering, **qasync** for `asyncio` event loop integration, **PyShark** for packet dissection, and **httpx** for Threat Intelligence REST API enrichment.

```
+-------------------------------------------------------------------------------+
|                             SentinelShark Desktop UI                           |
|  +-----------------------+ +-----------------------+ +---------------------+  |
|  |  PacketTable (Qt)     | |  PacketDetail (Tree)  | |  HexView (Inspector)|  |
|  +-----------------------+ +-----------------------+ +---------------------+  |
+---------------------------------------+---------------------------------------+
                                        |  Qt Signals / Slots
+---------------------------------------v---------------------------------------+
|                              qasync Event Loop                                |
|  +---------------------------------+     +---------------------------------+  |
|  |   LiveCaptureThread (QThread)   |     |   ThreatIntelQueueManager (Async|  |
|  | - PyShark Live / FileCapture    |     | - Rate Limiter & Priority Queue |  |
|  | - Fallback Mock Traffic Worker  |     | - HTTP 429 Exponential Backoff  |  |
|  +---------------------------------+     +---------------------------------+  |
+---------------------------------------+---------------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
+----------------v-------------------+       +-----------------v------------------+
|      ThreatIntelClient (httpx)     |       |    ThreatCache (SQLite + Memory)   |
| - AbuseIPDB API v2                 |       | - threatcache.db (24h TTL)         |
| - VirusTotal API v3                |       | - cachetools.TTLCache (In-Memory)  |
| - RFC 1918 Private IP Filtering    |       +------------------------------------+
+------------------------------------+
```

---

## Threading & Async Model

Desktop GUIs require high frame-rate responsiveness (60 FPS). Heavy network operations (packet sniffing and HTTP REST API calls) will freeze the GUI if run on the main Qt thread.

1. **GUI Thread (PyQt6)**:
   - Responsible strictly for rendering widgets, processing user mouse/keyboard input, updating table rows, and updating stat counters.
2. **Packet Capture Worker (`LiveCaptureThread` - `QThread`)**:
   - Runs in a dedicated native background thread.
   - Continuously calls `pyshark.LiveCapture.sniff_continuously()`.
   - Parses packets into thread-safe dictionary structures and emits `packet_received` PyQt signals back to the main UI thread.
3. **Async Threat Intelligence Queue (`ThreatIntelQueueManager` - `qasync`)**:
   - Runs as an asynchronous task managed by `qasync.QEventLoop`.
   - Listens for public IP addresses extracted from captured packets.
   - Manages API rate limits (e.g. 30 requests/min), deduplicates concurrent requests, and handles HTTP 429 rate limit backoff.

---

## Threat Intelligence Pipeline

```
Captured Packet -> Extract Destination/Source IP
       |
       v
Is IP Public & Routable? (Filter 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1)
       |
       +---> NO (Private / Loopback) ---> Mark as "Internal IP" (No API cost)
       |
       +---> YES (Public IP)
              |
              v
       Check SQLite Persistent Cache & In-Memory TTLCache
              |
              +---> HIT (Unexpired record found) ---> Emit cached threat data immediately
              |
              +---> MISS (Not cached or expired)
                     |
                     v
              Enqueue in ThreatIntelQueueManager
                     |
                     v
              Async HTTP Fetch (AbuseIPDB + VirusTotal)
                     |
                     v
              Store in SQLite Cache (`threatcache.db`) & TTLCache
                     |
                     v
              Emit `threat_resolved` signal -> Highlight Packet Table Row (Green/Yellow/Red)
```

---

## Database Schema (`threatcache.db`)

The persistent threat intelligence cache is powered by SQLite.

### Table: `ip_threat_cache`

| Column Name | Data Type | Constraint | Description |
| :--- | :--- | :--- | :--- |
| `ip` | `TEXT` | `PRIMARY KEY` | Targeted IP address |
| `abuse_score` | `INTEGER` | `DEFAULT 0` | AbuseIPDB Abuse Confidence Score (0 - 100%) |
| `vt_malicious` | `INTEGER` | `DEFAULT 0` | VirusTotal malicious engine detection count |
| `vt_suspicious`| `INTEGER` | `DEFAULT 0` | VirusTotal suspicious engine detection count |
| `vt_harmless`  | `INTEGER` | `DEFAULT 0` | VirusTotal harmless engine detection count |
| `country`      | `TEXT`    | `DEFAULT ''` | 2-letter ISO country code (e.g. `US`, `DE`) |
| `reports_count`| `INTEGER` | `DEFAULT 0` | Total abuse reports count from AbuseIPDB |
| `domain`       | `TEXT`    | `DEFAULT ''` | Reverse DNS / domain association |
| `updated_at`   | `INTEGER` | `NOT NULL`   | UNIX epoch timestamp of last lookup |

---

## Theme & Color-Coding Rules

SentinelShark enforces threat classification color-coding:

- **Safe Traffic (Green)**:
  - **Condition**: AbuseIPDB score = 0% AND VirusTotal Malicious count = 0.
  - **Style**: Dark emerald background (`#064e3b`), mint text (`#d1fae5`).
- **Low-Medium Risk (Amber / Orange)**:
  - **Condition**: AbuseIPDB score 1% - 30% OR VirusTotal Suspicious count > 0.
  - **Style**: Amber background (`#78350f`), warm yellow text (`#fef3c7`).
- **Critical Threat (Crimson Red)**:
  - **Condition**: AbuseIPDB score > 30% OR VirusTotal Malicious count > 0.
  - **Style**: Crimson red background (`#7f1d1d`), bold light-red text (`#fecaca`).
