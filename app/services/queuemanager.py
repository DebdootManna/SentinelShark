import asyncio
import time
from typing import Set, Dict, Any, Optional
from PyQt6.QtCore import QObject, pyqtSignal

from app.config import config
from app.core.cache import cache
from app.services.threatintel import threat_client, is_public_ip


class QueueManagerSignals(QObject):
    """Signals emitted when threat intelligence is resolved or when queue state updates."""
    threat_resolved = pyqtSignal(str, dict)  # ip, threat_dict
    queue_status = pyqtSignal(int, int)  # pending_count, rate_limited_count


class ThreatIntelQueueManager:
    """
    Manages background threat intelligence lookups with:
    1. Instant cache lookups.
    2. Non-routable/Private IP filtering.
    3. Duplicate request suppression.
    4. Rate-limiting & HTTP 429 exponential backoff.
    5. Thread-safe PyQt signal dispatching.
    """

    def __init__(self):
        self.signals = QueueManagerSignals()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.pending_ips: Set[str] = set()
        self.in_progress_ips: Set[str] = set()
        self.is_running = False
        self.worker_task: Optional[asyncio.Task] = None
        self.backoff_delay = 1.0
        self.max_backoff = 60.0

    def enqueue_ip(self, ip: str):
        """Enqueue an IP for threat intelligence lookup."""
        if not ip or not is_public_ip(ip):
            return

        # Check cache first
        cached_data = cache.get(ip)
        if cached_data:
            self.signals.threat_resolved.emit(ip, cached_data)
            return

        # Skip if already queued or processing
        if ip in self.pending_ips or ip in self.in_progress_ips:
            return

        # If no API keys are set, emit default public IP response to avoid wasting queue
        if not config.abuseipdb_api_key and not config.virustotal_api_key:
            default_resp = {
                "ip": ip,
                "abuse_score": 0,
                "vt_malicious": 0,
                "vt_suspicious": 0,
                "vt_harmless": 0,
                "country": "UNKNOWN",
                "reports_count": 0,
                "domain": "No API Keys Set",
                "is_public": True,
                "no_keys": True
            }
            self.signals.threat_resolved.emit(ip, default_resp)
            return

        self.pending_ips.add(ip)
        self.queue.put_nowait(ip)
        self.signals.queue_status.emit(self.queue.qsize(), len(self.in_progress_ips))

    async def start(self):
        """Start the background worker loop."""
        if self.is_running:
            return
        self.is_running = True
        self.worker_task = asyncio.create_task(self._worker_loop())

    async def stop(self):
        """Stop the background worker loop."""
        self.is_running = False
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass

    async def _worker_loop(self):
        """Main processing loop with rate limit pacing and 429 exponential backoff."""
        while self.is_running:
            try:
                ip = await self.queue.get()
                if ip in self.pending_ips:
                    self.pending_ips.remove(ip)
                self.in_progress_ips.add(ip)

                # Check cache once more
                cached_data = cache.get(ip)
                if cached_data:
                    self.in_progress_ips.remove(ip)
                    self.signals.threat_resolved.emit(ip, cached_data)
                    self.queue.task_done()
                    continue

                # Rate limiting pacing
                min_delay = 60.0 / max(config.max_requests_per_minute, 1)
                await asyncio.sleep(min_delay)

                # Execute API lookup
                threat_data = await threat_client.lookup_ip(ip)

                if threat_data.get("has_429"):
                    # Rate limit hit: re-queue IP and exponential backoff
                    print(f"[QueueManager] HTTP 429 hit. Backing off for {self.backoff_delay:.1f}s")
                    await asyncio.sleep(self.backoff_delay)
                    self.backoff_delay = min(self.backoff_delay * 2, self.max_backoff)
                    self.in_progress_ips.remove(ip)
                    self.pending_ips.add(ip)
                    self.queue.put_nowait(ip)
                    self.queue.task_done()
                    continue

                # Successful lookup: reset backoff
                self.backoff_delay = 1.0

                # Cache and emit
                cache.set(ip, threat_data)
                self.in_progress_ips.remove(ip)
                self.signals.threat_resolved.emit(ip, threat_data)
                self.signals.queue_status.emit(self.queue.qsize(), len(self.in_progress_ips))

                self.queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[QueueManager] Error processing item: {e}")
                await asyncio.sleep(1.0)


# Global queue manager instance
queue_manager = ThreatIntelQueueManager()
