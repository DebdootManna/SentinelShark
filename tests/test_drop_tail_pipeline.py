import os
import sys
import unittest
import queue
import psutil
from PyQt6.QtWidgets import QApplication

from app.core.capture import packet_queue, make_packet_summary_tuple
from app.ui.components.packettable import PacketTable
from app.ui.components.statspanel import StatsPanel


class TestDropTailPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication(sys.argv)

    def test_queue_drop_tail(self):
        """Verify queue maxsize=300 and drop-tail policy drops excess without memory growth."""
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break

        self.assertEqual(packet_queue.qsize(), 0)

        dropped = 0
        for i in range(1000):
            sample_tuple = (
                str(i), "12:00:00.000", "1234", "curl",
                "192.168.1.100", f"104.16.{i%256}.1", "TCP", "64",
                "T1105", "HIGH", f"HTTP GET /test_{i}"
            )
            try:
                packet_queue.put_nowait(sample_tuple)
            except queue.Full:
                dropped += 1

        self.assertLessEqual(packet_queue.qsize(), 300)
        self.assertGreater(dropped, 600)

        drained = []
        while not packet_queue.empty():
            try:
                drained.append(packet_queue.get_nowait())
            except queue.Empty:
                break
        self.assertEqual(len(drained), 300)

    def test_table_ring_buffer_and_memory_footprint(self):
        """Verify PacketTable deque maxlen=2000 and flat memory under 150 MB during bursts."""
        table = PacketTable()
        stats = StatsPanel()

        for burst in range(200):
            batch = []
            for i in range(50):
                idx = burst * 50 + i
                batch.append((
                    str(idx), "12:00:00.123", "5501", "python3",
                    "192.168.1.50", f"93.184.216.{i % 10}", "TCP", "128",
                    "T1059", "CRITICAL", f"TCP connection {idx}"
                ))
            table.add_packets_batch(batch)
            stats.update_packets_batch(batch)

        self.assertEqual(table.rowCount(), 2000)
        self.assertEqual(len(table.packets), 2000)

        proc = psutil.Process(os.getpid())
        rss_mb = proc.memory_info().rss / (1024 * 1024)
        print(f"\n[TestDropTailPipeline] Memory RSS after 10,000 packets: {rss_mb:.2f} MB")
        self.assertLess(rss_mb, 150.0, f"Memory ({rss_mb:.2f} MB) exceeded 150 MB ceiling!")

        pkt = table.packets[0]
        self.assertIn("process_name", pkt)
        self.assertEqual(pkt["process_name"], "python3")
        self.assertEqual(pkt["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
