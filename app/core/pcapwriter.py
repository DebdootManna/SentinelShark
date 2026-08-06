import struct
import time
from typing import List, Dict, Any


def save_pcap_file(filepath: str, packets: List[Dict[str, Any]]) -> bool:
    """
    Saves packet records into a standard libpcap binary file (.pcap / .pcapng).
    Excludes AbuseIPDB, VirusTotal, and IPinfo threat intel attributes, preserving
    100% native compatibility with Wireshark and tshark.
    """
    if not filepath:
        return False

    # Standard libpcap global header (24 bytes)
    # Magic: 0xa1b2c3d4 (little-endian), Major: 2, Minor: 4, Thiszone: 0, Sigfigs: 0, Snaplen: 65535, Network: 1 (Ethernet)
    global_header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    try:
        with open(filepath, "wb") as f:
            f.write(global_header)
            base_time = time.time()

            for idx, pkt in enumerate(packets):
                raw_bytes = pkt.get("raw_bytes", b"")
                if not raw_bytes:
                    # Construct minimal Ethernet frame if raw_bytes missing
                    raw_bytes = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

                # Extract or calculate packet timestamp
                time_str = pkt.get("time", "")
                ts_sec = int(base_time) + idx
                ts_usec = 0

                if time_str:
                    try:
                        parts = time_str.split(".")
                        time_struct = time.strptime(parts[0], "%H:%M:%S")
                        # Combine current date with packet HH:MM:SS
                        now_struct = time.localtime()
                        full_time = time.struct_time((
                            now_struct.tm_year, now_struct.tm_mon, now_struct.tm_mday,
                            time_struct.tm_hour, time_struct.tm_min, time_struct.tm_sec,
                            now_struct.tm_wday, now_struct.tm_yday, now_struct.tm_isdst
                        ))
                        ts_sec = int(time.mktime(full_time))
                        if len(parts) > 1:
                            ts_usec = int(parts[1][:3]) * 1000
                    except Exception:
                        pass

                length = len(raw_bytes)
                # Packet record header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
                pkt_header = struct.pack("<IIII", ts_sec, ts_usec, length, length)
                f.write(pkt_header)
                f.write(raw_bytes)

        return True
    except Exception as e:
        print(f"[PCAPWriter] Error writing PCAP file {filepath}: {e}")
        return False
