import hashlib
import time
from typing import Dict, Any, List, Tuple


def format_hex_dump(data_bytes: bytes) -> Tuple[str, str]:
    """
    Formats raw binary bytes into classic Wireshark split format:
    - Hex View with offsets: "0000   45 00 00 3c  1c 46 40 00   E..<.F@."
    - Pure ASCII String
    """
    if not data_bytes:
        return "No Raw Payload Data Available", ""

    hex_lines = []
    ascii_chars = []

    for offset in range(0, len(data_bytes), 16):
        chunk = data_bytes[offset:offset + 16]
        
        # Hex representation (group 8 bytes)
        hex_part1 = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_part2 = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str = f"{hex_part1:<23}  {hex_part2:<23}"

        # ASCII representation
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        ascii_chars.append(ascii_part)

        hex_lines.append(f"{offset:04x}   {hex_str}  |{ascii_part}|")

    full_hex_dump = "\n".join(hex_lines)
    full_ascii = "".join(ascii_chars)
    return full_hex_dump, full_ascii


def calculate_payload_hash(data_bytes: bytes) -> Dict[str, str]:
    """Calculates MD5 and SHA256 hashes of packet payload bytes."""
    if not data_bytes:
        return {"md5": "", "sha256": ""}
    return {
        "md5": hashlib.md5(data_bytes).hexdigest(),
        "sha256": hashlib.sha256(data_bytes).hexdigest()
    }


class PacketDissector:
    """Dissects PyShark packet objects or mock dictionary structures into unified data models."""

    @staticmethod
    def dissect_pyshark_packet(packet, number: int) -> Dict[str, Any]:
        """Dissect PyShark packet into structured representation."""
        try:
            timestamp = float(packet.sniff_timestamp)
            time_str = time.strftime("%H:%M:%S", time.localtime(timestamp)) + f".{int((timestamp % 1) * 1000):03d}"
        except Exception:
            time_str = time.strftime("%H:%M:%S")

        protocol = packet.highest_layer if hasattr(packet, "highest_layer") else "RAW"
        length = packet.length if hasattr(packet, "length") else 0

        src_ip = "N/A"
        dst_ip = "N/A"
        src_port = ""
        dst_port = ""
        info = f"{protocol} Protocol Packet"

        # Check IP layer
        if hasattr(packet, "ip"):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, "ipv6"):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst

        # Check Transport Layer
        if hasattr(packet, "tcp"):
            protocol = "TCP"
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            flags = getattr(packet.tcp, "flags", "")
            info = f"TCP {src_port} -> {dst_port} [Flags: {flags}]"
        elif hasattr(packet, "udp"):
            protocol = "UDP"
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            info = f"UDP {src_port} -> {dst_port} Len={getattr(packet.udp, 'length', length)}"
        elif hasattr(packet, "icmp"):
            protocol = "ICMP"
            info = f"ICMP Type={getattr(packet.icmp, 'type', '')} Code={getattr(packet.icmp, 'code', '')}"
        elif hasattr(packet, "dns"):
            protocol = "DNS"
            qry_name = getattr(packet.dns, "qry_name", "")
            info = f"DNS Query: {qry_name}" if qry_name else "DNS Packet"
        elif hasattr(packet, "http"):
            protocol = "HTTP"
            method = getattr(packet.http, "request_method", "")
            uri = getattr(packet.http, "request_uri", "")
            info = f"HTTP {method} {uri}" if method else "HTTP Response"

        # Raw Bytes
        raw_bytes = b""
        try:
            if hasattr(packet, "get_raw_packet"):
                raw_bytes = packet.get_raw_packet()
        except Exception:
            pass

        hex_dump, ascii_str = format_hex_dump(raw_bytes)
        hashes = calculate_payload_hash(raw_bytes)

        # Layer Breakdown tree structure
        layers_tree = PacketDissector._build_layers_tree_pyshark(packet, number, time_str, length, src_ip, dst_ip)

        return {
            "no": number,
            "time": time_str,
            "src": src_ip,
            "dst": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": int(length),
            "info": info,
            "raw_bytes": raw_bytes,
            "hex_dump": hex_dump,
            "ascii_str": ascii_str,
            "payload_md5": hashes["md5"],
            "payload_sha256": hashes["sha256"],
            "layers_tree": layers_tree,
            "threat_score": 0,
            "threat_data": None
        }

    @staticmethod
    def _build_layers_tree_pyshark(packet, number: int, time_str: str, length: int, src_ip: str, dst_ip: str) -> List[Dict[str, Any]]:
        """Construct layer-by-layer tree structure from PyShark packet."""
        tree = []

        # 1. Frame Info
        tree.append({
            "name": f"Frame {number}: {length} bytes on wire",
            "children": [
                f"Arrival Time: {time_str}",
                f"Frame Length: {length} bytes",
                f"Protocols in Frame: {getattr(packet, 'frame_protocols', 'N/A')}"
            ]
        })

        # 2. Ethernet Layer
        if hasattr(packet, "eth"):
            tree.append({
                "name": f"Ethernet II, Src: {getattr(packet.eth, 'src', 'N/A')}, Dst: {getattr(packet.eth, 'dst', 'N/A')}",
                "children": [
                    f"Destination: {getattr(packet.eth, 'dst', 'N/A')}",
                    f"Source: {getattr(packet.eth, 'src', 'N/A')}",
                    f"Type: {getattr(packet.eth, 'type', 'N/A')}"
                ]
            })

        # 3. IP Layer
        if hasattr(packet, "ip"):
            tree.append({
                "name": f"Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}",
                "children": [
                    f"Version: 4",
                    f"Header Length: {getattr(packet.ip, 'hdr_len', '20')} bytes",
                    f"Time to Live (TTL): {getattr(packet.ip, 'ttl', '64')}",
                    f"Protocol: {getattr(packet.ip, 'proto', 'N/A')}",
                    f"Header Checksum: {getattr(packet.ip, 'checksum', 'N/A')}",
                    f"Source Address: {src_ip}",
                    f"Destination Address: {dst_ip}"
                ]
            })

        # 4. Transport Layer
        if hasattr(packet, "tcp"):
            tree.append({
                "name": f"Transmission Control Protocol, Src Port: {packet.tcp.srcport}, Dst Port: {packet.tcp.dstport}",
                "children": [
                    f"Source Port: {packet.tcp.srcport}",
                    f"Destination Port: {packet.tcp.dstport}",
                    f"Sequence Number: {getattr(packet.tcp, 'seq', 'N/A')}",
                    f"Acknowledge Number: {getattr(packet.tcp, 'ack', 'N/A')}",
                    f"Header Length: {getattr(packet.tcp, 'hdr_len', 'N/A')}",
                    f"Flags: {getattr(packet.tcp, 'flags', 'N/A')}",
                    f"Window Size: {getattr(packet.tcp, 'window_size', 'N/A')}"
                ]
            })
        elif hasattr(packet, "udp"):
            tree.append({
                "name": f"User Datagram Protocol, Src Port: {packet.udp.srcport}, Dst Port: {packet.udp.dstport}",
                "children": [
                    f"Source Port: {packet.udp.srcport}",
                    f"Destination Port: {packet.udp.dstport}",
                    f"Length: {getattr(packet.udp, 'length', 'N/A')}",
                    f"Checksum: {getattr(packet.udp, 'checksum', 'N/A')}"
                ]
            })

        # 5. Application Layer
        if hasattr(packet, "dns"):
            tree.append({
                "name": f"Domain Name System (DNS)",
                "children": [
                    f"Transaction ID: {getattr(packet.dns, 'id', 'N/A')}",
                    f"Flags: {getattr(packet.dns, 'flags', 'N/A')}",
                    f"Questions: {getattr(packet.dns, 'count_queries', 'N/A')}",
                    f"Query Name: {getattr(packet.dns, 'qry_name', 'N/A')}",
                    f"Query Type: {getattr(packet.dns, 'qry_type', 'N/A')}"
                ]
            })
        elif hasattr(packet, "http"):
            tree.append({
                "name": f"Hypertext Transfer Protocol (HTTP)",
                "children": [
                    f"Request Method: {getattr(packet.http, 'request_method', 'N/A')}",
                    f"Request URI: {getattr(packet.http, 'request_uri', 'N/A')}",
                    f"User-Agent: {getattr(packet.http, 'user_agent', 'N/A')}",
                    f"Host: {getattr(packet.http, 'host', 'N/A')}"
                ]
            })

        return tree

    @staticmethod
    def dissect_dict_packet(pkt_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Dissect dict/mock packet into unified structure."""
        raw_bytes = pkt_dict.get("raw_bytes", b"")
        hex_dump, ascii_str = format_hex_dump(raw_bytes)
        hashes = calculate_payload_hash(raw_bytes)
        pkt_dict["hex_dump"] = hex_dump
        pkt_dict["ascii_str"] = ascii_str
        pkt_dict["payload_md5"] = hashes["md5"]
        pkt_dict["payload_sha256"] = hashes["sha256"]
        return pkt_dict
