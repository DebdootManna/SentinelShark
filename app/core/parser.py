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

        # Extract Transport Layer Ports
        if hasattr(packet, "tcp"):
            src_port = getattr(packet.tcp, "srcport", "")
            dst_port = getattr(packet.tcp, "dstport", "")
        elif hasattr(packet, "udp"):
            src_port = getattr(packet.udp, "srcport", "")
            dst_port = getattr(packet.udp, "dstport", "")

        highest = getattr(packet, "highest_layer", "").upper()

        # Check Application Layer Protocols first
        if hasattr(packet, "dns") or highest == "DNS":
            protocol = "DNS"
            qry_name = getattr(packet.dns, "qry_name", "") if hasattr(packet, "dns") else ""
            info = f"Standard query {getattr(packet.dns, 'id', '')} A {qry_name}" if qry_name else "DNS Packet"
        elif hasattr(packet, "http") or highest == "HTTP":
            protocol = "HTTP"
            method = getattr(packet.http, "request_method", "") if hasattr(packet, "http") else ""
            uri = getattr(packet.http, "request_uri", "") if hasattr(packet, "http") else ""
            info = f"HTTP {method} {uri}" if method else "HTTP Response / Data"
        elif hasattr(packet, "tls") or hasattr(packet, "ssl") or highest in ("TLS", "SSL"):
            protocol = "HTTPS"
            info = f"TLS/HTTPS Encrypted Session ({src_port} -> {dst_port})"
        elif hasattr(packet, "ssh") or highest == "SSH":
            protocol = "SSH"
            info = f"SSH Encrypted Session ({src_port} -> {dst_port})"
        elif hasattr(packet, "icmp") or highest == "ICMP":
            protocol = "ICMP"
            info = f"ICMP Type={getattr(packet.icmp, 'type', '')} Code={getattr(packet.icmp, 'code', '')}" if hasattr(packet, "icmp") else "ICMP Packet"
        elif hasattr(packet, "tcp"):
            protocol = "TCP"
            flags = getattr(packet.tcp, "flags", "")
            info = f"TCP {src_port} -> {dst_port} [Flags: {flags}]"
        elif hasattr(packet, "udp"):
            protocol = "UDP"
            info = f"UDP {src_port} -> {dst_port} Len={getattr(packet.udp, 'length', length)}"
        elif highest:
            protocol = highest
            info = f"{protocol} Protocol Packet"

        # Raw Bytes
        raw_bytes = b""
        try:
            if hasattr(packet, "get_raw_packet"):
                raw = packet.get_raw_packet()
                if isinstance(raw, (bytes, bytearray)):
                    raw_bytes = bytes(raw)
                elif isinstance(raw, str):
                    raw_bytes = bytes.fromhex(raw)
        except Exception:
            pass

        if not raw_bytes and hasattr(packet, "frame_raw"):
            try:
                frame_val = getattr(packet.frame_raw, "value", "")
                if frame_val:
                    raw_bytes = bytes.fromhex(frame_val)
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
    def _extract_str_val(layer_dict: Any, field_name: str, default_val: str = "") -> str:
        """Safely extracts a scalar string from TShark JSON layer fields that may be lists, dicts, or strings."""
        if not isinstance(layer_dict, dict):
            return str(default_val)
        val = layer_dict.get(field_name)
        if val is None:
            return str(default_val)
        if isinstance(val, list):
            if not val:
                return str(default_val)
            val = val[0]
        if isinstance(val, dict):
            val = val.get(field_name, default_val)
        return str(val) if val is not None else str(default_val)

    @staticmethod
    def dissect_tshark_json_packet(pkt_data: Dict[str, Any], number: int) -> Dict[str, Any]:
        """Dissect direct tshark JSON stream packet into unified data model."""
        source = pkt_data.get("_source", {})
        if "layers" in source:
            layers = source["layers"]
        elif "layers" in pkt_data:
            layers = pkt_data["layers"]
        else:
            layers = {}

        # 1. Frame info & Timestamp
        frame = layers.get("frame", {})
        raw_epoch = PacketDissector._extract_str_val(frame, "frame.time_epoch", "")
        try:
            time_epoch = float(raw_epoch) if raw_epoch else time.time()
        except (ValueError, TypeError):
            time_epoch = time.time()

        time_str = time.strftime("%H:%M:%S", time.localtime(time_epoch)) + f".{int((time_epoch % 1) * 1000):03d}"

        raw_len = PacketDissector._extract_str_val(frame, "frame.len", "0")
        try:
            length = int(raw_len)
        except (ValueError, TypeError):
            length = 0

        # 2. IP / IPv6 Addresses
        ip_layer = layers.get("ip", {})
        ipv6_layer = layers.get("ipv6", {})
        src_ip = PacketDissector._extract_str_val(ip_layer, "ip.src") or PacketDissector._extract_str_val(ipv6_layer, "ipv6.src", "N/A")
        dst_ip = PacketDissector._extract_str_val(ip_layer, "ip.dst") or PacketDissector._extract_str_val(ipv6_layer, "ipv6.dst", "N/A")

        # 3. Transport Ports
        tcp_layer = layers.get("tcp", {})
        udp_layer = layers.get("udp", {})
        src_port = PacketDissector._extract_str_val(tcp_layer, "tcp.srcport") or PacketDissector._extract_str_val(udp_layer, "udp.srcport", "")
        dst_port = PacketDissector._extract_str_val(tcp_layer, "tcp.dstport") or PacketDissector._extract_str_val(udp_layer, "udp.dstport", "")

        # 4. Protocol & Info line determination
        protocol = "RAW"
        info = "Network Packet"

        if "dns" in layers:
            protocol = "DNS"
            dns = layers.get("dns", {})
            qry_name = PacketDissector._extract_str_val(dns, "dns.qry.name")
            tid = PacketDissector._extract_str_val(dns, "dns.id")
            info = f"Standard query {tid} A {qry_name}" if qry_name else "DNS Query / Response"
        elif "http" in layers:
            protocol = "HTTP"
            http = layers.get("http", {})
            method = PacketDissector._extract_str_val(http, "http.request.method")
            uri = PacketDissector._extract_str_val(http, "http.request.uri")
            info = f"HTTP {method} {uri}" if method else "HTTP Response / Data"
        elif "tls" in layers or "ssl" in layers:
            protocol = "HTTPS"
            info = f"TLS/HTTPS Encrypted Session ({src_port} -> {dst_port})"
        elif "ssh" in layers:
            protocol = "SSH"
            info = f"SSH Session ({src_port} -> {dst_port})"
        elif "icmp" in layers:
            protocol = "ICMP"
            icmp = layers.get("icmp", {})
            itype = PacketDissector._extract_str_val(icmp, "icmp.type")
            icode = PacketDissector._extract_str_val(icmp, "icmp.code")
            info = f"ICMP Type={itype} Code={icode}" if itype else "ICMP Packet"
        elif isinstance(tcp_layer, dict) and tcp_layer:
            protocol = "TCP"
            flags = PacketDissector._extract_str_val(tcp_layer, "tcp.flags")
            info = f"TCP {src_port} -> {dst_port} [Flags: {flags}]"
        elif isinstance(udp_layer, dict) and udp_layer:
            protocol = "UDP"
            ulen = PacketDissector._extract_str_val(udp_layer, "udp.length", str(length))
            info = f"UDP {src_port} -> {dst_port} Len={ulen}"
        else:
            layer_keys = [k.upper() for k in layers.keys() if k not in ("frame", "frame_raw", "eth")]
            if layer_keys:
                protocol = layer_keys[-1]
                info = f"{protocol} Protocol Packet"

        # 5. Extract Raw Bytes from frame_raw / frame
        raw_bytes = b""
        frame_raw = layers.get("frame_raw")
        raw_hex = ""
        if isinstance(frame_raw, str):
            raw_hex = frame_raw
        elif isinstance(frame_raw, list) and frame_raw:
            raw_hex = str(frame_raw[0])
        elif isinstance(frame_raw, dict):
            raw_hex = PacketDissector._extract_str_val(frame_raw, "value", "")

        if raw_hex:
            try:
                raw_bytes = bytes.fromhex(raw_hex)
            except Exception:
                pass

        hex_dump, ascii_str = format_hex_dump(raw_bytes)
        hashes = calculate_payload_hash(raw_bytes)

        # 6. Build Layers Tree
        layers_tree = []
        # Frame
        frame_proto = PacketDissector._extract_str_val(frame, "frame.protocols", "N/A") if isinstance(frame, dict) else "N/A"
        layers_tree.append({
            "name": f"Frame {number}: {length} bytes on wire",
            "children": [
                f"Arrival Time: {time_str}",
                f"Frame Length: {length} bytes",
                f"Protocols in Frame: {frame_proto}"
            ]
        })
        # Eth
        eth = layers.get("eth", {})
        if isinstance(eth, dict) and eth:
            eth_src = PacketDissector._extract_str_val(eth, "eth.src", "N/A")
            eth_dst = PacketDissector._extract_str_val(eth, "eth.dst", "N/A")
            eth_type = PacketDissector._extract_str_val(eth, "eth.type", "N/A")
            layers_tree.append({
                "name": f"Ethernet II, Src: {eth_src}, Dst: {eth_dst}",
                "children": [
                    f"Destination: {eth_dst}",
                    f"Source: {eth_src}",
                    f"Type: {eth_type}"
                ]
            })
        # IP
        if isinstance(ip_layer, dict) and ip_layer:
            hdr_len = PacketDissector._extract_str_val(ip_layer, "ip.hdr_len", "20")
            ttl = PacketDissector._extract_str_val(ip_layer, "ip.ttl", "64")
            proto_val = PacketDissector._extract_str_val(ip_layer, "ip.proto", "N/A")
            chksum = PacketDissector._extract_str_val(ip_layer, "ip.checksum", "N/A")
            layers_tree.append({
                "name": f"Internet Protocol Version 4, Src: {src_ip}, Dst: {dst_ip}",
                "children": [
                    "Version: 4",
                    f"Header Length: {hdr_len} bytes",
                    f"Time to Live (TTL): {ttl}",
                    f"Protocol: {proto_val}",
                    f"Header Checksum: {chksum}",
                    f"Source Address: {src_ip}",
                    f"Destination Address: {dst_ip}"
                ]
            })
        # TCP / UDP
        if isinstance(tcp_layer, dict) and tcp_layer:
            seq = PacketDissector._extract_str_val(tcp_layer, "tcp.seq", "N/A")
            ack = PacketDissector._extract_str_val(tcp_layer, "tcp.ack", "N/A")
            hdr_len = PacketDissector._extract_str_val(tcp_layer, "tcp.hdr_len", "N/A")
            flags = PacketDissector._extract_str_val(tcp_layer, "tcp.flags", "N/A")
            win = PacketDissector._extract_str_val(tcp_layer, "tcp.window_size", "N/A")
            layers_tree.append({
                "name": f"Transmission Control Protocol, Src Port: {src_port}, Dst Port: {dst_port}",
                "children": [
                    f"Source Port: {src_port}",
                    f"Destination Port: {dst_port}",
                    f"Sequence Number: {seq}",
                    f"Acknowledge Number: {ack}",
                    f"Header Length: {hdr_len}",
                    f"Flags: {flags}",
                    f"Window Size: {win}"
                ]
            })
        elif isinstance(udp_layer, dict) and udp_layer:
            ulen = PacketDissector._extract_str_val(udp_layer, "udp.length", "N/A")
            uchk = PacketDissector._extract_str_val(udp_layer, "udp.checksum", "N/A")
            layers_tree.append({
                "name": f"User Datagram Protocol, Src Port: {src_port}, Dst Port: {dst_port}",
                "children": [
                    f"Source Port: {src_port}",
                    f"Destination Port: {dst_port}",
                    f"Length: {ulen}",
                    f"Checksum: {uchk}"
                ]
            })

        return {
            "no": number,
            "time": time_str,
            "src": src_ip,
            "dst": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": length,
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

