import os
import psutil


class NetworkInterfaceMapper:
    """
    Cross-platform interface metadata mapper that bridges TShark interface names
    (such as \\Device\\NPF_{GUID} on Windows or en0 on macOS/Linux) to psutil adapter keys,
    IPv4 addresses, and clean human-readable labels out-of-the-box.
    """

    def __init__(self):
        self.npf_to_psutil = {}
        self.psutil_to_ip = {}
        self.refresh()

    def refresh(self):
        """Build or refresh mapping dictionaries."""
        self.npf_to_psutil.clear()
        self.psutil_to_ip.clear()

        # 1. Map psutil interfaces to IPv4 addresses
        try:
            addrs = psutil.net_if_addrs()
            for if_name, addr_list in addrs.items():
                for addr in addr_list:
                    if str(addr.family).endswith("AF_INET") or addr.family == 2:
                        self.psutil_to_ip[if_name] = addr.address
                        break
        except Exception as e:
            print(f"[InterfaceMapper] Error reading psutil addresses: {e}")

        # 2. Windows Registry NPF GUID lookup
        if os.name == "nt":
            try:
                import winreg
                net_key = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_key) as root:
                    i = 0
                    while True:
                        try:
                            guid = winreg.EnumKey(root, i)
                            i += 1
                            conn_key_path = f"{net_key}\\{guid}\\Connection"
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, conn_key_path) as conn:
                                    name, _ = winreg.QueryValueEx(conn, "Name")
                                    guid_lower = guid.lower()
                                    self.npf_to_psutil[guid_lower] = name
                                    self.npf_to_psutil[f"\\device\\npf_{guid_lower}"] = name
                                    self.npf_to_psutil[f"\\device\\npf_{guid}".lower()] = name
                            except OSError:
                                pass
                        except OSError:
                            break
            except Exception as e:
                print(f"[InterfaceMapper] Error mapping Windows NPF interfaces: {e}")

    def get_psutil_name(self, tshark_iface: str) -> str:
        """Map a TShark interface identifier to its corresponding psutil adapter key."""
        if not tshark_iface:
            return ""

        # Direct match
        if tshark_iface in self.psutil_to_ip:
            return tshark_iface

        t_lower = tshark_iface.lower().strip()

        # NPF map match
        if t_lower in self.npf_to_psutil:
            return self.npf_to_psutil[t_lower]

        # Loopback check
        if "loopback" in t_lower:
            for p_name in self.psutil_to_ip:
                if "loopback" in p_name.lower():
                    return p_name
            return "lo0" if "lo0" in self.psutil_to_ip else "Loopback Pseudo-Interface 1"

        # Partial GUID match
        for guid_or_npf, psutil_name in self.npf_to_psutil.items():
            if guid_or_npf in t_lower or t_lower in guid_or_npf:
                return psutil_name

        return tshark_iface

    def get_ip_address(self, tshark_iface: str) -> str:
        """Get IPv4 address associated with a TShark interface."""
        psutil_name = self.get_psutil_name(tshark_iface)
        if psutil_name in self.psutil_to_ip:
            return self.psutil_to_ip[psutil_name]
        if tshark_iface in self.psutil_to_ip:
            return self.psutil_to_ip[tshark_iface]
        return "N/A"

    def get_friendly_label(self, tshark_iface: str) -> str:
        """Get human-readable friendly label for GUI display."""
        psutil_name = self.get_psutil_name(tshark_iface)

        # Standard macOS / Linux common interface names
        mac_linux_names = {
            "en0": "Wi-Fi (en0)",
            "lo0": "Local Loopback (lo0)",
            "lo": "Local Loopback (lo)",
            "eth0": "Ethernet (eth0)",
            "wlan0": "Wireless Network (wlan0)",
            "awdl0": "Apple Direct Link (awdl0)",
            "llw0": "Low Latency WLAN (llw0)",
            "bridge0": "Network Bridge (bridge0)",
        }
        if tshark_iface in mac_linux_names:
            return mac_linux_names[tshark_iface]

        if psutil_name and psutil_name != tshark_iface:
            return f"{psutil_name} ({tshark_iface[:18]}...)" if len(tshark_iface) > 20 else f"{psutil_name} ({tshark_iface})"

        if "loopback" in tshark_iface.lower():
            return "Local Loopback"

        if tshark_iface.startswith("\\Device\\NPF_"):
            short_npf = tshark_iface.replace("\\Device\\NPF_", "")
            if len(short_npf) > 12:
                short_npf = short_npf[:8] + "..."
            return f"Network Device ({short_npf})"

        return tshark_iface


# Global interface mapper singleton
interface_mapper = NetworkInterfaceMapper()
