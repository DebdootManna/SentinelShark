"""
Core SecOps engine for UDM Normalizer and MITRE ATT&CK heuristics.
"""

import platform
from typing import Dict, List, Any

# Assuming this exists as instructed by the prompt
from app.services.threatintel import is_public_ip

LOLBIN_SET = {
    'bash', 'sh', 'zsh', 'python', 'python3', 'python3.11', 'python3.12', 
    'python3.13', 'python3.14', 'curl', 'wget', 'powershell.exe', 'cmd.exe', 
    'nc', 'ncat', 'socat', 'ruby', 'perl', 'node'
}

MITRE_TECHNIQUE_MAP = {
    'bash': 'T1059',
    'sh': 'T1059',
    'zsh': 'T1059',
    'python': 'T1059',
    'python3': 'T1059',
    'python3.11': 'T1059',
    'python3.12': 'T1059',
    'python3.13': 'T1059',
    'python3.14': 'T1059',
    'powershell.exe': 'T1059',
    'cmd.exe': 'T1059',
    'curl': 'T1105',
    'wget': 'T1105',
    'nc': 'T1095',
    'ncat': 'T1095',
    'socat': 'T1095'
}

TECHNIQUE_NAMES = {
    'T1071': 'App Layer Protocol',
    'T1071.001': 'Web Protocols',
    'T1071.004': 'DNS Protocol',
    'T1059': 'Command & Scripting',
    'T1105': 'Ingress Tool Transfer',
    'T1095': 'Non-App Layer Protocol',
    'T1571': 'Non-Standard Port',
    'T1021.004': 'SSH Remote Services',
}


def evaluate_heuristics(process_data: dict, packet_data: dict) -> list[str]:
    """
    Evaluate MITRE ATT&CK heuristics based on process activity, network protocols,
    and baseline behavioral detection rules.
    """
    process_name = (process_data.get('name', '') or '').lower()
    mitre_tags = []

    # 1. LOLBin Heuristics
    matched_lolbin = None
    for lol in LOLBIN_SET:
        if lol == process_name or process_name.startswith(f"{lol}.") or f"/{lol}" in process_name:
            matched_lolbin = lol
            break

    try:
        dst_port_str = packet_data.get('dst_port', 0)
        dst_port = int(dst_port_str) if dst_port_str else 0
    except (ValueError, TypeError):
        dst_port = 0

    try:
        src_port_str = packet_data.get('src_port', 0)
        src_port = int(src_port_str) if src_port_str else 0
    except (ValueError, TypeError):
        src_port = 0

    protocol = str(packet_data.get('protocol', '') or '').upper()

    if matched_lolbin:
        technique = MITRE_TECHNIQUE_MAP.get(matched_lolbin, 'T1059')
        if technique and technique not in mitre_tags:
            mitre_tags.append(technique)

        web_ports = {80, 443, 8080, 8443}
        standard_ports = {22, 53, 80, 443, 8080, 8443}

        if dst_port in web_ports or src_port in web_ports:
            if 'T1071' not in mitre_tags:
                mitre_tags.append('T1071')
        elif dst_port not in standard_ports and src_port not in standard_ports:
            if 'T1571' not in mitre_tags:
                mitre_tags.append('T1571')

    # 2. Baseline Behavioral Detection Rules (populates coverage telemetry during normal captures)
    # DNS Traffic (queries on port 53 or DNS protocol)
    if dst_port == 53 or src_port == 53 or protocol == 'DNS':
        if 'T1071.004' not in mitre_tags:
            mitre_tags.append('T1071.004')

    # Unencrypted HTTP Traffic (plain web on port 80 or HTTP protocol)
    elif dst_port == 80 or src_port == 80 or protocol == 'HTTP':
        if 'T1071.001' not in mitre_tags:
            mitre_tags.append('T1071.001')

    # Standard Encrypted Web / TLS Traffic (port 443, HTTPS, TLS, QUIC)
    elif dst_port == 443 or src_port == 443 or protocol in ('HTTPS', 'TLS', 'QUIC'):
        if 'T1071' not in mitre_tags:
            mitre_tags.append('T1071')

    # Remote Management (SSH on port 22)
    elif dst_port == 22 or src_port == 22 or protocol == 'SSH':
        if 'T1021.004' not in mitre_tags:
            mitre_tags.append('T1021.004')

    # Web protocol on non-standard ports
    elif protocol in ('HTTP', 'HTTPS', 'TLS') and dst_port not in (80, 443, 8080, 8443):
        if 'T1571' not in mitre_tags:
            mitre_tags.append('T1571')

    return mitre_tags


def compute_severity(threat_data: dict, mitre_tags: list, process_data: dict) -> str:
    """
    Compute severity level based on threat intel, heuristics, and process data.
    """
    threat_data = threat_data or {}
    abuse_score = threat_data.get('abuse_score', 0) or 0
    vt_malicious = threat_data.get('vt_malicious', 0) or 0
    process_name = (process_data.get('name', '') or '').lower()

    is_lolbin = any(lol in process_name for lol in LOLBIN_SET)
    high_risk_tags = {'T1059', 'T1105', 'T1095'}
    has_high_risk_tag = any(t in high_risk_tags for t in mitre_tags)

    if abuse_score >= 80 or vt_malicious >= 5 or (is_lolbin and len(mitre_tags) > 1):
        return 'critical'

    if abuse_score >= 40 or vt_malicious >= 2 or (is_lolbin and has_high_risk_tag):
        return 'high'

    if abuse_score > 0 or 'T1571' in mitre_tags or 'T1071.001' in mitre_tags or is_lolbin:
        return 'medium'

    return 'safe'

def normalize_to_udm(packet_data: dict, process_data: dict, threat_intel: dict) -> dict:
    """
    Normalize security event data into Google SecOps Unified Data Model (UDM) format.
    
    Args:
        packet_data: Network connection data.
        process_data: Process information data.
        threat_intel: Threat intelligence data.
        
    Returns:
        A dictionary structured according to the SecOps UDM schema.
    """
    mitre_tags = evaluate_heuristics(process_data, packet_data)
    
    try:
        dst_port_str = packet_data.get('dst_port', 0)
        dst_port = int(dst_port_str) if dst_port_str else 0
    except ValueError:
        dst_port = 0

    return {
        'metadata': {
            'event_timestamp': packet_data.get('time', ''),
            'event_type': 'NETWORK_CONNECTION',
            'product_name': 'SentinelShark EDR',
            'vendor_name': 'SentinelShark'
        },
        'principal': {
            'ip': packet_data.get('src', ''),
            'hostname': platform.node(),
            'process': {
                'pid': process_data.get('pid', 0),
                'file': {
                    'full_path': process_data.get('exe_path', ''),
                    'sha256': process_data.get('sha256', '')
                },
                'command_line': process_data.get('cmdline', ''),
                'parent_process': {
                    'pid': process_data.get('ppid', 0)
                }
            },
            'user': {
                'userid': process_data.get('username', '')
            }
        },
        'target': {
            'ip': packet_data.get('dst', ''),
            'port': dst_port
        },
        'network': {
            'application_protocol': packet_data.get('protocol', ''),
            'direction': 'OUTBOUND'
        },
        'security_result': {
            'severity': compute_severity(threat_intel, mitre_tags, process_data).upper(),
            'threat_name': ', '.join(mitre_tags) if mitre_tags else '',
            'summary': packet_data.get('info', '')
        }
    }
