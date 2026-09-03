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

def evaluate_heuristics(process_data: dict, packet_data: dict) -> list[str]:
    """
    Evaluate MITRE ATT&CK heuristics based on process and network activity.
    
    Args:
        process_data: Dictionary containing process information.
        packet_data: Dictionary containing network packet information.
        
    Returns:
        A list of MITRE ATT&CK technique IDs.
    """
    process_name = process_data.get('name', '')
    mitre_tags = []
    
    if process_name in LOLBIN_SET:
        dst_ip = packet_data.get('dst', '')
        
        if is_public_ip(dst_ip):
            technique = MITRE_TECHNIQUE_MAP.get(process_name)
            if technique:
                mitre_tags.append(technique)
                
            try:
                dst_port_str = packet_data.get('dst_port', 0)
                dst_port = int(dst_port_str) if dst_port_str else 0
            except ValueError:
                dst_port = 0
                
            web_ports = {80, 443, 8080, 8443}
            standard_ports = {22, 53, 80, 443, 8080, 8443}
            
            if dst_port in web_ports:
                mitre_tags.append('T1071')
            elif dst_port not in standard_ports:
                mitre_tags.append('T1571')
                
    return mitre_tags

def compute_severity(threat_data: dict, mitre_tags: list, process_data: dict) -> str:
    """
    Compute the severity level based on threat intelligence, heuristics, and process data.
    
    Args:
        threat_data: Threat intelligence dictionary.
        mitre_tags: List of MITRE ATT&CK technique IDs found.
        process_data: Process data dictionary.
        
    Returns:
        One of 'critical', 'high', 'medium', or 'safe'.
    """
    abuse_score = threat_data.get('abuse_score', 0)
    vt_malicious = threat_data.get('vt_malicious', 0)
    process_name = process_data.get('name', '')
    
    is_lolbin = process_name in LOLBIN_SET
    
    if abuse_score >= 80 or vt_malicious >= 5 or (is_lolbin and len(mitre_tags) > 1):
        return 'critical'
    
    if abuse_score >= 40 or vt_malicious >= 2 or len(mitre_tags) == 1:
        return 'high'
    
    if len(mitre_tags) > 0 or abuse_score > 0:
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
