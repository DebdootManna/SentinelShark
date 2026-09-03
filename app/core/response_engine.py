"""
Active Response Engine for SentinelShark EDR.
Handles process termination, IP blocking, and file quarantine.
"""

import os
import platform
import subprocess
import shutil
import ipaddress
import time
import psutil
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal

def kill_process(pid: int) -> tuple[bool, str]:
    """
    Terminates a process by its PID.
    """
    try:
        if pid in (0, 1, os.getpid()):
            return False, f"Cannot terminate protected PID {pid}"
        
        proc = psutil.Process(pid)
        name = proc.name()
        proc.kill()
        return True, f"Process {pid} ({name}) terminated successfully"
    except psutil.NoSuchProcess:
        return False, f"Process {pid} no longer exists"
    except psutil.AccessDenied:
        return False, f"Access denied: insufficient privileges to kill PID {pid}"
    except Exception as e:
        return False, f"Error killing PID {pid}: {str(e)}"

def block_remote_ip(ip: str) -> tuple[bool, str]:
    """
    Blocks a remote IP address using OS-native firewall tools.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid IP address: {ip}"

    sys_platform = platform.system()
    try:
        if sys_platform == 'Linux':
            cmd = ['iptables', '-I', 'OUTPUT', '-d', ip, '-j', 'DROP']
        elif sys_platform == 'Darwin':
            cmd = ['pfctl', '-t', 'sentinelshark_blocked', '-T', 'add', ip]
        else:
            return False, f"Unsupported OS for IP blocking: {sys_platform}"
            
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            return True, f"Firewall rule created: blocking outbound traffic to {ip}"
        else:
            return False, f"Firewall command failed: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, f"Timeout while executing firewall command for {ip}"
    except Exception as e:
        return False, f"Error blocking IP {ip}: {str(e)}"

def quarantine_file(file_path: str) -> tuple[bool, str]:
    """
    Moves a file to a secure quarantine directory.
    """
    try:
        if not os.path.isfile(file_path):
            return False, f"File not found or not a regular file: {file_path}"
            
        quarantine_dir = Path.home() / '.sentinelshark' / 'quarantine'
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        orig_path = Path(file_path)
        timestamp = int(time.time())
        quarantine_filename = f"{orig_path.name}.{timestamp}.quarantined"
        quarantine_path = quarantine_dir / quarantine_filename
        
        shutil.move(file_path, str(quarantine_path))
        os.chmod(quarantine_path, 0o000)
        
        return True, f"File quarantined: {file_path} → {quarantine_path}"
    except PermissionError:
        return False, f"Permission denied while quarantining {file_path}"
    except FileNotFoundError:
        return False, f"File not found during quarantine: {file_path}"
    except OSError as e:
        return False, f"OS error while quarantining {file_path}: {str(e)}"
    except Exception as e:
        return False, f"Error quarantining file {file_path}: {str(e)}"

class ResponseWorkerThread(QThread):
    """
    Worker thread to perform active response actions without blocking the UI.
    """
    action_completed = pyqtSignal(bool, str)

    def __init__(self, action: str, **kwargs):
        super().__init__()
        self.action = action
        self.kwargs = kwargs

    def run(self):
        success = False
        message = ""
        
        try:
            if self.action == 'kill_process':
                pid = self.kwargs.get('pid')
                if pid is not None:
                    success, message = kill_process(pid)
                else:
                    success, message = False, "Missing 'pid' argument for kill_process"
                    
            elif self.action == 'block_remote_ip':
                ip = self.kwargs.get('ip')
                if ip is not None:
                    success, message = block_remote_ip(ip)
                else:
                    success, message = False, "Missing 'ip' argument for block_remote_ip"
                    
            elif self.action == 'quarantine_file':
                file_path = self.kwargs.get('file_path')
                if file_path is not None:
                    success, message = quarantine_file(file_path)
                else:
                    success, message = False, "Missing 'file_path' argument for quarantine_file"
                    
            else:
                success, message = False, f"Unknown action: {self.action}"
                
        except Exception as e:
            success, message = False, f"Thread error executing {self.action}: {str(e)}"
            
        self.action_completed.emit(success, message)
