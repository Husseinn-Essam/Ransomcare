"""
Utility functions for the ransomware detector.
"""
import os
import math
import psutil
import logging
from collections import defaultdict
import hashlib

# Try to import Windows-specific modules safely
try:
    import winreg
    import win32process
    import win32con
    import win32security
    import win32api
    import win32file
    WINDOWS_MODULES_AVAILABLE = True
except ImportError:
    WINDOWS_MODULES_AVAILABLE = False
    logging.warning("Windows-specific modules not available - some checks will be limited")

from .constants import TRUSTED_PROCESSES

def get_process_name(pid):
    """Get process name safely"""
    try:
        proc = psutil.Process(pid)
        return proc.name().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"

def get_process_path(pid):
    """Get full process path safely"""
    try:
        proc = psutil.Process(pid)
        return proc.exe().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"

def calculate_entropy(data, sample_size=8192):
    """Calculate Shannon entropy of data (measure of randomness)"""
    if not data:
        return 0
    
    # Take a sample to improve performance for large files
    if len(data) > sample_size:
        # Take samples from beginning, middle and end
        samples = []
        samples.append(data[:sample_size//3])
        mid_point = len(data) // 2
        samples.append(data[mid_point-sample_size//6:mid_point+sample_size//6])
        samples.append(data[-sample_size//3:])
        data = b''.join(samples)
    
    # Count byte frequencies
    byte_counts = defaultdict(int)
    data_len = len(data)
    
    for byte in data:
        byte_counts[byte] += 1
    
    # Calculate entropy
    entropy = 0
    for count in byte_counts.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    
    return entropy

def is_process_trusted(process_name):
    """Check if process is in the trusted list"""
    return process_name.lower() in TRUSTED_PROCESSES

def is_admin_process(pid):
    """Check if process has admin privileges"""
    if not WINDOWS_MODULES_AVAILABLE:
        return False
        
    try:
        proc_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        token = win32security.OpenProcessToken(proc_handle, win32con.TOKEN_QUERY)
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        
        # Get administrator SID
        admin_sid = win32security.LookupAccountName(None, 'Administrators')[0]
        
        # Check if process belongs to admin group
        return win32security.CheckTokenMembership(token, admin_sid)
    except:
        return False

def get_process_connections(pid):
    """Get network connections for a process"""
    try:
        proc = psutil.Process(pid)
        return proc.connections(kind='all')
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []

def log_suspicious_activity(pid, score, detection_reasons):
    """Log suspicious process activity"""
    process_name = get_process_name(pid)
    process_path = get_process_path(pid)
    
    if score >= 25:  # HIGH_CONFIDENCE_THRESHOLD
        level = "CRITICAL"
    elif score >= 15:  # INITIAL_THRESHOLD
        level = "WARNING"
    else:
        level = "INFO"
    
    reasons_str = ", ".join(detection_reasons)
    
    log_message = (
        f"{level}: Process {pid} ({process_name}) at {process_path} "
        f"scored {score} points. Reasons: {reasons_str}"
    )
    
    if level == "CRITICAL":
        logging.critical(log_message)
    elif level == "WARNING":
        logging.warning(log_message)
    else:
        logging.info(log_message)

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None
