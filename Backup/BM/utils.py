"""
Utility and helper functions for the ransomware detector.
"""

import os
import math
import psutil
import logging
import time
import re
from collections import defaultdict, deque

# Import constants and state from the constants module
from .constants import (
    PROTECTED_DIRS, TRUSTED_PROCESSES, WINDOWS_MODULES_AVAILABLE, 
    EVENT_EXPIRY_TIME, MAX_HISTORY_ENTRIES, process_history, 
    file_operations, network_connections, flagged_processes,
    INITIAL_THRESHOLD, HIGH_CONFIDENCE_THRESHOLD
)

# Try to import Windows-specific modules if available
if WINDOWS_MODULES_AVAILABLE:
    import win32api
    import win32con
    import win32security

def initialize_protected_dirs():
    """Initialize protected directories based on the OS"""
    global PROTECTED_DIRS # Need to modify the global set from constants
    system_drive = os.environ.get('SystemDrive', 'C:')
    
    base_dirs = [
        os.path.join(system_drive, os.sep),
        os.environ.get('USERPROFILE', os.path.join(system_drive, 'Users')),
        os.environ.get('WINDIR', os.path.join(system_drive, 'Windows')),
        os.path.join(system_drive, 'Program Files'),
        os.path.join(system_drive, 'Program Files (x86)'),
        os.path.join(system_drive, 'ProgramData'),
    ]
    
    # Add user directories that are common targets
    user_dir = os.environ.get('USERPROFILE')
    if user_dir:
        for folder in ['Documents', 'Pictures', 'Desktop', 'Downloads', 'Videos', 'Music']:
            path = os.path.join(user_dir, folder)
            if os.path.exists(path): # Check if the directory exists before adding
                 base_dirs.append(path)
    
    PROTECTED_DIRS.update(dir for dir in base_dirs if os.path.exists(dir))
    logging.info(f"Initialized protected directories: {PROTECTED_DIRS}")


def get_process_name(pid):
    """Get process name safely"""
    # Special handling for PID 0 and -1 (our unknown PID marker)
    if pid == 0:
        return "unknown_operations"  # This is our special bucket, not System Idle Process
    if pid == -1:
        return "unknown_process"  # Special marker for unknown process
        
    try:
        proc = psutil.Process(pid)
        return proc.name().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"

def get_process_path(pid):
    """Get full process path safely"""
    try:
        proc = psutil.Process(pid)
        # Use as_dict to prevent multiple access attempts
        proc_info = proc.as_dict(attrs=['exe'])
        return proc_info.get('exe', "unknown").lower() if proc_info.get('exe') else "unknown"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"
    except Exception as e: # Catch potential other errors like zombie processes
        logging.debug(f"Could not get path for PID {pid}: {e}")
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
    
    if data_len == 0: # Avoid division by zero if sample is empty
        return 0

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
        return False # Assume not admin if we can't check
        
    try:
        proc_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        token = win32security.OpenProcessToken(proc_handle, win32con.TOKEN_QUERY)
        
        # Check if the token has the administrator SID
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
        is_admin = win32security.CheckTokenMembership(token, admin_sid)
        
        win32api.CloseHandle(proc_handle)
        win32api.CloseHandle(token)
        return is_admin
    except (win32api.error, psutil.NoSuchProcess, psutil.AccessDenied) as e:
        # Log error if needed, e.g., access denied
        # logging.debug(f"Could not check admin status for PID {pid}: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error checking admin status for PID {pid}: {e}")
        return False


def get_process_connections(pid):
    """Get network connections for a process"""
    try:
        proc = psutil.Process(pid)
        # Specify kind='inet' to potentially reduce overhead if only TCP/UDP needed
        return proc.connections(kind='inet') 
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []
    except Exception as e: # Catch potential errors like zombie processes
        logging.debug(f"Could not get connections for PID {pid}: {e}")
        return []


def log_suspicious_activity(pid, score, detection_reasons):
    """Log suspicious process activity"""
    process_name = get_process_name(pid)
    process_path = get_process_path(pid)
    
    if score >= HIGH_CONFIDENCE_THRESHOLD:
        level = "CRITICAL"
        log_func = logging.critical
    elif score >= INITIAL_THRESHOLD:
        level = "WARNING"
        log_func = logging.warning
    else:
        level = "INFO"
        log_func = logging.info # Log even low scores if needed for debugging/tuning
    
    reasons_str = ", ".join(detection_reasons)
    
    log_message = (
        f"{level}: Process {pid} ({process_name}) at {process_path} "
        f"scored {score}. Reasons: [{reasons_str}]"
    )
    
    log_func(log_message)


def cleanup_expired_entries():
    """Clean up expired entries from tracking dictionaries"""
    current_time = time.time()
    
    # Clean up processes that no longer exist or have expired data
    existing_pids = set(psutil.pids())
    
    for pid in list(process_history.keys()):
        if pid not in existing_pids:
            # Process doesn't exist anymore, remove all its data
            if pid in process_history: del process_history[pid]
            if pid in file_operations: del file_operations[pid]
            if pid in network_connections: del network_connections[pid]
            if pid in flagged_processes: flagged_processes.discard(pid)
            continue # Move to the next pid

        # Clean up expired events within existing process data
        if pid in process_history:
            process_history[pid] = deque(
                (e for e in process_history[pid] if current_time - e['time'] < EVENT_EXPIRY_TIME),
                maxlen=MAX_HISTORY_ENTRIES
            )
            # If deque becomes empty after cleanup, consider removing the pid entry
            # if not process_history[pid]: del process_history[pid] 
        
        if pid in file_operations:
            file_operations[pid] = deque(
                (e for e in file_operations[pid] if current_time - e['time'] < EVENT_EXPIRY_TIME),
                maxlen=MAX_HISTORY_ENTRIES
            )
            # if not file_operations[pid]: del file_operations[pid]

        if pid in network_connections:
            network_connections[pid] = deque(
                (e for e in network_connections[pid] if current_time - e['time'] < EVENT_EXPIRY_TIME),
                maxlen=MAX_HISTORY_ENTRIES
            )
            # if not network_connections[pid]: del network_connections[pid]

    # Optional: Clean up flagged processes if they no longer exist
    # flagged_processes.intersection_update(existing_pids) # Keep only existing flagged PIDs
