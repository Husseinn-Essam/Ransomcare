"""
Main entry point for the ransomware detector.
"""
import os
import logging
import time
import threading
import psutil
from collections import defaultdict, deque

# Configure logging with rotation
logging.basicConfig(
    filename='ransomware_detector.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Add console handler for immediate feedback
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Import our modules
from .constants import (
    initialize_protected_dirs, 
    MAX_HISTORY_ENTRIES, 
    INITIAL_THRESHOLD, 
    HIGH_CONFIDENCE_THRESHOLD,
    FILE_WATCH_INTERVAL,
    PROCESS_CHECK_INTERVAL,
    FEATURE_WEIGHTS,
    TRUSTED_PROCESSES,
    PROTECTED_DIRS
)
from .utils import log_suspicious_activity, is_process_trusted
from .monitors import monitor_file_operations, monitor_processes
from .threat_handler import handle_detected_threat

# Import detectors
from .detectors import (
    detect_file_encryption_patterns,
    detect_multiple_extension_changes,
    detect_mass_file_operations,
    detect_suspicious_file_access,
    detect_ransomware_extensions,
    detect_high_entropy_writes,
    detect_shadow_copy_deletion,
    detect_network_c2_traffic,
    detect_ransomware_process_patterns,
    detect_system_modifications,
    detect_high_disk_usage
)

# Global state
process_history = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
file_operations = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
network_connections = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
flagged_processes = set()             # PIDs of processes already flagged
scan_lock = threading.Lock()          # Lock for thread safety
stop_event = threading.Event()        # Event to signal threads to stop

def analyze_process(pid):
    """Analyze a process for ransomware behavior"""
    with scan_lock:
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            
            # Skip trusted processes
            if is_process_trusted(proc_name):
                return
            
            # Apply all detection functions and calculate score
            score = 0
            detection_reasons = []
            
            # File encryption patterns
            points = detect_file_encryption_patterns(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['file_encryption_patterns']
                detection_reasons.append(f"File encryption patterns: {points}")
            
            # Multiple extension changes
            points = detect_multiple_extension_changes(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['multiple_extension_changes']
                detection_reasons.append(f"Multiple extension changes: {points}")
            
            # Mass file operations
            points = detect_mass_file_operations(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['mass_file_operations']
                detection_reasons.append(f"Mass file operations: {points}")
            
            # Suspicious file access
            points = detect_suspicious_file_access(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['suspicious_file_access']
                detection_reasons.append(f"Suspicious file access: {points}")
                
            # Ransomware extensions
            points = detect_ransomware_extensions(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['ransomware_extensions']
                detection_reasons.append(f"Ransomware extensions detected: {points}")
            
            # High entropy writes
            points = detect_high_entropy_writes(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['high_entropy_writes']
                detection_reasons.append(f"High entropy writes: {points}")
            
            # Shadow copy deletion
            points = detect_shadow_copy_deletion(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['shadow_copy_deletion']
                detection_reasons.append(f"Shadow copy deletion attempt: {points}")
            
            # Network C2 traffic
            points = detect_network_c2_traffic(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['network_c2_traffic']
                detection_reasons.append(f"Suspicious network traffic: {points}")
            
            # Ransomware process patterns
            points = detect_ransomware_process_patterns(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['ransomware_process_patterns']
                detection_reasons.append(f"Ransomware process behavior: {points}")
            
            # High disk usage
            points = detect_high_disk_usage(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['high_disk_usage']
                detection_reasons.append(f"High disk usage: {points}")
            
            # System modifications
            points = detect_system_modifications(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['system_modifications']
                detection_reasons.append(f"Suspicious system modifications: {points}")
            
            # Log suspicious activity
            if score > 0:
                log_suspicious_activity(pid, score, detection_reasons)
            
            # Take action if score is high enough
            if score >= HIGH_CONFIDENCE_THRESHOLD:
                handle_detected_threat(pid, score, detection_reasons)
            elif score >= INITIAL_THRESHOLD:
                # For medium scores, just log a warning
                flagged_processes.add(pid)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logging.error(f"Error analyzing process {pid}: {e}")

def start_monitoring():
    """Start all monitoring threads"""
    initialize_protected_dirs()
    
    logging.info("===== Ransomware Detector Started =====")
    logging.info(f"Current settings: Initial threshold={INITIAL_THRESHOLD}, High confidence threshold={HIGH_CONFIDENCE_THRESHOLD}")
    
    print("Ransomware Detector started")
    print(f"- Monitoring file operations with {FILE_WATCH_INTERVAL}s interval")
    print(f"- Monitoring processes with {PROCESS_CHECK_INTERVAL}s interval")
    print(f"- Alert thresholds: Warning={INITIAL_THRESHOLD}, Critical={HIGH_CONFIDENCE_THRESHOLD}")
    print(f"- Trusted processes: {len(TRUSTED_PROCESSES)}")
    print(f"- Protected directories: {len(PROTECTED_DIRS)}")
    print("Monitoring active... Press Ctrl+C to stop")
    
    # Make global variables available to imported modules
    from . import utils
    utils.analyze_process = analyze_process
    
    from . import detectors
    from .detectors import file_operations as detectors_file_ops
    from .detectors import process_activity as detectors_proc
    from .detectors import network_activity as detectors_net
    from .detectors import system_changes as detectors_sys
    
    detectors_file_ops.file_operations = file_operations
    detectors_proc.process_history = process_history
    detectors_net.network_connections = network_connections
    detectors_sys.process_history = process_history
    
    from . import monitors
    from .monitors import file_monitor, process_monitor
    
    file_monitor.file_operations = file_operations
    file_monitor.stop_event = stop_event
    
    process_monitor.process_history = process_history
    process_monitor.file_operations = file_operations
    process_monitor.network_connections = network_connections
    process_monitor.flagged_processes = flagged_processes
    process_monitor.stop_event = stop_event
    process_monitor.scan_lock = scan_lock
    process_monitor.analyze_process = analyze_process
    
    # Start monitoring threads
    file_thread = threading.Thread(target=monitor_file_operations, daemon=True)
    process_thread = threading.Thread(target=monitor_processes, daemon=True)
    
    file_thread.start()
    process_thread.start()
    
    try:
        # Main thread waits for Ctrl+C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping ransomware detector...")
        stop_event.set()
        
        # Wait for threads to finish
        file_thread.join(timeout=5)
        process_thread.join(timeout=5)
        
        logging.info("===== Ransomware Detector Stopped =====")
        print("Ransomware Detector stopped")

if __name__ == "__main__":
    try:
        start_monitoring()
    except Exception as e:
        logging.critical(f"Critical error in main process: {e}")
        print(f"Critical error: {e}")
        exit(1)
