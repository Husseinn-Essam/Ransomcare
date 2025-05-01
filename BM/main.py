"""
Main entry point for the ransomware detector.
"""
import os
import logging
import time
import threading
import psutil
import sys  # Added import
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
    detect_high_disk_usage,
    detect_ransomware_ml,
    setup_ml_detector
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
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name().lower()
        
        # Skip trusted processes
        if is_process_trusted(proc_name):
            return

        logging.debug(f"Starting analysis for process: {proc_name} (PID: {pid})")
        
        # Apply all detection functions and calculate score
        score = 0
        detection_reasons = []
        
        # File encryption patterns
        points = detect_file_encryption_patterns(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['file_encryption_patterns']
            score += weighted_points
            reason = f"File encryption patterns ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # Multiple extension changes
        points = detect_multiple_extension_changes(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['multiple_extension_changes']
            score += weighted_points
            reason = f"Multiple extension changes ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # Mass file operations
        points = detect_mass_file_operations(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['mass_file_operations']
            score += weighted_points
            reason = f"Mass file operations ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # Suspicious file access
        points = detect_suspicious_file_access(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['suspicious_file_access']
            score += weighted_points
            reason = f"Suspicious file access ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # Ransomware extensions
        points = detect_ransomware_extensions(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['ransomware_extensions']
            score += weighted_points
            reason = f"Ransomware extensions detected ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # High entropy writes
        points = detect_high_entropy_writes(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['high_entropy_writes']
            score += weighted_points
            reason = f"High entropy writes ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # Shadow copy deletion
        points = detect_shadow_copy_deletion(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['shadow_copy_deletion']
            score += weighted_points
            reason = f"Shadow copy deletion attempt ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # Network C2 traffic
        points = detect_network_c2_traffic(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['network_c2_traffic']
            score += weighted_points
            reason = f"Suspicious network traffic ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # Ransomware process patterns
        points = detect_ransomware_process_patterns(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['ransomware_process_patterns']
            score += weighted_points
            reason = f"Ransomware process behavior ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # High disk usage
        points = detect_high_disk_usage(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['high_disk_usage']
            score += weighted_points
            reason = f"High disk usage ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # System modifications
        points = detect_system_modifications(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS['system_modifications']
            score += weighted_points
            reason = f"Suspicious system modifications ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")

        # ML-based detection
        points = detect_ransomware_ml(pid)
        if points > 0:
            weighted_points = points * FEATURE_WEIGHTS.get('ml_detection', 6)
            score += weighted_points
            reason = f"Machine learning detection ({points} raw, {weighted_points:.1f} weighted)"
            detection_reasons.append(reason)
            logging.debug(f"PID {pid}: +{weighted_points:.1f} score. Reason: {reason}")
        
        # Log final score if above zero
        if score > 0:
            logging.info(f"Analysis complete for PID {pid} ('{proc_name}'). Final Score: {score:.1f}")
            log_suspicious_activity(pid, score, detection_reasons)
        else:
            logging.debug(f"Analysis complete for PID {pid} ('{proc_name}'). Score: {score:.1f}. No suspicious activity detected.")

        # Take action if score is high enough
        if score >= HIGH_CONFIDENCE_THRESHOLD:
            if pid not in flagged_processes:
                logging.critical(f"CRITICAL THREAT DETECTED: PID={pid}, Name='{proc_name}', Score={score:.1f}. Initiating response.")
                print(f"[!!!] CRITICAL THREAT: PID={pid}, Name='{proc_name}', Score={score:.1f}. Taking action!")
                handle_detected_threat(pid, score, detection_reasons)
                flagged_processes.add(pid)
            else:
                logging.warning(f"PID {pid} ('{proc_name}') score {score:.1f} remains above critical threshold, but already handled.")
        elif score >= INITIAL_THRESHOLD:
            if pid not in flagged_processes:
                 logging.warning(f"Potential threat detected: PID={pid}, Name='{proc_name}', Score={score:.1f}. Monitoring closely.")
                 print(f"[!] WARNING: PID={pid}, Name='{proc_name}', Score={score:.1f}. Monitoring closely.")
                 flagged_processes.add(pid)
            else:
                 logging.info(f"PID {pid} ('{proc_name}') score {score:.1f} remains above initial threshold, already flagged.")
                
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        logging.debug(f"Process {pid} terminated or access denied during analysis.")
        pass
    except Exception as e:
        logging.error(f"Error analyzing process {pid}: {e}", exc_info=True)

def start_monitoring():
    """Start all monitoring threads"""
    initialize_protected_dirs()
    
    logging.info("="*20 + " RansomCare Detector Starting " + "="*20)
    logging.info(f"Version: 1.0.0")
    logging.info(f"OS: {os.name}, Platform: {sys.platform}")
    logging.info(f"Python Version: {sys.version}")
    logging.info(f"Process ID: {os.getpid()}")
    logging.info(f"Initial threshold={INITIAL_THRESHOLD}, High confidence threshold={HIGH_CONFIDENCE_THRESHOLD}")
    logging.info(f"File Watch Interval: {FILE_WATCH_INTERVAL}s, Process Check Interval: {PROCESS_CHECK_INTERVAL}s")
    logging.info(f"Trusted processes count: {len(TRUSTED_PROCESSES)}")
    logging.info(f"Protected directories count: {len(PROTECTED_DIRS)}")
    if PROTECTED_DIRS:
        for d in sorted(list(PROTECTED_DIRS)):
             logging.info(f"  - Protected: {d}")
    
    print("="*60)
    print("     RansomCare - Ransomware Detection System      ")
    print("="*60)
    print(f"[+] Initializing RansomCare...")
    print(f"- Alert thresholds: Warning={INITIAL_THRESHOLD}, Critical={HIGH_CONFIDENCE_THRESHOLD}")
    print(f"- Monitoring {len(PROTECTED_DIRS)} protected directories.")
    print(f"[+] Initializing ML detector...")
    
    # Initialize ML detector
    setup_ml_detector()
    logging.info("ML detector initialized.")
    print("[+] ML detector initialized.")
    
    from . import utils
    utils.analyze_process = analyze_process
    
    from . import detectors
    from .detectors import file_operations as detectors_file_ops
    from .detectors import process_activity as detectors_proc
    from .detectors import network_activity as detectors_net
    from .detectors import system_changes as detectors_sys
    from .detectors import ml_detector
    
    detectors_file_ops.file_operations = file_operations
    detectors_proc.process_history = process_history
    detectors_net.network_connections = network_connections
    detectors_sys.process_history = process_history
    ml_detector.process_history = process_history
    ml_detector.file_operations = file_operations
    ml_detector.network_connections = network_connections
    
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
    
    logging.info("Starting monitoring threads...")
    print("[+] Starting monitoring threads...")
    
    # Start monitoring threads
    file_thread = threading.Thread(target=monitor_file_operations, name="FileMonitorThread", daemon=True)
    process_thread = threading.Thread(target=monitor_processes, name="ProcessMonitorThread", daemon=True)
    
    file_thread.start()
    process_thread.start()
    
    logging.info("Monitoring threads started successfully.")
    print("[+] Monitoring active. Press Ctrl+C to stop.")
    
    try:
        while file_thread.is_alive() and process_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutdown signal received (Ctrl+C). Stopping monitors...")
        logging.info("Shutdown signal received (KeyboardInterrupt).")
        stop_event.set()
    except Exception as e:
        logging.critical(f"Main loop encountered an unexpected error: {e}", exc_info=True)
        print(f"[!!!] CRITICAL ERROR in main loop: {e}. Shutting down.")
        stop_event.set()
    finally:
        logging.info("Waiting for monitoring threads to terminate...")
        print("[*] Waiting for monitoring threads to finish...")
        
        file_thread.join(timeout=5)
        process_thread.join(timeout=5)
        
        if file_thread.is_alive():
            logging.warning("File monitoring thread did not terminate gracefully.")
            print("[!] File monitoring thread timed out.")
        else:
            logging.info("File monitoring thread terminated.")
            print("[+] File monitoring thread stopped.")
            
        if process_thread.is_alive():
            logging.warning("Process monitoring thread did not terminate gracefully.")
            print("[!] Process monitoring thread timed out.")
        else:
            logging.info("Process monitoring thread terminated.")
            print("[+] Process monitoring thread stopped.")
            
        logging.info("="*20 + " RansomCare Detector Stopped " + "="*20)
        print("[+] RansomCare Detector stopped.")

if __name__ == "__main__":
    try:
        start_monitoring()
    except Exception as e:
        logging.critical(f"Critical error in main process: {e}")
        print(f"Critical error: {e}")
        exit(1)
