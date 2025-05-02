"""
Monitors process activity and analyzes processes for suspicious behavior.
"""

import psutil
import time
import logging

from ..constants import (
    stop_event, process_history, network_connections, flagged_processes,
    PROCESS_CHECK_INTERVAL, FEATURE_WEIGHTS, INITIAL_THRESHOLD, 
    HIGH_CONFIDENCE_THRESHOLD, scan_lock, REANALYSIS_INTERVAL, file_operations
)
from ..utils import (
    is_process_trusted, get_process_connections, log_suspicious_activity, 
    cleanup_expired_entries, get_process_name
)
from ..threat_handler import handle_detected_threat

# Import detector functions (adjust path if detectors are structured differently)
from ..detectors import file_detectors, process_detectors

def analyze_process(pid):
    """Analyze a process for ransomware behavior by calling detector functions."""
    # Special case for PID 0 - this is our "unknown PID" bucket, not System Idle Process
    if pid == 0:
        return analyze_unknown_operations()
        
    # Ensure analysis is thread-safe if called concurrently
    with scan_lock: 
        # Double check if process exists and isn't flagged before analysis
        if pid in flagged_processes:
            return
        try:
            # Skip system processes entirely
            if pid <= 4:  # System, Idle, System Interrupts, etc.
                return
                
            proc = psutil.Process(pid) # Check existence
            proc_name = get_process_name(pid) # Get name safely

            # Skip trusted processes early
            if is_process_trusted(proc_name):
                return
            
            # Apply all detection functions and calculate weighted score
            score = 0
            detection_reasons = []
            
            detector_funcs = {
                'file_encryption_patterns': file_detectors.detect_file_encryption_patterns,
                'multiple_extension_changes': file_detectors.detect_multiple_extension_changes,
                'mass_file_operations': file_detectors.detect_mass_file_operations,
                'suspicious_file_access': file_detectors.detect_suspicious_file_access,
                'ransomware_extensions': file_detectors.detect_ransomware_extensions,
                'high_entropy_writes': file_detectors.detect_high_entropy_writes,
                'shadow_copy_deletion': process_detectors.detect_shadow_copy_deletion,
                'network_c2_traffic': process_detectors.detect_network_c2_traffic,
                'ransomware_process_patterns': process_detectors.detect_ransomware_process_patterns,
                'system_modifications': process_detectors.detect_system_modifications,
                'high_disk_usage': process_detectors.detect_high_disk_usage,
            }

            for name, func in detector_funcs.items():
                try:
                    points = func(pid)
                    weight = FEATURE_WEIGHTS.get(name, 0) # Default weight 0 if not defined
                    if points > 0 and weight > 0:
                        weighted_score = points * weight
                        score += weighted_score
                        detection_reasons.append(f"{name} ({points} pts * {weight} weight = {weighted_score:.1f})") 
                except Exception as e:
                     logging.error(f"Error running detector '{name}' for PID {pid}: {e}")

            # Round final score
            score = round(score)

            # Log if any suspicious activity was detected (score > 0)
            if score > 0:
                log_suspicious_activity(pid, score, detection_reasons)
            
            # Take action based on score thresholds
            if score >= HIGH_CONFIDENCE_THRESHOLD:
                logging.warning(f"High confidence threat detected for PID {pid} (Score: {score}). Triggering handler.")
                handle_detected_threat(pid, score, detection_reasons)
            elif score >= INITIAL_THRESHOLD:
                logging.info(f"Moderate suspicion for PID {pid} (Score: {score}). Flagging process.")
                flagged_processes.add(pid)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass 
        except Exception as e:
            logging.error(f"Error analyzing process PID {pid}: {e}", exc_info=True)

def analyze_unknown_operations():
    """Specifically analyze operations from unknown PIDs to detect ransomware behavior."""
    with scan_lock:
        # Skip if unknown PID bucket is already flagged
        if -1 in flagged_processes:  # Use -1 as flag for unknown operations
            return
            
        score = 0
        detection_reasons = []
        
        # Only use file-based detectors that make sense for unknown PIDs
        unknown_detector_funcs = {
            'mass_file_operations': file_detectors.detect_mass_file_operations,
            'high_entropy_writes': file_detectors.detect_high_entropy_writes,
            'ransomware_extensions': file_detectors.detect_ransomware_extensions,
        }
        
        for name, func in unknown_detector_funcs.items():
            try:
                # Call with PID 0 which is our special bucket for unknown operations
                points = func(0)  
                weight = FEATURE_WEIGHTS.get(name, 0)
                if points > 0 and weight > 0:
                    weighted_score = points * weight
                    score += weighted_score
                    detection_reasons.append(f"{name} ({points} pts * {weight} weight = {weighted_score:.1f})")
            except Exception as e:
                logging.error(f"Error running unknown detector '{name}': {e}")
        
        # Round final score
        score = round(score)
        
        # Log suspicious activity for unknown PIDs
        if score > 0:
            logging.warning(f"Unknown PID operations scored {score}. Reasons: {', '.join(detection_reasons)}")
        
        # Take action based on thresholds
        if score >= HIGH_CONFIDENCE_THRESHOLD:
            logging.critical(f"HIGH RISK: Unknown operations detected (Score: {score}). Triggering alert.")
            handle_detected_threat(-1, score, detection_reasons)
        elif score >= INITIAL_THRESHOLD:
            logging.warning(f"Moderate suspicion for unknown operations (Score: {score}).")
            flagged_processes.add(-1)
            
        return score

def monitor_processes():
    """Monitor process creation, resource usage, and trigger analysis."""
    logging.info("Process monitor started.")
    
    monitored_pids = set()
    last_analysis_time = {}
    last_unknown_analysis = 0

    while not stop_event.is_set():
        current_pids = set()
        current_time = time.time()
        
        try:
            # Check unknown PID operations frequently (every few seconds)
            if current_time - last_unknown_analysis > 5:
                if 0 in file_operations and file_operations[0]:
                    analyze_unknown_operations()
                    last_unknown_analysis = current_time
                    
            # Iterate through currently running processes
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'create_time']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)
                    
                    # Skip system processes and known trusted processes efficiently
                    if pid <= 4 or proc.info.get('name') == 'System Idle Process':
                        continue
                    if is_process_trusted(proc.info.get('name', 'unknown')):
                        continue
                    
                    # Skip already flagged/handled processes
                    if pid in flagged_processes:
                        continue
                    
                    # Record basic telemetry
                    cpu_usage = proc.info.get('cpu_percent') 
                    if cpu_usage is not None:
                         process_history[pid].append({
                             'time': current_time,
                             'type': 'cpu_usage',
                             'value': cpu_usage
                         })
                    
                    try:
                        io_counters = proc.io_counters() 
                        process_history[pid].append({
                            'time': current_time,
                            'type': 'disk_io',
                            'read_bytes': io_counters.read_bytes,
                            'write_bytes': io_counters.write_bytes,
                            'read_count': io_counters.read_count,
                            'write_count': io_counters.write_count
                        })
                    except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
                        pass 
                    
                    try:
                        connections = get_process_connections(pid)
                        for conn in connections:
                            if conn.status == 'ESTABLISHED' and conn.raddr: 
                                network_connections[pid].append({
                                    'time': current_time,
                                    'status': conn.status,
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'local_ip': conn.laddr.ip if conn.laddr else None,
                                    'local_port': conn.laddr.port if conn.laddr else None
                                })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                         pass
                    except Exception as e:
                         logging.debug(f"Error getting connections for PID {pid}: {e}")

                    # Trigger Analysis
                    if pid not in monitored_pids:
                         logging.info(f"New process detected: PID={pid}, Name={proc.info.get('name', 'unknown')}. Analyzing.")
                         analyze_process(pid)
                         monitored_pids.add(pid)
                         last_analysis_time[pid] = current_time
                    elif current_time - last_analysis_time.get(pid, 0) > REANALYSIS_INTERVAL: 
                         if pid not in flagged_processes:
                             logging.debug(f"Re-analyzing process PID {pid} after interval.")
                             analyze_process(pid)
                         last_analysis_time[pid] = current_time

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    if pid in last_analysis_time: del last_analysis_time[pid]
                    continue 
                except Exception as e:
                    logging.debug(f"Error monitoring individual process PID {proc.info.get('pid', 'N/A')}: {e}")
            
            # Clean up data for PIDs that no longer exist
            terminated_pids = monitored_pids - current_pids
            for pid in terminated_pids:
                 monitored_pids.remove(pid)
                 if pid in last_analysis_time: del last_analysis_time[pid]

            cleanup_expired_entries()
            
            time.sleep(PROCESS_CHECK_INTERVAL)

        except Exception as e:
            logging.error(f"Critical error in process monitoring loop: {e}", exc_info=True)
            time.sleep(PROCESS_CHECK_INTERVAL * 5) 

    logging.info("Process monitor stopped.")
