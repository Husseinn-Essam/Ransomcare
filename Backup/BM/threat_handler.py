"""
Handles the response to a detected ransomware threat.
"""

import psutil
import logging
import hashlib

from .constants import flagged_processes, HIGH_CONFIDENCE_THRESHOLD

def handle_detected_threat(pid, score, detection_reasons):
    """Handle a detected ransomware threat"""
    if pid in flagged_processes: # Double check if already handled
        return
        
    # Special case for unknown PIDs (-1)
    if pid == -1:
        # Can't terminate a specific process for unknown operations
        flagged_processes.add(-1)  # Flag to prevent re-alerting
        
        alert_message = (
            "\n" + "!"*80 + "\n"
            f"RANSOMWARE THREAT DETECTED FROM UNKNOWN PROCESS!\n"
            f"---------------------------\n"
            f"WARNING: Process could not be identified\n"
            f"Threat Score: {score} (Threshold: {HIGH_CONFIDENCE_THRESHOLD})\n"
            f"Reasons: {', '.join(detection_reasons)}\n"
            f"ACTION: Manual investigation required - system under attack\n"
            f"Look for suspicious processes with high disk activity\n"
            + "!"*80 + "\n"
        )
        print(alert_message)
        logging.critical(f"RANSOMWARE THREAT DETECTED (UNKNOWN PROCESS): Score {score}, Reasons: {', '.join(detection_reasons)}")
        return
    
    # Never attempt to terminate system processes
    if pid <= 4:
        logging.error(f"Invalid threat detection for system process {pid}. This should never happen!")
        return
    
    # Protect critical system processes
    if pid >= 0 and pid <= 4:  # System processes have PIDs 0-4
        logging.error(f"CRITICAL ERROR: Attempted to flag system process {pid} as ransomware. This is a bug.")
        print(f"ERROR: System incorrectly identified system process {pid} as threat. This is a bug.")
        
        alert_message = (
            "\n" + "!"*80 + "\n"
            f"RANSOMWARE THREAT DETECTED (UNKNOWN PROCESS)!\n"
            f"---------------------------\n"
            f"Warning: Process could not be identified\n"
            f"Threat Score: {score} (Threshold: {HIGH_CONFIDENCE_THRESHOLD})\n"
            f"Reasons: {', '.join(detection_reasons)}\n"
            f"ACTION: Manual investigation required - cannot terminate unknown process\n"
            f"Look for suspicious processes with high disk activity\n"
            + "!"*80 + "\n"
        )
        print(alert_message)
        logging.critical(f"RANSOMWARE THREAT DETECTED (UNKNOWN PROCESS): Score {score}, Reasons: {', '.join(detection_reasons)}")
        return

    try:
        proc = psutil.Process(pid)
        # Use as_dict for efficiency and safety
        proc_info = proc.as_dict(attrs=['name', 'exe', 'pid'])
        proc_name = proc_info.get('name', 'unknown')
        proc_path = proc_info.get('exe', 'unknown')
        
        # Mark as flagged to avoid duplicate actions
        flagged_processes.add(pid)
        
        # Log the threat
        logging.critical(
            f"RANSOMWARE THREAT DETECTED: Process {pid} ({proc_name}) at {proc_path} "
            f"scored {score}. Taking protective action. Reasons: {', '.join(detection_reasons)}"
        )
        
        # Calculate hash of the executable for reporting
        file_hash = "N/A"
        if proc_path and proc_path != "unknown":
            try:
                with open(proc_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    logging.critical(f"Threat file hash (SHA256): {file_hash}")
            except FileNotFoundError:
                 logging.error(f"Executable file not found for hashing: {proc_path}")
            except PermissionError:
                 logging.error(f"Permission denied to read executable file: {proc_path}")
            except Exception as e:
                logging.error(f"Unable to calculate hash for {proc_path}: {e}")
        
        # Create alert notification for user
        alert_message = (
            "\n" + "!"*80 + "\n"
            f"RANSOMWARE THREAT DETECTED!\n"
            f"---------------------------\n"
            f"Process Name: {proc_name}\n"
            f"Process ID:   {pid}\n"
            f"Process Path: {proc_path}\n"
            f"File Hash:    {file_hash}\n"
            f"Threat Score: {score} (Threshold: {HIGH_CONFIDENCE_THRESHOLD})\n"
            f"Reasons:      {', '.join(detection_reasons)}\n"
            f"ACTION:       Attempting to terminate process...\n"
            + "!"*80 + "\n"
        )
        print(alert_message)
        
        # Kill the process
        try:
            logging.warning(f"Attempting to terminate process {pid} ({proc_name})")
            proc.terminate()
            
            # Wait briefly for graceful termination
            try:
                 gone, alive = psutil.wait_procs([proc], timeout=1)
                 if proc in alive:
                     logging.warning(f"Process {pid} did not terminate gracefully, forcing kill.")
                     proc.kill()
                     gone, alive = psutil.wait_procs([proc], timeout=1) # Check again after kill
                     if proc in alive:
                          logging.error(f"Failed to kill process {pid} even after force kill.")
                     else:
                          logging.info(f"Process {pid} successfully killed.")
                 else:
                     logging.info(f"Process {pid} successfully terminated.")
            except psutil.TimeoutExpired:
                 logging.warning(f"Timeout waiting for process {pid} termination status, assuming killed.")
            
        except psutil.AccessDenied as e:
            logging.error(f"Access Denied: Failed to terminate process {pid}. {e}")
            print(f"ERROR: Access Denied trying to terminate process {pid}. Run as Administrator.")
        except psutil.NoSuchProcess:
             logging.info(f"Process {pid} already terminated before action could be taken.")
             print(f"INFO: Process {pid} ({proc_name}) already stopped.")
        except Exception as e:
            logging.error(f"Unexpected error terminating process {pid}: {e}")
            print(f"ERROR: Could not terminate process {pid}: {e}")
    
    except psutil.NoSuchProcess:
        # Process might have terminated between detection and handling
        logging.warning(f"Threat handling failed: Process {pid} no longer exists.")
        if pid in flagged_processes: flagged_processes.discard(pid) # Remove if it disappeared
    except psutil.AccessDenied:
        logging.error(f"Access Denied: Cannot get information for process {pid} to handle threat.")
        flagged_processes.add(pid) # Still flag it to prevent re-analysis loops
    except Exception as e:
        logging.error(f"Unexpected error handling threat for PID {pid}: {e}")
        flagged_processes.add(pid) # Flag to prevent loops
