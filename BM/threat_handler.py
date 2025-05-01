"""
Threat handling functionality.
"""
import psutil
import logging
import hashlib

from .utils import get_process_name, get_process_path, calculate_file_hash

def handle_detected_threat(pid, score, detection_reasons):
    """Handle a detected ransomware threat"""
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc_path = proc.exe()
        
        # Log the threat
        logging.critical(
            f"RANSOMWARE THREAT DETECTED: Process {pid} ({proc_name}) at {proc_path} "
            f"scored {score} points. Taking protective action."
        )
        
        # Calculate hash of the executable for reporting
        file_hash = calculate_file_hash(proc_path)
        if file_hash:
            logging.critical(f"Threat file hash (SHA256): {file_hash}")
        
        # Create alert notification for user
        print("\n" + "!"*80)
        print(f"RANSOMWARE THREAT DETECTED: Process {proc_name} (PID: {pid})")
        print(f"Process path: {proc_path}")
        print(f"Detection score: {score} out of 25 threshold")
        print(f"Detection reasons: {', '.join(detection_reasons)}")
        print("!"*80 + "\n")
        
        # Kill the process
        try:
            logging.info(f"Attempting to terminate process {pid}")
            proc.terminate()
            
            # Wait up to 3 seconds for graceful termination
            gone, still_alive = psutil.wait_procs([proc], timeout=3)
            
            # If still running, force kill
            if proc in still_alive:
                logging.info(f"Process {pid} still alive after terminate(), killing")
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.error(f"Failed to terminate process {pid}: {e}")
            print(f"FAILED TO TERMINATE PROCESS: {str(e)}")
            print("Try running this program with administrator privileges")
    
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logging.error(f"Error handling threat for process {pid}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error handling threat: {e}")
