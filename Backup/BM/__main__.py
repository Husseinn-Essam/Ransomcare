"""
Main entry point for the Ransomcare Behavioral Monitor.
Initializes logging, starts monitoring threads, and handles shutdown.
"""

import logging
import threading
import time
import sys
import os

# Configure logging (do this first)
log_filename = 'ransomware_detector.log'
log_level = logging.INFO
log_format = '%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s'

# Basic logging config
logging.basicConfig(
    filename=log_filename,
    level=log_level,
    format=log_format,
    filemode='a' # Append mode
)

# Add console handler for immediate feedback
console = logging.StreamHandler(sys.stdout) # Use stdout for console
console.setLevel(log_level) # Match file level or set differently (e.g., logging.WARNING)
formatter = logging.Formatter(log_format)
console.setFormatter(formatter)
logging.getLogger('').addHandler(console) # Add to root logger

# Now import other components from the package
from .constants import (
    INITIAL_THRESHOLD, HIGH_CONFIDENCE_THRESHOLD, FILE_WATCH_INTERVAL,
    PROCESS_CHECK_INTERVAL, TRUSTED_PROCESSES, PROTECTED_DIRS, stop_event
)
from .utils import initialize_protected_dirs
from .monitors.file_monitor import monitor_file_operations
from .monitors.process_monitor import monitor_processes

def start_monitoring():
    """Initializes and starts all monitoring threads."""
    try:
        # Initialize protected directories list
        initialize_protected_dirs()
        
        logging.info("===== Ransomware Detector Starting =====")
        logging.info(f"Version: 1.0.0") # Example version
        logging.info(f"Log Level: {logging.getLevelName(log_level)}")
        logging.info(f"File Watch Interval: {FILE_WATCH_INTERVAL}s")
        logging.info(f"Process Check Interval: {PROCESS_CHECK_INTERVAL}s")
        logging.info(f"Initial Threshold: {INITIAL_THRESHOLD}")
        logging.info(f"High Confidence Threshold: {HIGH_CONFIDENCE_THRESHOLD}")
        logging.info(f"Trusted Processes Count: {len(TRUSTED_PROCESSES)}")
        logging.info(f"Protected Directories Count: {len(PROTECTED_DIRS)}")
        
        print("--- Ransomware Detector ---")
        print(f"Monitoring active. Log file: {os.path.abspath(log_filename)}")
        print(f"Alert thresholds: Warning={INITIAL_THRESHOLD}, Critical={HIGH_CONFIDENCE_THRESHOLD}")
        print("Press Ctrl+C to stop.")
        print("---------------------------")
        
        # Create monitoring threads
        file_thread = threading.Thread(target=monitor_file_operations, name="FileMonitor", daemon=True)
        process_thread = threading.Thread(target=monitor_processes, name="ProcessMonitor", daemon=True)
        
        # Start monitoring threads
        file_thread.start()
        process_thread.start()
        
        logging.info("Monitoring threads started.")
        
        # Keep main thread alive while monitoring threads run
        while not stop_event.is_set():
            # Check if threads are alive (optional)
            if not file_thread.is_alive() or not process_thread.is_alive():
                 logging.error("A monitoring thread has unexpectedly stopped!")
                 stop_event.set() # Signal shutdown
                 break
            time.sleep(1) # Main thread sleep

    except Exception as e:
         logging.critical(f"Error during monitoring startup: {e}", exc_info=True)
         print(f"FATAL ERROR during startup: {e}")
         stop_event.set() # Ensure stop event is set if startup fails

def shutdown(file_thread, process_thread):
    """Handles graceful shutdown of monitoring threads."""
    print("\nStopping ransomware detector...")
    logging.info("Shutdown initiated.")
    
    # Signal threads to stop
    stop_event.set()
    
    # Wait for threads to finish with a timeout
    try:
        file_thread.join(timeout=5)
        if file_thread.is_alive():
            logging.warning("File monitor thread did not stop gracefully.")
    except Exception as e:
         logging.error(f"Error joining file_thread: {e}")

    try:
        process_thread.join(timeout=5)
        if process_thread.is_alive():
            logging.warning("Process monitor thread did not stop gracefully.")
    except Exception as e:
         logging.error(f"Error joining process_thread: {e}")
        
    logging.info("===== Ransomware Detector Stopped =====")
    print("Ransomware Detector stopped.")


if __name__ == "__main__":
    # Placeholder threads for shutdown call in case of early exit
    file_mon_thread = None
    proc_mon_thread = None
    try:
        # Re-get threads after start_monitoring potentially creates them
        # This assumes start_monitoring runs to the point of creating threads
        # A better approach might be to have start_monitoring return the threads
        
        # --- Start Monitoring ---
        # Create monitoring threads (modified start_monitoring to return threads)
        
        initialize_protected_dirs()
        
        logging.info("===== Ransomware Detector Starting =====")
        # ... (logging setup as before) ...
        print("--- Ransomware Detector ---")
        # ... (print statements as before) ...

        file_mon_thread = threading.Thread(target=monitor_file_operations, name="FileMonitor", daemon=True)
        proc_mon_thread = threading.Thread(target=monitor_processes, name="ProcessMonitor", daemon=True)
        
        file_mon_thread.start()
        proc_mon_thread.start()
        logging.info("Monitoring threads started.")

        # Keep main thread alive
        while True:
             if not file_mon_thread.is_alive() or not proc_mon_thread.is_alive():
                 logging.error("A monitoring thread has unexpectedly stopped!")
                 break # Exit loop to shutdown
             time.sleep(1)

    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received.")
        # Shutdown handled in finally block
    except Exception as e:
        logging.critical(f"Critical error in main execution: {e}", exc_info=True)
        print(f"CRITICAL ERROR: {e}")
    finally:
        # Ensure shutdown is called regardless of how the loop exits
        if file_mon_thread and proc_mon_thread:
             shutdown(file_mon_thread, proc_mon_thread)
        else:
             logging.warning("Monitoring threads not initialized properly, attempting basic shutdown.")
             stop_event.set() # Signal any potentially running parts to stop
             print("Ransomware Detector stopped (potential initialization issue).")
        
        logging.shutdown() # Flush and close logging handlers
        exit(1 if 'e' in locals() and isinstance(e, Exception) else 0) # Exit with error code if exception occurred
