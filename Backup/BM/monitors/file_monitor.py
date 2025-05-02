"""
Monitors file system operations using watchdog.
"""

import psutil
import os
import time
import logging
import re
import subprocess
from collections import defaultdict

# Import watchdog components
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemMovedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.error("Watchdog library not found. File monitoring will be disabled. Install with: pip install watchdog")

from ..constants import (
    stop_event, file_operations, PROTECTED_DIRS, WINDOWS_MODULES_AVAILABLE
)
from ..utils import is_process_trusted, calculate_entropy, get_process_name

# --- Watchdog Event Handler ---
class RansomwareEventHandler(FileSystemEventHandler):
    """Handles file system events detected by watchdog."""

    def __init__(self):
        super().__init__()
        self.pid_cache = {} # Simple cache for PID lookup {path: pid} - very unreliable

    def _get_pid_for_path(self, path):
        """
        Attempt to find the PID that might be related to this path.
        Uses multiple strategies to improve detection reliability.
        """
        # Check cache first (quick path)
        if path in self.pid_cache:
            try:
                proc = psutil.Process(self.pid_cache[path])
                # Verify the process still exists and has the file open
                if any(hasattr(f, 'path') and f.path == path for f in proc.open_files()):
                    logging.debug(f"PID cache hit for path {path}: PID {self.pid_cache[path]}")
                    return self.pid_cache[path]
                else:
                    del self.pid_cache[path]  # Cache invalid
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
                if path in self.pid_cache: 
                    del self.pid_cache[path]  # Clean invalid entry
        
        # Strategy 1: Check recently active processes with disk I/O first
        # This is more efficient than checking all processes
        try:
            active_pids = []
            for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
                # Skip system processes and our own process
                if proc.info['pid'] <= 4 or proc.info['pid'] == os.getpid():
                    continue
                if is_process_trusted(proc.info.get('name', '')):
                    continue
                    
                # Get processes with recent disk activity
                if 'io_counters' in proc.info and proc.info['io_counters']:
                    active_pids.append(proc.info['pid'])
            
            # Check most active processes first (limited to 10 for performance)
            for pid in active_pids[:10]:
                try:
                    proc = psutil.Process(pid)
                    open_files = proc.open_files()
                    if any(hasattr(f, 'path') and f.path == path for f in open_files):
                        self.pid_cache[path] = pid  # Update cache
                        logging.debug(f"Found PID {pid} ({proc.name()}) for path {path} via active I/O check")
                        return pid
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except Exception as e:
            logging.debug(f"Error during active process check for {path}: {e}")
        
        # Strategy 2: Use Windows-specific tools if available
        if WINDOWS_MODULES_AVAILABLE:
            try:
                # Try using handle.exe (SysInternals) if available
                handle_cmd = "handle.exe"
                if os.path.exists('C:\\Windows\\System32\\handle.exe') or os.path.exists('handle.exe'):
                    normalized_path = path.lower().replace('\\', '\\\\')
                    cmd = [handle_cmd, normalized_path, "/accepteula"]
                    try:
                        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=1).decode('utf-8', errors='ignore')
                        # Parse output to find PIDs
                        for line in output.splitlines():
                            match = re.search(r'pid: (\d+)', line, re.IGNORECASE)
                            if match:
                                pid = int(match.group(1))
                                if pid > 4:  # Ignore system processes
                                    self.pid_cache[path] = pid
                                    logging.debug(f"Found PID {pid} for path {path} via handle.exe")
                                    return pid
                    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                        logging.debug(f"Handle.exe failed for {path}: {e}")
            except Exception as e:
                logging.debug(f"Error during Windows-specific check for {path}: {e}")
        
        # Strategy 3: Fallback to checking all processes (expensive)
        try:
            logging.debug(f"Advanced PID detection for path {path}")
            
            # Build up a list of suspicious processes first, then check only those
            suspicious_processes = []
            
            # First pass: collect processes with disk activity or in suspicious locations
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                pid = proc.info['pid']
                
                # Skip system processes and trusted processes
                if pid <= 4 or pid == os.getpid() or is_process_trusted(proc.info.get('name', '')):
                    continue
                
                try:
                    # Check if process has suspicious path or high I/O activity
                    exe_path = proc.info.get('exe', '')
                    is_suspicious = False
                    
                    # Check exe location (temp folders are suspicious)
                    if exe_path and any(substring in exe_path.lower() for substring in 
                                       ['\\temp\\', '\\tmp\\', '\\appdata\\local\\', '\\downloads\\']):
                        is_suspicious = True
                    
                    # Add to suspicious list if criteria met
                    if is_suspicious:
                        suspicious_processes.append(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # If we have suspicious processes, check them first
            target_processes = suspicious_processes if suspicious_processes else list(psutil.pids())
            for pid in target_processes:
                if pid <= 4 or pid == os.getpid():
                    continue
                    
                try:
                    proc = psutil.Process(pid)
                    open_files = proc.open_files()
                    # Check if file path matches
                    if any(hasattr(f, 'path') and f.path == path for f in open_files):
                        self.pid_cache[path] = pid
                        logging.debug(f"Found PID {pid} ({proc.name()}) for path {path} via full process scan")
                        return pid
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue
        except Exception as e:
            logging.error(f"Error during process scan for {path}: {e}")
        
        # Strategy 4: Directory-based heuristic 
        # Check if any process has recently accessed files in the same directory
        try:
            directory = os.path.dirname(path)
            for pid, ops in file_operations.items():
                if pid != 0 and ops:  # Skip unknown PID bucket
                    # Look at recent operations from this process
                    recent_time = time.time() - 5  # Last 5 seconds
                    recent_ops = [op for op in ops if op['time'] > recent_time]
                    
                    # Check if process accessed files in the same directory recently
                    for op in recent_ops:
                        if 'path' in op and os.path.dirname(op['path']) == directory:
                            # Process has recently accessed same directory, good candidate
                            try:
                                proc = psutil.Process(pid)  # Verify process still exists
                                self.pid_cache[path] = pid
                                logging.debug(f"Found PID {pid} ({proc.name()}) for path {path} via directory heuristic")
                                return pid
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                break  # Process doesn't exist anymore
        except Exception as e:
            logging.debug(f"Error during directory heuristic for {path}: {e}")
            
        logging.debug(f"Could not determine PID for path: {path} after exhaustive search")
        return None  # No reliable PID found

    def _record_event(self, event_type, path, is_directory=False, dest_path=None):
        """Records the detected file operation."""
        pid = self._get_pid_for_path(path) # Attempt to get PID (unreliable)
        process_name = "Unknown"

        # Store the operation data regardless of whether we found a PID
        operation = {
            'time': time.time(),
            'type': event_type,
            'path': path,
            'is_directory': is_directory,
        }
        if dest_path:
            operation['dest_path'] = dest_path

        # If PID is found, record in process-specific history
        if pid:
            try:
                process_name = get_process_name(pid) # Get process name if PID found
            except psutil.NoSuchProcess:
                logging.debug(f"Process {pid} ended before name could be retrieved for path {path}")
                process_name = f"PID_{pid}_Ended"
            except (psutil.AccessDenied, OSError) as e:
                 logging.debug(f"Could not get process name for PID {pid}: {e}")
                 process_name = f"PID_{pid}_AccessError"

            operation['process_name'] = process_name # Added process name
            operation['pid'] = pid # Added PID explicitly

            # Calculate entropy for file modifications
            # Note: Entropy calculation is based on a sample and may not always indicate encryption.
            # Ransomware detectors should look for patterns (e.g., many high-entropy modifications).
            if event_type == 'modify' and not is_directory:
                entropy = None
                try:
                    if os.path.exists(path) and os.path.getsize(path) > 0:
                        with open(path, 'rb') as f:
                            data = f.read(8192)  # Read 8KB sample
                        if data:
                            entropy = calculate_entropy(data)
                            operation['entropy'] = entropy
                            logging.debug(f"Calculated entropy {entropy:.4f} for modified file: {path}")
                    elif os.path.exists(path):
                        logging.debug(f"File exists but is empty, skipping entropy calc: {path}")
                    else:
                        logging.debug(f"File not found for entropy calc (likely deleted): {path}")
                except FileNotFoundError:
                    logging.warning(f"File not found for entropy calc (race condition?): {path}")
                except PermissionError:
                    logging.warning(f"Permission denied for entropy calc: {path}")
                except OSError as e:
                    logging.warning(f"OS error during entropy calc for {path}: {e}")
                except Exception as e:
                    logging.error(f"Unexpected error during entropy calc for {path}: {e}", exc_info=True)

                if entropy is not None:
                    operation['entropy'] = entropy

            file_operations[pid].append(operation)
            logging.info(f"Event Recorded: PID={pid} ({process_name}), Type={event_type}, Path={path}" + (f", Entropy={entropy:.4f}" if 'entropy' in operation else "")) # Enhanced log
        else:
            # For PID UNKNOWN, store in special bucket (PID 0) for analysis
            logging.warning(f"Event Recorded (PID UNKNOWN): Type={event_type}, Path={path}")
            
            # Special case: handle entropy calculation for unknown PID modify events
            if event_type == 'modify' and not is_directory:
                entropy = None
                try:
                    if os.path.exists(path) and os.path.getsize(path) > 0:
                        with open(path, 'rb') as f:
                            data = f.read(8192)  # Read 8KB sample
                        if data:
                            entropy = calculate_entropy(data)
                            operation['entropy'] = entropy
                            logging.warning(f"Unknown PID modified file with entropy {entropy:.4f}: {path}")
                except Exception as e:
                    logging.debug(f"Error calculating entropy for unknown PID: {e}")
            
            # Store in special PID 0 bucket for unknown processes
            # This is critical for detection when PID association fails
            file_operations[0].append(operation)

    def on_created(self, event):
        self._record_event('create', event.src_path, event.is_directory)

    def on_deleted(self, event):
        self._record_event('delete', event.src_path, event.is_directory)
        if event.src_path in self.pid_cache: # Clean cache on delete
             del self.pid_cache[event.src_path]

    def on_modified(self, event):
        # Ignore directory modifications for simplicity unless needed
        if not event.is_directory:
            self._record_event('modify', event.src_path, event.is_directory)

    def on_moved(self, event):
        # A move involves a source and destination path
        self._record_event('move', event.src_path, event.is_directory, dest_path=event.dest_path)
        if event.src_path in self.pid_cache: # Clean cache on move
             del self.pid_cache[event.src_path]


# --- Main Monitoring Function ---
def monitor_file_operations():
    """Monitor file system operations using watchdog."""
    if not WATCHDOG_AVAILABLE:
        logging.error("Watchdog library not available. File monitoring disabled.")
        return # Exit if watchdog is not installed

    logging.info("File operation monitor started (using Watchdog).")
    
    event_handler = RansomwareEventHandler()
    observer = Observer()

    # Determine directories to watch
    dirs_to_watch = set()
    # Watch the entire C: drive
    drive_c = "C:\\"
    if os.path.exists(drive_c):
        dirs_to_watch.add(drive_c)
        logging.warning("Watching the entire C: drive. This can be resource-intensive and generate many events.")
    else:
        logging.error("C: drive not found. Cannot start monitoring.")
    
    # Add other critical dirs if necessary, but be cautious
    # dirs_to_watch.update(p for p in PROTECTED_DIRS if 'Windows' not in p and 'Program Files' not in p) # Example filter
    logging.debug(f"Directories initially selected for watching: {dirs_to_watch}") # Added logging

    if not dirs_to_watch:
        logging.warning("No user directories found to monitor. Specify directories manually if needed.")
        print("Warning: No directories configured for monitoring.") # Added print
        # Fallback or exit? For now, log and continue, observer won't start.
    
    watched_count = 0
    print("Scheduling directories for watching...") # Added print
    for path in dirs_to_watch:
        try:
            # recursive=True monitors subdirectories
            observer.schedule(event_handler, path, recursive=True)
            watched_count += 1
            logging.info(f"Successfully scheduled watching for directory: {path}") # Changed logging level
            print(f"  Scheduled: {path}") # Added print
        except Exception as e:
             logging.error(f"Failed to schedule watching for {path}: {e}")
             print(f"  Failed to schedule {path}: {e}") # Added print

    if watched_count == 0:
         logging.error("Watchdog observer could not be scheduled on any directory. File monitoring inactive.")
         print("Error: Could not schedule any directories. File monitor inactive.") # Added print
         return # Exit if observer couldn't start

    print(f"Starting observer for {watched_count} scheduled directories...") # Added print
    observer.start()
    logging.info(f"Watchdog observer started successfully on {watched_count} directories.") # Changed logging level
    print("--- File Monitor Running ---") # Added print

    try:
        # Keep the thread alive until stop event is set
        while not stop_event.is_set():
            # Check observer health periodically (optional)
            if not observer.is_alive():
                 logging.error("Watchdog observer thread has stopped unexpectedly!")
                 print("Error: Watchdog observer thread stopped unexpectedly!") # Added print
                 break
            # Add a debug log and print to show the loop is active
            logging.debug("File monitor watchdog loop active, observer alive.") # Added logging
            # print(".", end='', flush=True) # Optional: uncomment for visual indication of activity
            time.sleep(1) # Sleep to avoid busy-waiting
        logging.info("Stop event received or observer died. Exiting monitoring loop.") # Added logging
        print("\nStop event received or observer died. Exiting monitoring loop.") # Added print
    except Exception as e:
        logging.error(f"Error in file monitoring watchdog loop: {e}", exc_info=True)
        print(f"\nException in file monitor loop: {e}") # Added print with newline
    finally:
        print("--- Stopping File Monitor ---") # Added print
        if observer.is_alive():
            observer.stop()
            logging.info("Watchdog observer stopping...")
            print("Sent stop signal to Watchdog observer.") # Added print
        print("Waiting for observer thread to join...") # Added print
        observer.join() # Wait for observer thread to finish
        logging.info("File operation monitor stopped (Watchdog).")
        print("File monitor stopped.") # Added print

# Note: The previous psutil polling loop is now replaced.
# The accuracy of PID association is significantly reduced and potentially slow.
# Detectors relying heavily on PID-specific file operation sequences
# (like read-then-write) might become less effective or require adjustments.
# Detectors focusing on counts (mass delete/create/rename) and entropy patterns
# across many files (even with unknown PIDs) benefit more from watchdog's event capture.
