"""
File system monitoring functionality using watchdog.
"""
import os
import time
import psutil
import logging
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ..utils import calculate_entropy, is_process_trusted, get_process_name
from ..constants import PROTECTED_DIRS

# These will be imported from global state
file_operations = {}  # Will be replaced with global reference
stop_event = None    # Will be replaced with global event

class RansomwareFileHandler(FileSystemEventHandler):
    """Handler for file system events that might indicate ransomware activity."""
    
    def __init__(self):
        self.last_modified_map = {}
        self.event_counts = {"created": 0, "deleted": 0, "modified": 0, "moved": 0}
        
    def get_process_for_file(self, path):
        """Attempt to identify the process modifying a file."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    if is_process_trusted(proc.name()):
                        continue
                        
                    for f in proc.open_files():
                        if f.path == path:
                            return proc.pid
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception as e:
            logging.debug(f"Error identifying process for file {path}: {e}")
        return None
    
    def on_created(self, event):
        """Called when a file is created."""
        if event.is_directory:
            return
            
        path = event.src_path
        self.event_counts["created"] += 1
        
        pid = self.get_process_for_file(path)
        proc_name = get_process_name(pid) if pid else "Unknown"
        
        logging.debug(f"File created: {path} by process {proc_name} (PID: {pid})")
        
        if pid:
            operation = {
                'time': time.time(),
                'type': 'create',
                'path': path
            }
            
            # Calculate entropy for newly created files
            try:
                if os.path.exists(path) and os.path.getsize(path) > 0:
                    with open(path, 'rb') as f:
                        data = f.read(8192)
                        entropy = calculate_entropy(data)
                        operation['entropy'] = entropy
                        
                        if entropy > 7.0:
                            logging.info(f"High entropy file created: {path} (entropy: {entropy:.2f}) by {proc_name}")
                            print(f"[!] High entropy file detected: {os.path.basename(path)} by {proc_name}")
            except:
                pass
                
            if pid not in file_operations:
                file_operations[pid] = deque(maxlen=1000)
            file_operations[pid].append(operation)
    
    def on_deleted(self, event):
        """Called when a file is deleted."""
        if event.is_directory:
            return
            
        path = event.src_path
        self.event_counts["deleted"] += 1
        
        pid = self.get_process_for_file(path)
        proc_name = get_process_name(pid) if pid else "Unknown"
        
        logging.debug(f"File deleted: {path} by process {proc_name} (PID: {pid})")
        
        if pid:
            operation = {
                'time': time.time(),
                'type': 'delete',
                'path': path
            }
            
            if pid not in file_operations:
                file_operations[pid] = deque(maxlen=1000)
            file_operations[pid].append(operation)
    
    def on_modified(self, event):
        """Called when a file is modified."""
        if event.is_directory:
            return
        
        path = event.src_path
        
        # Avoid duplicate events in short time windows
        last_modified = self.last_modified_map.get(path, 0)
        current_time = time.time()
        if current_time - last_modified < 0.1:  # 100ms window
            return
            
        self.last_modified_map[path] = current_time
        self.event_counts["modified"] += 1
        
        pid = self.get_process_for_file(path)
        proc_name = get_process_name(pid) if pid else "Unknown"
        
        logging.debug(f"File modified: {path} by process {proc_name} (PID: {pid})")
        
        if pid:
            operation = {
                'time': current_time,
                'type': 'write',
                'path': path
            }
            
            # Calculate entropy for modified files
            try:
                if os.path.exists(path) and os.path.getsize(path) > 0:
                    with open(path, 'rb') as f:
                        data = f.read(8192)
                        entropy = calculate_entropy(data)
                        operation['entropy'] = entropy
                        
                        if entropy > 7.0:
                            logging.info(f"High entropy file modification: {path} (entropy: {entropy:.2f}) by {proc_name}")
                            print(f"[!] High entropy modification: {os.path.basename(path)} by {proc_name}")
            except:
                pass
                
            if pid not in file_operations:
                file_operations[pid] = deque(maxlen=1000)
            file_operations[pid].append(operation)
    
    def on_moved(self, event):
        """Called when a file is moved or renamed."""
        if event.is_directory:
            return
            
        src_path = event.src_path
        dest_path = event.dest_path
        self.event_counts["moved"] += 1
        
        pid = self.get_process_for_file(dest_path)
        proc_name = get_process_name(pid) if pid else "Unknown"
        
        logging.debug(f"File moved: {src_path} -> {dest_path} by process {proc_name} (PID: {pid})")
        
        if pid:
            operation = {
                'time': time.time(),
                'type': 'rename',
                'old_path': src_path,
                'new_path': dest_path
            }
            
            if pid not in file_operations:
                file_operations[pid] = deque(maxlen=1000)
            file_operations[pid].append(operation)

def monitor_file_operations():
    """Monitor file system operations using watchdog"""
    logging.info("File system monitoring started")
    print("[+] File system monitoring thread started")
    
    start_time = time.time()
    last_stats_time = start_time
    
    try:
        event_handler = RansomwareFileHandler()
        observer = Observer()
        
        # Monitor protected directories
        monitored_dirs = 0
        for directory in PROTECTED_DIRS:
            try:
                observer.schedule(event_handler, directory, recursive=True)
                monitored_dirs += 1
                logging.info(f"Monitoring directory: {directory}")
                print(f"[+] Monitoring directory: {directory}")
            except Exception as e:
                logging.error(f"Error scheduling watchdog for {directory}: {e}")
                print(f"[!] Error monitoring directory {directory}: {e}")
        
        # Start the observer
        observer.start()
        logging.info(f"File system monitoring started on {monitored_dirs} directories")
        print(f"[+] File system monitoring active on {monitored_dirs} directories")
        
        try:
            while not stop_event.is_set():
                current_time = time.time()
                
                # Print periodic stats (every 30 seconds)
                if current_time - last_stats_time > 30:
                    elapsed = current_time - start_time
                    created = event_handler.event_counts["created"]
                    modified = event_handler.event_counts["modified"]
                    deleted = event_handler.event_counts["deleted"]
                    moved = event_handler.event_counts["moved"]
                    
                    stats_msg = (f"File monitor stats: Uptime={elapsed:.1f}s, "
                                f"Created={created}, Modified={modified}, "
                                f"Deleted={deleted}, Moved={moved}")
                    
                    logging.info(stats_msg)
                    print(f"[*] {stats_msg}")
                    last_stats_time = current_time
                
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()
            observer.join()
            logging.info("File system observer stopped")
            print("[+] File system monitoring stopped")
            
    except Exception as e:
        logging.error(f"File monitoring error: {e}")
        print(f"[!] File monitoring error: {e}")
