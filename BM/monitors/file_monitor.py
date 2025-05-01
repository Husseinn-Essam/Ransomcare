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
        pid = self.get_process_for_file(path)
        
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
                        operation['entropy'] = calculate_entropy(data)
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
        pid = self.get_process_for_file(path)
        
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
        pid = self.get_process_for_file(path)
        
        # Avoid duplicate events in short time windows
        last_modified = self.last_modified_map.get(path, 0)
        current_time = time.time()
        if current_time - last_modified < 0.1:  # 100ms window
            return
            
        self.last_modified_map[path] = current_time
        
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
                        operation['entropy'] = calculate_entropy(data)
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
        pid = self.get_process_for_file(dest_path)
        
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
    try:
        event_handler = RansomwareFileHandler()
        observer = Observer()
        
        # Monitor protected directories
        for directory in PROTECTED_DIRS:
            try:
                observer.schedule(event_handler, directory, recursive=True)
                logging.info(f"Monitoring directory: {directory}")
            except Exception as e:
                logging.error(f"Error scheduling watchdog for {directory}: {e}")
        
        # Start the observer
        observer.start()
        logging.info("File system monitoring started using watchdog")
        
        try:
            while not stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            observer.stop()
            observer.join()
            
    except Exception as e:
        logging.error(f"File monitoring error: {e}")
