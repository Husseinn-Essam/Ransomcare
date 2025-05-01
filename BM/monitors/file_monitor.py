"""
File system monitoring functionality.
"""
import os
import time
import psutil
import logging

from ..utils import calculate_entropy, is_process_trusted

# These will be imported from global state
file_operations = {}  # Will be replaced with global reference
stop_event = None    # Will be replaced with global event

def monitor_file_operations():
    """Monitor file system operations"""
    try:
        # Initialize file monitoring
        if is_process_trusted.__globals__['WINDOWS_MODULES_AVAILABLE']:
            # On Windows, we would use the win32file API to monitor file operations
            # This would be implemented with ReadDirectoryChangesW
            pass
        else:
            # On other platforms, we'd use a different approach
            pass
        
        while not stop_event.is_set():
            # Process all active processes
            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    pid = proc.info['pid']
                    
                    # Skip system processes and already terminated processes
                    if pid <= 4:
                        continue
                    
                    # Skip trusted processes to reduce overhead
                    if is_process_trusted(proc.info['name']):
                        continue
                    
                    # Record file operations
                    try:
                        for file in proc.open_files():
                            file_path = file.path
                            
                            # Create a file operation record
                            operation = {
                                'time': time.time(),
                                'type': 'access',  # Default type
                                'path': file_path
                            }
                            
                            # Try to determine operation type
                            if hasattr(file, 'mode'):
                                if 'w' in file.mode:
                                    operation['type'] = 'write'
                                    
                                    # Calculate entropy for write operations
                                    try:
                                        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                                            with open(file_path, 'rb') as f:
                                                data = f.read(8192)
                                                operation['entropy'] = calculate_entropy(data)
                                    except:
                                        pass
                                    
                                elif 'r' in file.mode:
                                    operation['type'] = 'read'
                            
                            if pid not in file_operations:
                                file_operations[pid] = []
                            file_operations[pid].append(operation)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                except:
                    pass
            
            # Sleep to reduce CPU usage
            time.sleep(0.5)  # FILE_WATCH_INTERVAL
            
    except Exception as e:
        logging.error(f"File monitoring error: {e}")
