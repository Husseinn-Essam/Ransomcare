"""
Process monitoring functionality.
"""
import time
import psutil
import logging
from collections import deque

from ..utils import is_process_trusted, get_process_connections
from ..constants import EVENT_EXPIRY_TIME, MAX_HISTORY_ENTRIES

# These will be imported from global state
process_history = {}        # Will be replaced with global reference
file_operations = {}        # Will be replaced with global reference
network_connections = {}    # Will be replaced with global reference
flagged_processes = set()   # Will be replaced with global reference
stop_event = None           # Will be replaced with global event
scan_lock = None            # Will be replaced with global lock
analyze_process = None      # Will be replaced with global function

def monitor_processes():
    """Monitor process activity"""
    logging.info("Process monitoring started")
    print("[+] Process monitoring thread started")
    
    process_count = 0
    start_time = time.time()
    last_stats_time = start_time
    
    try:
        while not stop_event.is_set():
            current_time = time.time()
            processes_checked = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    pid = proc.info['pid']
                    proc_name = proc.info['name']
                    
                    # Skip system processes
                    if pid <= 4:
                        # logging.debug(f"Skipping system process PID {pid}") # Can be noisy
                        continue
                    
                    # Skip trusted processes for efficiency
                    if is_process_trusted(proc_name):
                        # logging.debug(f"Skipping trusted process: {proc_name} (PID: {pid})") # Can be noisy
                        continue
                    
                    # Skip already flagged processes
                    if pid in flagged_processes:
                        # logging.debug(f"Skipping already flagged process PID {pid}") # Can be noisy
                        continue
                    
                    # Initialize process history if needed
                    if pid not in process_history:
                        logging.debug(f"Initializing history for new process: {proc_name} (PID: {pid})")
                        process_history[pid] = deque(maxlen=MAX_HISTORY_ENTRIES)
                    
                    # Record CPU usage
                    cpu_usage = proc.info['cpu_percent']
                    process_history[pid].append({
                        'time': time.time(),
                        'type': 'cpu_usage',
                        'value': cpu_usage
                    })
                    
                    # Record disk I/O usage
                    try:
                        io_counters = psutil.Process(pid).io_counters()
                        process_history[pid].append({
                            'time': time.time(),
                            'type': 'disk_io',
                            'read_bytes': io_counters.read_bytes,
                            'write_bytes': io_counters.write_bytes,
                            'read_count': io_counters.read_count,
                            'write_count': io_counters.write_count
                        })
                    except (psutil.AccessDenied, AttributeError):
                        pass
                    
                    # Record network connections
                    try:
                        connections = get_process_connections(pid)
                        
                        if pid not in network_connections:
                            network_connections[pid] = deque(maxlen=MAX_HISTORY_ENTRIES)
                            
                        for conn in connections:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                network_connections[pid].append({
                                    'time': time.time(),
                                    'remote_ip': conn.raddr.ip,
                                    'remote_port': conn.raddr.port,
                                    'local_port': conn.laddr.port if conn.laddr else None
                                })
                    except:
                        pass
                    
                    # Analyze the process for ransomware behavior
                    # logging.debug(f"Analyzing process: {proc_name} (PID: {pid})") # Can be noisy
                    with scan_lock:
                        analyze_process(pid)
                    
                    processes_checked += 1
                    process_count += 1
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # logging.debug(f"Process {pid} terminated or access denied during monitoring loop.")
                    pass
                except Exception as e:
                    logging.debug(f"Error monitoring process {pid}: {e}")
            
            # Clean up expired entries
            cleanup_expired_entries()
            
            # Print periodic stats
            if current_time - last_stats_time > 30:  # Every 30 seconds
                report_monitoring_stats(current_time - start_time, process_count)
                last_stats_time = current_time
                
            time.sleep(1)  # PROCESS_CHECK_INTERVAL
    
    except Exception as e:
        logging.error(f"Process monitoring error: {e}")
        print(f"[!] Process monitoring error: {e}")
    
    logging.info("Process monitoring stopped")
    print("[+] Process monitoring thread stopped")

def report_monitoring_stats(elapsed_time, process_count):
    """Report monitoring statistics to log and console"""
    active_processes = len(process_history)
    flagged_count = len(flagged_processes)
    
    stats_msg = (f"Process monitor stats: Uptime={elapsed_time:.1f}s, "
                f"Processes monitored={active_processes}, "
                f"Total checks={process_count}, "
                f"Flagged processes={flagged_count}")
    
    logging.info(stats_msg)
    print(f"[*] {stats_msg}")

def cleanup_expired_entries():
    """Clean up expired entries from tracking dictionaries"""
    current_time = time.time()
    cleaned_pids = []
    
    # Clean up processes that no longer exist
    for pid in list(process_history.keys()):
        try:
            psutil.Process(pid)
        except psutil.NoSuchProcess:
            cleaned_pids.append(pid)
            del process_history[pid]
            if pid in file_operations:
                del file_operations[pid]
            if pid in network_connections:
                del network_connections[pid]
            if pid in flagged_processes:
                flagged_processes.remove(pid)
                
    if cleaned_pids:
        logging.debug(f"Cleaned up data for terminated PIDs: {cleaned_pids}")

    # Clean up expired events
    for pid in process_history:
        process_history[pid] = deque(
            [e for e in process_history[pid] if current_time - e['time'] < EVENT_EXPIRY_TIME],
            maxlen=MAX_HISTORY_ENTRIES
        )
    
    for pid in file_operations:
        file_operations[pid] = deque(
            [e for e in file_operations[pid] if current_time - e['time'] < EVENT_EXPIRY_TIME],
            maxlen=MAX_HISTORY_ENTRIES
        )
    
    for pid in network_connections:
        network_connections[pid] = deque(
            [e for e in network_connections[pid] if current_time - e['time'] < EVENT_EXPIRY_TIME],
            maxlen=MAX_HISTORY_ENTRIES
        )
