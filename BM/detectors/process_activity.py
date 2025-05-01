"""
Detectors for suspicious process activity that may indicate ransomware.
"""
import logging  # Added logging
from ..utils import is_process_trusted, get_process_name

# Import these from global state once we've refactored
process_history = {}  # Will be imported from global state

def detect_ransomware_process_patterns(pid):
    """Detect process behavior indicative of ransomware"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history_events = process_history.get(pid, [])
    
    # Check for high CPU usage spikes (encryption is CPU intensive)
    cpu_spikes = 0
    high_cpu_values = []
    for event in proc_history_events:
        if event['type'] == 'cpu_usage' and event['value'] > 80:
            cpu_spikes += 1
            high_cpu_values.append(event['value'])
    
    if cpu_spikes >= 3:
        logging.debug(f"PID {pid}: Detected {cpu_spikes} high CPU usage spikes (values: {high_cpu_values}). Score +2")
        score += 2
    
    # Check for suspicious process names
    suspicious_names = [
        'crypt', 'ransom', 'wcry', 'wncry', 'lock', 
        'encryptor', 'cryptor', 'decrypt', 'locker'
    ]
    
    for pattern in suspicious_names:
        if pattern in proc_name:
            logging.debug(f"PID {pid}: Process name '{proc_name}' matches suspicious pattern '{pattern}'. Score +3")
            score += 3
            break
    
    if score > 0:
        logging.info(f"PID {pid}: Detected suspicious process patterns. Score contribution: {score}")
    return score

def detect_high_disk_usage(pid):
    """Detect unusually high disk I/O operations"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history_events = process_history.get(pid, [])
    
    # Count disk read/write events
    disk_events = [e for e in proc_history_events if e['type'] == 'disk_io']
    
    if not disk_events:
        logging.debug(f"PID {pid}: No disk I/O events found for high disk usage check.")
        return 0
    
    # Calculate total read/write bytes
    total_read_bytes = sum(e['read_bytes'] for e in disk_events if 'read_bytes' in e)
    total_write_bytes = sum(e['write_bytes'] for e in disk_events if 'write_bytes' in e)
    
    # Calculate rates (bytes per second)
    time_span = max(1, disk_events[-1]['time'] - disk_events[0]['time'])
    read_rate = total_read_bytes / time_span
    write_rate = total_write_bytes / time_span
    
    logging.debug(f"PID {pid}: Disk I/O over {time_span:.2f}s - Read: {total_read_bytes} bytes ({read_rate/1024/1024:.2f} MB/s), Write: {total_write_bytes} bytes ({write_rate/1024/1024:.2f} MB/s)")
    
    # Score based on read/write rates
    if write_rate > 10 * 1024 * 1024:  # More than 10 MB/s
        score += 3
        logging.debug(f"PID {pid}: High write rate detected ({write_rate/1024/1024:.2f} MB/s). Score +3")
    elif write_rate > 5 * 1024 * 1024:  # More than 5 MB/s
        score += 2
        logging.debug(f"PID {pid}: Moderate-high write rate detected ({write_rate/1024/1024:.2f} MB/s). Score +2")
    elif write_rate > 1 * 1024 * 1024:  # More than 1 MB/s
        score += 1
        logging.debug(f"PID {pid}: Moderate write rate detected ({write_rate/1024/1024:.2f} MB/s). Score +1")
    
    # High read rate combined with high write could indicate file encryption
    if read_rate > 10 * 1024 * 1024 and write_rate > 5 * 1024 * 1024:
        score += 2
        logging.debug(f"PID {pid}: High read and write rates detected. Score +2")
    
    # Check for sustained disk activity
    if len(disk_events) >= 5:
        consecutive_high_io = 0
        for i in range(1, len(disk_events)):
            prev = disk_events[i-1]
            curr = disk_events[i]
            
            # If both events show significant I/O
            if ('read_bytes' in prev and prev['read_bytes'] > 1024*1024) or \
               ('write_bytes' in prev and prev['write_bytes'] > 1024*1024):
                if ('read_bytes' in curr and curr['read_bytes'] > 1024*1024) or \
                   ('write_bytes' in curr and curr['write_bytes'] > 1024*1024):
                    consecutive_high_io += 1
        
        if consecutive_high_io >= 3:
            logging.debug(f"PID {pid}: Detected {consecutive_high_io} consecutive high I/O events. Score +2")
            score += 2
    
    final_score = min(score, 5)  # Cap at 5 points
    if final_score > 0:
        logging.info(f"PID {pid}: Detected high disk usage activity. Score contribution: {final_score}")
    return final_score
