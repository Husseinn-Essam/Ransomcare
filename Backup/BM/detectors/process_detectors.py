"""
Detection functions focused on process behavior and system interactions.
"""

import re
import time

from ..constants import process_history, network_connections
from ..utils import get_process_name, is_process_trusted

def detect_shadow_copy_deletion(pid):
    """Detect commands attempting to delete Windows shadow copies."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    history = process_history.get(pid)
    if not history:
        return 0

    # Common commands used by ransomware to delete backups/shadow copies
    # Make patterns case-insensitive and robust
    shadow_copy_patterns = [
        re.compile(r'vssadmin.*delete shadows', re.IGNORECASE),
        re.compile(r'wmic.*shadowcopy delete', re.IGNORECASE),
        re.compile(r'bcdedit.*(recoveryenabled no|bootstatuspolicy ignoreallfailures)', re.IGNORECASE), # Disable recovery
        re.compile(r'wbadmin delete catalog', re.IGNORECASE),
        re.compile(r'delete.*shadow', re.IGNORECASE), # Broader pattern
        re.compile(r'powershell.*(Get-WmiObject.*Win32_ShadowCopy|Get-CimInstance.*Win32_ShadowCopy).*Delete\(\)', re.IGNORECASE), # PS commands
    ]
    
    # Check process execution events (assuming they are logged)
    # This requires a mechanism to capture process creation + command lines
    for event in history:
        # Assuming an event type like 'process_exec' or similar exists
        if event.get('type') == 'process_exec' and 'command_line' in event:
            cmd = event['command_line'].lower() # Lowercase once
            
            for pattern in shadow_copy_patterns:
                if pattern.search(cmd):
                    score += 10  # High score - strong indicator of ransomware intent
                    # No need to check other patterns for this event if one matches
                    break 
            # If score is already high, maybe break outer loop too?
            # if score >= 10: break 

    # Return score (implicitly capped by the logic, max 10 per detected command instance)
    # If multiple commands are detected in the history, the score could exceed 10.
    # Let's cap it explicitly.
    return min(score, 10) 


def detect_network_c2_traffic(pid):
    """Detect network patterns potentially indicating Command & Control communication."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    connections = network_connections.get(pid)
    if not connections:
        return 0
    
    # Known TOR exit node ports / common C2 ports (expand list)
    suspicious_ports = {80, 443, 9001, 9030, 9050, 9051, 9150, 9151} # Include common web ports often used for C2
    high_ports_count = 0
    suspicious_ips = set()
    connection_count = len(connections)
    established_conns = 0

    for conn in connections:
        # Focus on established outbound connections
        if conn.get('status') == 'ESTABLISHED' and 'remote_ip' in conn and 'remote_port' in conn:
            established_conns += 1
            remote_ip = conn['remote_ip']
            remote_port = conn['remote_port']

            # Check for connections to suspicious ports (TOR, known C2)
            if remote_port in suspicious_ports:
                 # Weight based on port? e.g., TOR ports higher?
                 score += 2 
            
            # Check for unusual high ports (often used to evade simple firewalls)
            if remote_port > 49151: # Ephemeral port range start
                high_ports_count += 1

            # Track unique remote IPs connected to
            # Avoid adding local/private IPs if possible
            if not re.match(r"^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)", remote_ip):
                 suspicious_ips.add(remote_ip)

    # Score based on high port usage
    if high_ports_count > 3: # Multiple connections to high ports
        score += min(high_ports_count // 2, 3)

    # Score based on connecting to many unique external IPs (potential C2 network/scan)
    num_suspicious_ips = len(suspicious_ips)
    if num_suspicious_ips > 5:
        score += min(num_suspicious_ips // 2, 4) # Cap score contribution

    # Score based on high number of established connections (could be data exfil/C2)
    if established_conns > 10:
         score += min(established_conns // 5, 3)

    return min(score, 8) # Cap total score for this detector


def detect_ransomware_process_patterns(pid):
    """Detect process behavior patterns like high CPU or suspicious names."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    history = process_history.get(pid)
    if not history:
        return 0
    
    # Check for sustained high CPU usage (encryption is CPU intensive)
    cpu_events = [e for e in history if e.get('type') == 'cpu_usage' and 'value' in e]
    high_cpu_count = 0
    sustained_high_cpu = 0
    if len(cpu_events) > 3: # Need a few samples
        for i in range(len(cpu_events)):
            if cpu_events[i]['value'] > 75: # Threshold for high CPU %
                high_cpu_count += 1
                # Check for consecutive high usage
                if i > 0 and cpu_events[i-1]['value'] > 75:
                     sustained_high_cpu += 1
            else:
                 sustained_high_cpu = 0 # Reset consecutive count

    if high_cpu_count > 5: # More than 5 instances of high CPU
        score += 2
    if sustained_high_cpu >= 3: # 3+ consecutive high CPU readings
         score += 3 # Higher score for sustained activity

    # Check for suspicious keywords in process name (simple but sometimes effective)
    suspicious_name_patterns = [
        'crypt', 'ransom', 'lock', 'encrypt', 'decrypt', # Common keywords
        'wncry', 'petya', 'cerber', # Specific ransomware names
        # Add more known patterns or suspicious generic terms
    ]
    
    proc_name_lower = proc_name.lower() # Lowercase once
    for pattern in suspicious_name_patterns:
        if pattern in proc_name_lower:
            score += 5 # Higher score for matching known suspicious names
            break # Score once for name match
    
    # Check for execution from suspicious locations (e.g., Temp folders, AppData)
    # This requires process path information to be available in history or via get_process_path
    # proc_path = get_process_path(pid) # Might be slow to call here repeatedly
    # if proc_path and proc_path != "unknown":
    #     if any(loc in proc_path for loc in ['\\temp\\', '\\appdata\\', '\\temporary internet files\\']):
    #          score += 2

    return min(score, 8) # Cap total score


def detect_system_modifications(pid):
    """Detect system modifications like registry changes for persistence or service creation."""
    # This detector relies heavily on specific event types being logged, 
    # e.g., 'registry_write', 'service_create'. These require deeper OS integration.
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    history = process_history.get(pid)
    if not history:
        return 0
    
    registry_modifications = 0
    startup_modifications = 0
    service_creations = 0
    
    # Persistence registry key patterns (case-insensitive)
    startup_key_patterns = [
        re.compile(r'\\software\\microsoft\\windows\\currentversion\\run', re.IGNORECASE),
        re.compile(r'\\software\\microsoft\\windows\\currentversion\\runonce', re.IGNORECASE),
        re.compile(r'\\software\\wow6432node\\microsoft\\windows\\currentversion\\run', re.IGNORECASE), # 32-bit on 64-bit
        re.compile(r'\\software\\microsoft\\windows nt\\currentversion\\winlogon\\userinit', re.IGNORECASE),
        re.compile(r'\\software\\microsoft\\windows nt\\currentversion\\windows\\load', re.IGNORECASE),
        # Add other common persistence locations
    ]

    for event in history:
        event_type = event.get('type')
        
        # Check for registry writes (assuming 'registry_write' event type)
        if event_type == 'registry_write':
            registry_modifications += 1
            
            # Check if the write targets a known persistence key
            reg_path = event.get('path') # Assuming path is logged
            if reg_path:
                for pattern in startup_key_patterns:
                    if pattern.search(reg_path):
                        startup_modifications += 1
                        break # Score once per event for startup modification
        
        # Check for service creation (assuming 'service_create' event type)
        elif event_type == 'service_create':
            service_creations += 1
            # Could add checks for suspicious service names/paths if available in event data

    # Score based on volume and type of modifications
    if registry_modifications > 10: # Numerous registry writes
        score += 1
    
    if startup_modifications > 0: # Any modification to startup keys is highly suspicious
        score += 5 * startup_modifications # Score per modification
    
    if service_creations > 0: # Creating services is a common persistence/privesc technique
        score += 4 * service_creations # Score per service created

    # Add checks for other modifications if event data is available
    # e.g., task scheduler changes, firewall rule modifications

    return min(score, 10) # Cap total score


def detect_high_disk_usage(pid):
    """Detect sustained high disk I/O operations."""
    # Note: FEATURE_WEIGHTS['high_disk_usage'] is currently 0, disabling this detector's score contribution.
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    history = process_history.get(pid)
    if not history:
        return 0
    
    # Filter relevant disk I/O events
    disk_events = [e for e in history if e.get('type') == 'disk_io' and 'read_bytes' in e and 'write_bytes' in e and 'time' in e]
    
    if len(disk_events) < 3: # Need at least a few samples for rate calculation
        return 0
    
    # Calculate total read/write and time span
    # Ensure events are sorted by time if deque doesn't guarantee it
    # disk_events.sort(key=lambda x: x['time']) 
    
    first_time = disk_events[0]['time']
    last_time = disk_events[-1]['time']
    time_span = max(1.0, last_time - first_time) # Avoid division by zero, ensure float division

    total_read_bytes = 0
    total_write_bytes = 0
    # Calculate delta bytes between consecutive measurements for rate
    # This assumes io_counters are cumulative as provided by psutil
    if len(disk_events) > 1:
         total_read_bytes = disk_events[-1]['read_bytes'] - disk_events[0]['read_bytes']
         total_write_bytes = disk_events[-1]['write_bytes'] - disk_events[0]['write_bytes']
    
    # Ensure non-negative values (counters might reset or process restart)
    total_read_bytes = max(0, total_read_bytes)
    total_write_bytes = max(0, total_write_bytes)

    read_rate_mbps = (total_read_bytes / time_span) / (1024 * 1024)
    write_rate_mbps = (total_write_bytes / time_span) / (1024 * 1024)
    
    # Score based on write rate (encryption often causes high writes)
    if write_rate_mbps > 15:  # Sustained > 15 MB/s write
        score += 3
    elif write_rate_mbps > 8: # Sustained > 8 MB/s write
        score += 2
    elif write_rate_mbps > 3: # Sustained > 3 MB/s write
        score += 1
    
    # Add score if read rate is also high (read -> encrypt -> write pattern)
    if read_rate_mbps > 10 and write_rate_mbps > 5:
        score += 2
    
    # Check for sustained activity (multiple consecutive high I/O events)
    # This requires comparing deltas between points, not just overall rate
    consecutive_high_io = 0
    high_io_threshold_mb = 1 # 1MB delta between checks considered high
    
    for i in range(1, len(disk_events)):
        prev = disk_events[i-1]
        curr = disk_events[i]
        delta_time = max(0.1, curr['time'] - prev['time']) # Min time delta
        
        delta_read = max(0, curr['read_bytes'] - prev['read_bytes'])
        delta_write = max(0, curr['write_bytes'] - prev['write_bytes'])
        
        read_rate_inst_mbps = (delta_read / delta_time) / (1024*1024)
        write_rate_inst_mbps = (delta_write / delta_time) / (1024*1024)

        # Check if instantaneous rate is high
        if read_rate_inst_mbps > 5 or write_rate_inst_mbps > 5:
             consecutive_high_io += 1
        else:
             consecutive_high_io = 0 # Reset streak

        if consecutive_high_io >= 3: # 3+ consecutive periods of high I/O
             score += 2
             break # Score once for sustained activity

    return min(score, 5) # Cap score for this detector
