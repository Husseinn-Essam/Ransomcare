"""
Detectors for suspicious network activity that may indicate ransomware.
"""
from ..utils import is_process_trusted, get_process_name

# Import these from global state once we've refactored
network_connections = {}  # Will be imported from global state

def detect_network_c2_traffic(pid):
    """Detect potential command & control traffic"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_connections = network_connections.get(pid, [])
    
    # Suspicious connection patterns
    tor_ports = {9050, 9051, 9150, 9151}
    suspicious_ips = set()
    connection_count = 0
    
    for conn in proc_connections:
        connection_count += 1
        
        if 'remote_port' in conn:
            # Check for TOR connections
            if conn['remote_port'] in tor_ports:
                score += 3
            
            # Check for unusual high ports
            if conn['remote_port'] > 50000:
                score += 1
        
        if 'remote_ip' in conn:
            suspicious_ips.add(conn['remote_ip'])
    
    # Many unique connections
    if len(suspicious_ips) > 5:
        score += min(len(suspicious_ips) // 2, 3)
    
    return min(score, 4)  # Cap at 4 points
