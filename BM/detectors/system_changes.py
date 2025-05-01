"""
Detectors for suspicious system changes that may indicate ransomware.
"""
import re
from ..utils import is_process_trusted, get_process_name

# Import these from global state once we've refactored
process_history = {}  # Will be imported from global state

def detect_shadow_copy_deletion(pid):
    """Detect attempts to delete Windows shadow copies"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history_events = process_history.get(pid, [])
    
    shadow_copy_patterns = [
        r'vssadmin.*delete shadows',
        r'wmic.*shadowcopy delete',
        r'bcdedit.*set default',
        r'wbadmin delete catalog',
        r'delete.*shadow',
    ]
    
    for event in proc_history_events:
        if event['type'] == 'process_exec' and 'command_line' in event:
            cmd = event['command_line'].lower()
            
            for pattern in shadow_copy_patterns:
                if re.search(pattern, cmd):
                    score += 10  # This is a strong indicator
                    break
    
    return score

def detect_system_modifications(pid):
    """Detect system modifications typical of ransomware"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history_events = process_history.get(pid, [])
    
    # Check for registry modifications
    registry_modifications = 0
    startup_modifications = 0
    service_creations = 0
    
    for event in proc_history_events:
        if event['type'] == 'registry_write':
            registry_modifications += 1
            
            # Check registry path
            if 'path' in event:
                path = event['path'].lower()
                if 'run' in path or 'runonce' in path or 'startup' in path:
                    startup_modifications += 1
        
        elif event['type'] == 'service_create':
            service_creations += 1
    
    if registry_modifications > 5:
        score += 1
    
    if startup_modifications > 0:
        score += 2
    
    if service_creations > 0:
        score += 3
    
    return min(score, 6)  # Cap at 6 points
