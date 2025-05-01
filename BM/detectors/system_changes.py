"""
Detectors for suspicious system changes that may indicate ransomware.
"""
import re
import logging  # Added logging
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
                    logging.debug(f"PID {pid}: Detected shadow copy deletion attempt via command: '{cmd}' matching pattern '{pattern}'")
                    score += 10  # This is a strong indicator
                    break
    
    if score > 0:
        logging.info(f"PID {pid}: Detected potential shadow copy deletion activity. Score contribution: {score}")
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
            logging.debug(f"PID {pid}: Detected registry write: {event.get('path', 'N/A')}")
            
            # Check registry path
            if 'path' in event:
                path = event['path'].lower()
                startup_keys = [
                    r'software\\microsoft\\windows\\currentversion\\run',
                    r'software\\microsoft\\windows\\currentversion\\runonce',
                ]
                for key in startup_keys:
                    if key in path:
                        startup_modifications += 1
                        logging.debug(f"PID {pid}: Detected potential startup modification: {path}")
                        break
        
        elif event['type'] == 'service_create':
            service_creations += 1
            logging.debug(f"PID {pid}: Detected service creation: {event.get('service_name', 'N/A')}")
    
    current_score = 0
    if registry_modifications > 5:
        current_score += 1
        logging.debug(f"PID {pid}: High registry modification count ({registry_modifications}). Score +1")
    
    if startup_modifications > 0:
        current_score += 2
        logging.debug(f"PID {pid}: Startup registry modification detected ({startup_modifications}). Score +2")
    
    if service_creations > 0:
        current_score += 3
        logging.debug(f"PID {pid}: Service creation detected ({service_creations}). Score +3")
    
    final_score = min(current_score, 6)  # Cap at 6 points
    if final_score > 0:
        logging.info(f"PID {pid}: Detected potential system modifications. Score contribution: {final_score}")
    return final_score
