"""
Detectors for suspicious file operations that may indicate ransomware activity.
"""
import os
import re
import logging  # Added logging

from ..utils import is_process_trusted, is_admin_process, get_process_name
from ..constants import RANSOMWARE_TARGET_EXTENSIONS, RANSOMWARE_EXTENSIONS, PROTECTED_DIRS

# Import these from global state once we've refactored
file_operations = {}  # Will be imported from global state

def detect_file_encryption_patterns(pid):
    """Detect patterns suggesting file encryption"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    
    # Track read-then-write patterns on same files
    files_read = set()
    files_written = set()
    
    for op in operations:
        if op['type'] == 'read':
            files_read.add(op['path'])
        elif op['type'] == 'write':
            files_written.add(op['path'])
    
    # Files that were read then written to
    read_write_files = files_read.intersection(files_written)
    
    if len(read_write_files) >= 3:
        score_increase = min(len(read_write_files), 10)  # Cap at 10 points
        score += score_increase
        logging.debug(f"PID {pid}: Detected read-then-write pattern on {len(read_write_files)} files. Score +{score_increase}")
    
    if score > 0:
        logging.info(f"PID {pid}: Detected file encryption patterns. Score contribution: {score}")
    return score

def detect_multiple_extension_changes(pid):
    """Detect multiple file extension changes"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    ext_changes = 0
    ransom_ext_changes = 0
    operations = file_operations.get(pid, [])
    
    for op in operations:
        if op['type'] == 'rename' and 'old_path' in op and 'new_path' in op:
            old_ext = os.path.splitext(op['old_path'])[1].lower()
            new_ext = os.path.splitext(op['new_path'])[1].lower()
            
            if old_ext != new_ext:
                ext_changes += 1
                logging.debug(f"PID {pid}: Detected extension change: '{op['old_path']}' -> '{op['new_path']}'")
                
                if new_ext in RANSOMWARE_EXTENSIONS:
                    ransom_ext_changes += 1
                    logging.debug(f"PID {pid}: New extension '{new_ext}' matches known ransomware extension. Score +5")
                    score += 5  # Higher score for known ransomware extensions
    
    if ext_changes >= 3:
        score_increase = min(ext_changes, 10)  # Cap at 10 points
        score += score_increase
        logging.debug(f"PID {pid}: Detected {ext_changes} total extension changes. Score +{score_increase}")

    if score > 0:
        logging.info(f"PID {pid}: Detected multiple extension changes ({ext_changes} total, {ransom_ext_changes} ransom). Score contribution: {score}")
    return score

def detect_mass_file_operations(pid):
    """Detect unusually high number of file operations"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    
    # Count operations by type
    op_counts = {}
    for op_type in ['read', 'write', 'create', 'delete', 'rename']:
        op_counts[op_type] = 0
        
    extensions_accessed = set()
    directories_accessed = set()
    
    for op in operations:
        op_counts[op['type']] = op_counts.get(op['type'], 0) + 1
        if 'path' in op:
            ext = os.path.splitext(op['path'])[1].lower()
            if ext:
                extensions_accessed.add(ext)
            
            directory = os.path.dirname(op['path'])
            if directory:
                directories_accessed.add(directory)
    
    # Score based on volume and diversity of operations
    write_count = op_counts.get('write', 0)
    if write_count > 20:
        score_increase = min(write_count // 10, 5)
        score += score_increase
        logging.debug(f"PID {pid}: High write count ({write_count}). Score +{score_increase}")
    
    delete_count = op_counts.get('delete', 0)
    if delete_count > 10:
        score_increase = min(delete_count // 5, 5)
        score += score_increase
        logging.debug(f"PID {pid}: High delete count ({delete_count}). Score +{score_increase}")
    
    target_exts_accessed_count = len(extensions_accessed.intersection(RANSOMWARE_TARGET_EXTENSIONS))
    if target_exts_accessed_count >= 3:
        score_increase = min(target_exts_accessed_count, 5)
        score += score_increase
        logging.debug(f"PID {pid}: Accessed {target_exts_accessed_count} targeted extension types. Score +{score_increase}")
    
    dir_count = len(directories_accessed)
    if dir_count > 5:
        score_increase = min(dir_count // 2, 5)
        score += score_increase
        logging.debug(f"PID {pid}: Accessed {dir_count} different directories. Score +{score_increase}")
    
    if score > 0:
        logging.info(f"PID {pid}: Detected mass file operations. Score contribution: {score}")
    return score

def detect_suspicious_file_access(pid):
    """Detect access to sensitive files or unusual access patterns"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    is_admin = is_admin_process(pid)
    protected_access_count = 0
    sensitive_access_count = 0
    
    sensitive_patterns = [
        r'wallet\.dat',
        r'bitcoin',
        r'\.keystore',
        r'password',
        r'\.kdbx',  # KeePass database
        r'\.key$',
        r'certificate',
        r'\.pfx$',
        r'\.p12$',
    ]
    
    for op in operations:
        if 'path' not in op:
            continue
            
        path = op['path'].lower()
        
        accessed_protected = False
        for protected_dir in PROTECTED_DIRS:
            if path.startswith(protected_dir.lower()) and not is_admin:
                protected_access_count += 1
                accessed_protected = True
                logging.debug(f"PID {pid}: Non-admin access detected in protected directory: '{path}'")
                break
        if accessed_protected:
            score += 1
        
        accessed_sensitive = False
        for pattern in sensitive_patterns:
            if re.search(pattern, path):
                sensitive_access_count += 1
                accessed_sensitive = True
                logging.debug(f"PID {pid}: Access detected to potentially sensitive file: '{path}' matching pattern '{pattern}'")
                break
        if accessed_sensitive:
            score += 2
    
    final_score = min(score, 5)
    if final_score > 0:
        logging.info(f"PID {pid}: Detected suspicious file access ({protected_access_count} protected, {sensitive_access_count} sensitive). Score contribution: {final_score}")
    return final_score

def detect_ransomware_extensions(pid):
    """Detect creation of files with known ransomware extensions"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    ransom_ext_found = False
    
    for op in operations:
        if op['type'] in ('write', 'create') and 'path' in op:
            ext = os.path.splitext(op['path'])[1].lower()
            if ext in RANSOMWARE_EXTENSIONS:
                logging.debug(f"PID {pid}: Detected write/create with ransomware extension '{ext}' for file: '{op['path']}'")
                score += 5
                ransom_ext_found = True
                break
    
    if ransom_ext_found:
        logging.info(f"PID {pid}: Detected ransomware file extension activity. Score contribution: {score}")
    return score

def detect_high_entropy_writes(pid):
    """Detect writes with high entropy (likely encrypted)"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    high_entropy_count = 0
    entropy_values = []
    
    for op in operations:
        if op['type'] == 'write' and 'path' in op and 'entropy' in op:
            entropy = op['entropy']
            entropy_values.append(entropy)
            if entropy > 7.5:
                high_entropy_count += 1
                logging.debug(f"PID {pid}: High entropy write detected (Entropy: {entropy:.2f}) for file: '{op['path']}'")
    
    if high_entropy_count >= 3:
        score_increase = min(high_entropy_count, 6)
        score += score_increase
        logging.debug(f"PID {pid}: Detected {high_entropy_count} high entropy writes (Avg: {sum(entropy_values)/len(entropy_values):.2f}). Score +{score_increase}")
    
    if score > 0:
        logging.info(f"PID {pid}: Detected high entropy write activity. Score contribution: {score}")
    return score
