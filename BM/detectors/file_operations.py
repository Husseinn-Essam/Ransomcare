"""
Detectors for suspicious file operations that may indicate ransomware activity.
"""
import os
import re

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
        score += min(len(read_write_files), 10)  # Cap at 10 points
    
    return score

def detect_multiple_extension_changes(pid):
    """Detect multiple file extension changes"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    ext_changes = 0
    operations = file_operations.get(pid, [])
    
    for op in operations:
        if op['type'] == 'rename' and 'old_path' in op and 'new_path' in op:
            old_ext = os.path.splitext(op['old_path'])[1].lower()
            new_ext = os.path.splitext(op['new_path'])[1].lower()
            
            # If extension changed and new extension is suspicious
            if old_ext != new_ext:
                ext_changes += 1
                
                if new_ext in RANSOMWARE_EXTENSIONS:
                    score += 5  # Higher score for known ransomware extensions
    
    if ext_changes >= 3:
        score += min(ext_changes, 10)  # Cap at 10 points
    
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
    if op_counts.get('write', 0) > 20:
        score += min(op_counts.get('write', 0) // 10, 5)
    
    if op_counts.get('delete', 0) > 10:
        score += min(op_counts.get('delete', 0) // 5, 5)
    
    # Score based on accessing many different types of files
    target_exts_accessed = len(extensions_accessed.intersection(RANSOMWARE_TARGET_EXTENSIONS))
    if target_exts_accessed >= 3:
        score += min(target_exts_accessed, 5)
    
    # Score based on accessing many different directories
    if len(directories_accessed) > 5:
        score += min(len(directories_accessed) // 2, 5)
    
    return score

def detect_suspicious_file_access(pid):
    """Detect access to sensitive files or unusual access patterns"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    is_admin = is_admin_process(pid)
    
    # Patterns to look for in accessed files
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
    
    # Check for access to sensitive files
    for op in operations:
        if 'path' not in op:
            continue
            
        path = op['path'].lower()
        
        # Check if accessing protected directories without admin rights
        for protected_dir in PROTECTED_DIRS:
            if path.startswith(protected_dir.lower()) and not is_admin:
                score += 1
                break
        
        # Check for sensitive file patterns
        for pattern in sensitive_patterns:
            if re.search(pattern, path):
                score += 2
                break
    
    return min(score, 5)  # Cap at 5 points

def detect_ransomware_extensions(pid):
    """Detect creation of files with known ransomware extensions"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    
    for op in operations:
        if op['type'] in ('write', 'create') and 'path' in op:
            ext = os.path.splitext(op['path'])[1].lower()
            if ext in RANSOMWARE_EXTENSIONS:
                score += 5
                break
    
    return score

def detect_high_entropy_writes(pid):
    """Detect writes with high entropy (likely encrypted)"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid, [])
    high_entropy_count = 0
    
    for op in operations:
        if op['type'] == 'write' and 'path' in op and 'entropy' in op:
            # Entropy over 7.5 is typical for encrypted/compressed data
            if op['entropy'] > 7.5:
                high_entropy_count += 1
    
    if high_entropy_count >= 3:
        score += min(high_entropy_count, 6)
    
    return score
