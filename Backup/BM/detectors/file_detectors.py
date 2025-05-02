"""
Detection functions focused on file system activity.
"""

import os
import re
import time
import logging
from collections import defaultdict

from ..constants import (
    file_operations, RANSOMWARE_EXTENSIONS, RANSOMWARE_TARGET_EXTENSIONS, 
    PROTECTED_DIRS
)
from ..utils import get_process_name, is_process_trusted, is_admin_process

def detect_file_encryption_patterns(pid):
    """Detect patterns suggesting file encryption (read-then-write)."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid)
    if not operations:
        return 0

    # Track read-then-write patterns on same files within the observation window
    files_read = set()
    files_written = set()
    read_write_files = set()
    
    # Iterate chronologically if deque maintains order
    for op in operations:
        path = op.get('path')
        if not path: continue

        if op['type'] == 'read':
            files_read.add(path)
        elif op['type'] == 'write':
            files_written.add(path)
            # If a file is written *after* being read in this window, count it
            if path in files_read:
                read_write_files.add(path)
    
    # Score based on the number of files read then written
    num_read_write = len(read_write_files)
    if num_read_write >= 5: # Threshold for suspicion
        score += min(num_read_write // 2, 10) # Scale score, cap at 10
    
    return score


def detect_multiple_extension_changes(pid):
    """Detect multiple file extension changes, especially to known ransomware extensions."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    ext_changes = 0
    ransom_ext_changes = 0
    operations = file_operations.get(pid)
    if not operations:
        return 0

    # Note: psutil's open_files doesn't directly show renames. 
    # This detector relies on hypothetical 'rename' events if implemented via OS hooks.
    # If using only open_files, this detector might be ineffective.
    # Assuming 'rename' events exist in file_operations[pid]
    for op in operations:
        if op.get('type') == 'rename' and 'old_path' in op and 'new_path' in op:
            old_ext = os.path.splitext(op['old_path'])[1].lower()
            new_ext = os.path.splitext(op['new_path'])[1].lower()
            
            # If extension changed 
            if old_ext != new_ext and new_ext: # Ensure new_ext is not empty
                ext_changes += 1
                
                # Higher score for known ransomware extensions
                if new_ext in RANSOMWARE_EXTENSIONS:
                    ransom_ext_changes += 1
    
    # Score based on total changes
    if ext_changes >= 5: # Threshold for general mass renaming
        score += min(ext_changes // 2, 5) 

    # Add significant score for changes to known bad extensions
    if ransom_ext_changes > 0:
         score += min(ransom_ext_changes * 3, 10) # Higher weight for known bad extensions

    return min(score, 10) # Cap total score for this detector


def detect_mass_file_operations(pid):
    """Detect unusually high number of file operations (writes, deletes)."""
    # Special case for PID 0 (unknown operations bucket)
    if pid == 0:
        return detect_unknown_pid_mass_operations()

    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid)
    if not operations:
        return 0
    
    op_counts = defaultdict(int)
    extensions_accessed = set()
    directories_accessed = set()
    
    for op in operations:
        op_type = op.get('type')
        if op_type:
            op_counts[op_type] += 1
        
        path = op.get('path')
        if path:
            try:
                ext = os.path.splitext(path)[1].lower()
                if ext:
                    extensions_accessed.add(ext)
                
                directory = os.path.dirname(path)
                if directory:
                    directories_accessed.add(directory)
            except Exception: # Handle potential path errors
                pass

    # Score based on volume of writes/deletes
    # Adjusted thresholds based on typical ransomware behavior
    if op_counts['write'] > 20: # Lower from 50 to 20
        score += min(op_counts['write'] // 10, 8) # Increase score factor
    
    if op_counts['delete'] > 10: # Lower from 20 to 10
        score += min(op_counts['delete'] // 5, 8) # Increase score factor

    # Score based on accessing many different types of target files
    target_exts_accessed = len(extensions_accessed.intersection(RANSOMWARE_TARGET_EXTENSIONS))
    if target_exts_accessed >= 5: # Accessing 5+ types is suspicious
        score += min(target_exts_accessed, 5)
    
    # Score based on accessing many different directories
    num_dirs = len(directories_accessed)
    if num_dirs > 10: # Accessing 10+ directories is suspicious
        score += min(num_dirs // 5, 5) # Scale score
    
    # Consider total operations count as well
    total_ops = len(operations)
    if total_ops > 200: # Very high total activity
        score += min(total_ops // 100, 3)

    return min(score, 15) # Cap total score for this detector


def detect_suspicious_file_access(pid):
    """Detect access to sensitive files or protected directories without admin rights."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations.get(pid)
    if not operations:
        return 0
        
    is_admin = is_admin_process(pid) # Check admin status once
    
    # Patterns for potentially sensitive files (expand as needed)
    sensitive_patterns = [
        re.compile(r'wallet\.dat$', re.IGNORECASE),
        re.compile(r'bitcoin', re.IGNORECASE),
        re.compile(r'\.keystore$', re.IGNORECASE),
        re.compile(r'password', re.IGNORECASE),
        re.compile(r'\.kdbx$', re.IGNORECASE),  # KeePass database
        re.compile(r'\.(key|pem|crt)$', re.IGNORECASE), # Key/Cert files
        re.compile(r'certificate', re.IGNORECASE),
        re.compile(r'\.(pfx|p12)$', re.IGNORECASE), # Cert bundles
        re.compile(r'secret', re.IGNORECASE),
        re.compile(r'private.*key', re.IGNORECASE),
        # Add patterns for common config files, browser profiles, etc.
        # re.compile(r'AppData\\Local\\Google\\Chrome\\User Data', re.IGNORECASE),
    ]
    
    accessed_sensitive = False
    accessed_protected = False

    for op in operations:
        path = op.get('path')
        if not path:
            continue
            
        path_lower = path.lower() # Lowercase once for comparisons
        
        # Check if accessing protected directories without admin rights (more efficient check)
        if not is_admin:
            for protected_dir in PROTECTED_DIRS:
                 # Ensure comparison is consistent (e.g., both lowercase)
                 # Check if path starts with the protected dir + separator to avoid partial matches
                 if path_lower.startswith(protected_dir.lower() + os.sep):
                    score += 1
                    accessed_protected = True
                    break # Only score once per operation for protected access
        
        # Check for sensitive file patterns only once per process analysis if needed
        if not accessed_sensitive:
            for pattern in sensitive_patterns:
                if pattern.search(path_lower):
                    score += 2 # Higher score for accessing potentially sensitive files
                    accessed_sensitive = True
                    break # Only score once per operation for sensitive access
            
        # Optimization: if both flags are true, can potentially break early 
        # if accessed_protected and accessed_sensitive: break 

    return min(score, 5)  # Cap score for this detector


def detect_ransomware_extensions(pid):
    """Detect creation or writing to files with known ransomware extensions."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    count = 0
    operations = file_operations.get(pid)
    if not operations:
        return 0

    for op in operations:
        # Check for 'write' or potentially 'create' if that event type exists
        if op.get('type') in ('write', 'create') and 'path' in op:
            try:
                ext = os.path.splitext(op['path'])[1].lower()
                if ext in RANSOMWARE_EXTENSIONS:
                    count += 1
            except Exception: # Handle potential path errors
                 pass

    if count > 0:
        # Score significantly if even one known extension is used
        score = 5 + min(count, 5) # Base score + bonus for multiple occurrences, capped

    return min(score, 10) # Cap score


def detect_high_entropy_writes(pid):
    """Detect multiple file writes with high entropy (suggesting encryption)."""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    # Handle special case for unknown PID
    if pid == 0:
        return detect_unknown_pid_mass_operations() // 2  # Use mass detector but with lower weight
    
    score = 0
    high_entropy_count = 0
    operations = file_operations.get(pid)
    if not operations:
        return 0

    for op in operations:
        # Check for write operations that have entropy calculated
        if op.get('type') == 'write' and 'entropy' in op:
            # Entropy > 7.0 is often indicative of compressed/encrypted data
            # Entropy > 7.5 is a stronger indicator
            if op['entropy'] > 7.5: 
                high_entropy_count += 1
            elif op['entropy'] > 7.0: # Give partial credit for slightly lower entropy
                 high_entropy_count += 0.5

    # Score based on the number of high-entropy writes
    if high_entropy_count >= 3: # Lower from 5 to 3
        score += min(int(high_entropy_count * 1.5), 10) # Increase score factor

    return score


def detect_unknown_pid_mass_operations(pid=0):
    """
    Specialized detector for file operations with unknown PIDs.
    This is crucial when file events can't be associated with processes.
    """
    score = 0
    operations = file_operations.get(0)  # Special PID 0 bucket for unknown PIDs
    if not operations:
        return 0
    
    # Focus on recent operations
    recent_time_window = 30  # Analyze events in the last 30 seconds
    current_time = time.time()
    recent_ops = [op for op in operations if current_time - op.get('time', 0) <= recent_time_window]
    
    # Skip if too few operations
    if len(recent_ops) < 3:
        return 0
        
    # Count by operation type
    op_counts = defaultdict(int)
    extensions_modified = set()
    directories_accessed = set()
    sequential_paths = []
    
    for op in recent_ops:
        op_type = op.get('type')
        if op_type:
            op_counts[op_type] += 1
        
        path = op.get('path')
        if path:
            try:
                # Track extensions being accessed
                ext = os.path.splitext(path)[1].lower()
                if ext:
                    extensions_modified.add(ext)
                
                # Track directories being accessed
                directory = os.path.dirname(path)
                if directory:
                    directories_accessed.add(directory)
                    
                # Look for sequential filenames (common in ransomware)
                sequential_paths.append(path)
            except Exception:
                pass
    
    # Check for operations across multiple extensions (ransomware hits many file types)
    unique_exts = len(extensions_modified)
    if unique_exts >= 3:
        score += min(unique_exts, 5)
        logging.warning(f"Unknown PID accessing multiple file types: {unique_exts} extensions")
    
    # Check for operations across multiple directories
    unique_dirs = len(directories_accessed)
    if unique_dirs >= 2:
        score += min(unique_dirs, 3)
        logging.warning(f"Unknown PID accessing multiple directories: {unique_dirs} directories")
    
    # Volume-based scoring (aggressive thresholds for unknown PIDs)
    if len(recent_ops) >= 5:  # Lower threshold - 5 operations is suspicious without a PID
        score += min(len(recent_ops) // 2, 8)
        logging.warning(f"Unknown PID performing many operations: {len(recent_ops)} ops in {recent_time_window}s")
    
    # Check for sequential access patterns
    if len(sequential_paths) >= 5:
        # Look at the directories - consistent directory is more suspicious
        main_dir = os.path.dirname(sequential_paths[0]) if sequential_paths else None
        same_dir_count = sum(1 for p in sequential_paths if os.path.dirname(p) == main_dir)
        
        if same_dir_count >= 4:  # Multiple files in same directory is very suspicious
            score += min(same_dir_count, 10)
            logging.warning(f"Unknown PID sequentially accessing {same_dir_count} files in {main_dir}")
    
    # Check high entropy modifications
    high_entropy_ops = [op for op in recent_ops if op.get('type') == 'modify' and op.get('entropy', 0) > 7.0]
    if high_entropy_ops:
        score += min(len(high_entropy_ops) * 2, 10)  # Higher weight for entropy
        logging.warning(f"Unknown PID performing {len(high_entropy_ops)} high-entropy writes - strong encryption indicator")
    
    return min(score, 20)  # Cap score but allow higher ceiling for unknown PIDs
