import psutil
import os
import logging
import time
import math
import re
import hashlib
from datetime import datetime
from collections import defaultdict, deque
import socket
import threading

# Try to import Windows-specific modules safely
try:
    import winreg
    import win32process
    import win32con
    import win32security
    import win32api
    import win32file
    WINDOWS_MODULES_AVAILABLE = True
except ImportError:
    WINDOWS_MODULES_AVAILABLE = False
    logging.warning("Windows-specific modules not available - some checks will be limited")

# Configure logging with rotation
logging.basicConfig(
    filename='ransomware_detector.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Add console handler for immediate feedback
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# ===== Configuration =====

# Trusted processes that should never be flagged (add your common applications)
TRUSTED_PROCESSES = {
    "vscode.exe", "code.exe", "explorer.exe", "chrome.exe", "firefox.exe", 
    "outlook.exe", "notepad.exe", "msedge.exe", "brave.exe", "slack.exe",
    "powershell.exe", "cmd.exe", "python.exe", "svchost.exe", "spoolsv.exe",
    "devenv.exe", "winword.exe", "excel.exe", "powerpnt.exe", "teams.exe",
    "spotify.exe", "discord.exe", "msiexec.exe", "winzip.exe", "7z.exe",
    "pycharm64.exe", "intellij.exe", "idea64.exe", "node.exe", "npm.exe","windowsterminal.exe",
}

# File extensions commonly targeted by ransomware
RANSOMWARE_TARGET_EXTENSIONS = {
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.jpg', '.jpeg', 
    '.png', '.txt', '.rtf', '.csv', '.mdb', '.accdb', '.psd', '.ai', '.svg',
    '.mp3', '.mp4', '.mov', '.avi', '.zip', '.rar', '.7z', '.bak', '.sql',
    '.db', '.dbf', '.mdf', '.dwg', '.odt', '.ods', '.odp',
}

# Ransomware-specific file extensions
RANSOMWARE_EXTENSIONS = {
    '.locked', '.encrypted', '.crypted', '.crypt', '.enc', '.locky', '.zepto', 
    '.cerber', '.cerber3', '.cryptowall', '.aaa', '.ecc', '.ezz', '.exx', 
    '.zzz', '.xyz', '.abc', '.pzdc', '.2020', '.ctbl', '.djvu', '.wcry',
    '.wncry', '.wncryt', '.onion', '.cryp1', '.lock', '.wncry', '.wannacry',
    '.jaff', '.thor', '.rokku', '.globe', '.btc', '.killdisk', '.petya'
}

# Protected system directories
PROTECTED_DIRS = set()

# Adjusted feature weights based on effectiveness
FEATURE_WEIGHTS = {
    'file_encryption_patterns': 10,    # High weight for clear encryption patterns
    'multiple_extension_changes': 8,   # High for typical ransomware behavior
    'mass_file_operations': 7,         # File operations in bulk
    'suspicious_file_access': 5,       # Access to sensitive files
    'ransomware_extensions': 10,       # Known ransomware extensions
    'high_entropy_writes': 6,          # Encrypted content has high entropy
    'shadow_copy_deletion': 10,        # Direct indicator of ransomware
    'network_c2_traffic': 4,           # Potential command & control
    'ransomware_process_patterns': 5,  # Process behavior patterns
    'system_modifications': 6,         # Registry or service changes
    'high_disk_usage': 7,              # High disk I/O operations
}

# Configuration of thresholds
INITIAL_THRESHOLD = 15                # Minimum score to trigger an alert
HIGH_CONFIDENCE_THRESHOLD = 25        # Score that strongly indicates ransomware
MAX_HISTORY_ENTRIES = 1000            # Maximum events to track in history
FILE_WATCH_INTERVAL = 0.5             # Seconds between file system checks
PROCESS_CHECK_INTERVAL = 1            # Seconds between process checks
EVENT_EXPIRY_TIME = 60                # Seconds before events expire from memory

# ===== Global state =====
process_history = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
file_operations = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
network_connections = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
flagged_processes = set()             # PIDs of processes already flagged
scan_lock = threading.Lock()          # Lock for thread safety
stop_event = threading.Event()        # Event to signal threads to stop

# Initialize protected directories based on the OS
def initialize_protected_dirs():
    global PROTECTED_DIRS
    system_drive = os.environ.get('SystemDrive', 'C:')
    
    base_dirs = [
        os.path.join(system_drive, os.sep),
        os.environ.get('USERPROFILE', os.path.join(system_drive, 'Users')),
        os.environ.get('WINDIR', os.path.join(system_drive, 'Windows')),
        os.path.join(system_drive, 'Program Files'),
        os.path.join(system_drive, 'Program Files (x86)'),
        os.path.join(system_drive, 'ProgramData'),
    ]
    
    # Add user directories that are common targets
    user_dir = os.environ.get('USERPROFILE')
    if user_dir:
        for folder in ['Documents', 'Pictures', 'Desktop', 'Downloads', 'Videos', 'Music']:
            base_dirs.append(os.path.join(user_dir, folder))
    
    PROTECTED_DIRS = set(dir for dir in base_dirs if os.path.exists(dir))

# ===== Helper functions =====

def get_process_name(pid):
    """Get process name safely"""
    try:
        proc = psutil.Process(pid)
        return proc.name().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"

def get_process_path(pid):
    """Get full process path safely"""
    try:
        proc = psutil.Process(pid)
        return proc.exe().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"

def calculate_entropy(data, sample_size=8192):
    """Calculate Shannon entropy of data (measure of randomness)"""
    if not data:
        return 0
    
    # Take a sample to improve performance for large files
    if len(data) > sample_size:
        # Take samples from beginning, middle and end
        samples = []
        samples.append(data[:sample_size//3])
        mid_point = len(data) // 2
        samples.append(data[mid_point-sample_size//6:mid_point+sample_size//6])
        samples.append(data[-sample_size//3:])
        data = b''.join(samples)
    
    # Count byte frequencies
    byte_counts = defaultdict(int)
    data_len = len(data)
    
    for byte in data:
        byte_counts[byte] += 1
    
    # Calculate entropy
    entropy = 0
    for count in byte_counts.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    
    return entropy

def is_process_trusted(process_name):
    """Check if process is in the trusted list"""
    return process_name.lower() in TRUSTED_PROCESSES

def is_admin_process(pid):
    """Check if process has admin privileges"""
    if not WINDOWS_MODULES_AVAILABLE:
        return False
        
    try:
        proc_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        token = win32security.OpenProcessToken(proc_handle, win32con.TOKEN_QUERY)
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        
        # Get administrator SID
        admin_sid = win32security.LookupAccountName(None, 'Administrators')[0]
        
        # Check if process belongs to admin group
        return win32security.CheckTokenMembership(token, admin_sid)
    except:
        return False

def get_process_connections(pid):
    """Get network connections for a process"""
    try:
        proc = psutil.Process(pid)
        return proc.connections(kind='all')
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []

def log_suspicious_activity(pid, score, detection_reasons):
    """Log suspicious process activity"""
    process_name = get_process_name(pid)
    process_path = get_process_path(pid)
    
    if score >= HIGH_CONFIDENCE_THRESHOLD:
        level = "CRITICAL"
    elif score >= INITIAL_THRESHOLD:
        level = "WARNING"
    else:
        level = "INFO"
    
    reasons_str = ", ".join(detection_reasons)
    
    log_message = (
        f"{level}: Process {pid} ({process_name}) at {process_path} "
        f"scored {score} points. Reasons: {reasons_str}"
    )
    
    if level == "CRITICAL":
        logging.critical(log_message)
    elif level == "WARNING":
        logging.warning(log_message)
    else:
        logging.info(log_message)

# ===== Detection functions =====

def detect_file_encryption_patterns(pid):
    """Detect patterns suggesting file encryption"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    operations = file_operations[pid]
    
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
    operations = file_operations[pid]
    
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
    operations = file_operations[pid]
    
    # Count operations by type
    op_counts = defaultdict(int)
    extensions_accessed = set()
    directories_accessed = set()
    
    for op in operations:
        op_counts[op['type']] += 1
        if 'path' in op:
            ext = os.path.splitext(op['path'])[1].lower()
            if ext:
                extensions_accessed.add(ext)
            
            directory = os.path.dirname(op['path'])
            if directory:
                directories_accessed.add(directory)
    
    # Score based on volume and diversity of operations
    if op_counts['write'] > 20:
        score += min(op_counts['write'] // 10, 5)
    
    if op_counts['delete'] > 10:
        score += min(op_counts['delete'] // 5, 5)
    
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
    operations = file_operations[pid]
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
    operations = file_operations[pid]
    
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
    operations = file_operations[pid]
    high_entropy_count = 0
    
    for op in operations:
        if op['type'] == 'write' and 'path' in op and 'entropy' in op:
            # Entropy over 7.5 is typical for encrypted/compressed data
            if op['entropy'] > 7.5:
                high_entropy_count += 1
    
    if high_entropy_count >= 3:
        score += min(high_entropy_count, 6)
    
    return score

def detect_shadow_copy_deletion(pid):
    """Detect attempts to delete Windows shadow copies"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history = process_history[pid]
    
    shadow_copy_patterns = [
        r'vssadmin.*delete shadows',
        r'wmic.*shadowcopy delete',
        r'bcdedit.*set default',
        r'wbadmin delete catalog',
        r'delete.*shadow',
    ]
    
    for event in proc_history:
        if event['type'] == 'process_exec' and 'command_line' in event:
            cmd = event['command_line'].lower()
            
            for pattern in shadow_copy_patterns:
                if re.search(pattern, cmd):
                    score += 10  # This is a strong indicator
                    break
    
    return score

def detect_network_c2_traffic(pid):
    """Detect potential command & control traffic"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_connections = network_connections[pid]
    
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

def detect_ransomware_process_patterns(pid):
    """Detect process behavior indicative of ransomware"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history = process_history[pid]
    
    # Check for high CPU usage spikes (encryption is CPU intensive)
    cpu_spikes = 0
    for event in proc_history:
        if event['type'] == 'cpu_usage' and event['value'] > 80:
            cpu_spikes += 1
    
    if cpu_spikes >= 3:
        score += 2
    
    # Check for suspicious process names
    suspicious_names = [
        'crypt', 'ransom', 'wcry', 'wncry', 'lock', 
        'encryptor', 'cryptor', 'decrypt', 'locker'
    ]
    
    for pattern in suspicious_names:
        if pattern in proc_name:
            score += 3
            break
    
    return score

def detect_system_modifications(pid):
    """Detect system modifications typical of ransomware"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history = process_history[pid]
    
    # Check for registry modifications
    registry_modifications = 0
    startup_modifications = 0
    service_creations = 0
    
    for event in proc_history:
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

def detect_high_disk_usage(pid):
    """Detect unusually high disk I/O operations"""
    proc_name = get_process_name(pid)
    if is_process_trusted(proc_name):
        return 0
    
    score = 0
    proc_history = process_history[pid]
    
    # Count disk read/write events
    disk_events = [e for e in proc_history if e['type'] == 'disk_io']
    
    if not disk_events:
        return 0
    
    # Calculate total read/write bytes
    total_read_bytes = sum(e['read_bytes'] for e in disk_events if 'read_bytes' in e)
    total_write_bytes = sum(e['write_bytes'] for e in disk_events if 'write_bytes' in e)
    
    # Calculate rates (bytes per second)
    time_span = max(1, disk_events[-1]['time'] - disk_events[0]['time'])
    read_rate = total_read_bytes / time_span
    write_rate = total_write_bytes / time_span
    
    # Score based on read/write rates
    # High write rate is more suspicious (encryption creates writes)
    if write_rate > 10 * 1024 * 1024:  # More than 10 MB/s
        score += 3
    elif write_rate > 5 * 1024 * 1024:  # More than 5 MB/s
        score += 2
    elif write_rate > 1 * 1024 * 1024:  # More than 1 MB/s
        score += 1
    
    # High read rate combined with high write could indicate file encryption
    if read_rate > 10 * 1024 * 1024 and write_rate > 5 * 1024 * 1024:
        score += 2
    
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
            score += 2
    
    return min(score, 5)  # Cap at 5 points

# ===== Main monitoring functions =====

def monitor_file_operations():
    """Monitor file system operations"""
    try:
        # Initialize file monitoring
        if WINDOWS_MODULES_AVAILABLE:
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
                            
                            file_operations[pid].append(operation)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                except:
                    pass
            
            # Sleep to reduce CPU usage
            time.sleep(FILE_WATCH_INTERVAL)
            
    except Exception as e:
        logging.error(f"File monitoring error: {e}")

def monitor_processes():
    """Monitor process activity"""
    try:
        while not stop_event.is_set():
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    pid = proc.info['pid']
                    
                    # Skip system processes
                    if pid <= 4:
                        continue
                    
                    # Skip trusted processes for efficiency
                    if is_process_trusted(proc.info['name']):
                        continue
                    
                    # Skip already flagged processes
                    if pid in flagged_processes:
                        continue
                    
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
                    analyze_process(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception as e:
                    logging.debug(f"Error monitoring process {pid}: {e}")
            
            # Clean up expired entries
            cleanup_expired_entries()
            
            time.sleep(PROCESS_CHECK_INTERVAL)
    except Exception as e:
        logging.error(f"Process monitoring error: {e}")

def cleanup_expired_entries():
    """Clean up expired entries from tracking dictionaries"""
    current_time = time.time()
    
    # Clean up processes that no longer exist
    for pid in list(process_history.keys()):
        try:
            psutil.Process(pid)
        except psutil.NoSuchProcess:
            del process_history[pid]
            if pid in file_operations:
                del file_operations[pid]
            if pid in network_connections:
                del network_connections[pid]
            if pid in flagged_processes:
                flagged_processes.remove(pid)
    
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

def analyze_process(pid):
    """Analyze a process for ransomware behavior"""
    with scan_lock:
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name().lower()
            
            # Skip trusted processes
            if is_process_trusted(proc_name):
                return
            
            # Apply all detection functions and calculate score
            score = 0
            detection_reasons = []
            
            # File encryption patterns
            points = detect_file_encryption_patterns(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['file_encryption_patterns']
                detection_reasons.append(f"File encryption patterns: {points}")
            
            # Multiple extension changes
            points = detect_multiple_extension_changes(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['multiple_extension_changes']
                detection_reasons.append(f"Multiple extension changes: {points}")
            
            # Mass file operations
            points = detect_mass_file_operations(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['mass_file_operations']
                detection_reasons.append(f"Mass file operations: {points}")
            
            # Suspicious file access
            points = detect_suspicious_file_access(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['suspicious_file_access']
                detection_reasons.append(f"Suspicious file access: {points}")
                
            # Ransomware extensions
            points = detect_ransomware_extensions(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['ransomware_extensions']
                detection_reasons.append(f"Ransomware extensions detected: {points}")
            
            # High entropy writes
            points = detect_high_entropy_writes(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['high_entropy_writes']
                detection_reasons.append(f"High entropy writes: {points}")
            
            # Shadow copy deletion
            points = detect_shadow_copy_deletion(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['shadow_copy_deletion']
                detection_reasons.append(f"Shadow copy deletion attempt: {points}")
            
            # Network C2 traffic
            points = detect_network_c2_traffic(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['network_c2_traffic']
                detection_reasons.append(f"Suspicious network traffic: {points}")
            
            # Ransomware process patterns
            points = detect_ransomware_process_patterns(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['ransomware_process_patterns']
                detection_reasons.append(f"Ransomware process behavior: {points}")
            
            # High disk usage
            points = detect_high_disk_usage(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['high_disk_usage']
                detection_reasons.append(f"High disk usage: {points}")
            
            # System modifications
            points = detect_system_modifications(pid)
            if points > 0:
                score += points * FEATURE_WEIGHTS['system_modifications']
                detection_reasons.append(f"Suspicious system modifications: {points}")
            
            # Log suspicious activity
            if score > 0:
                log_suspicious_activity(pid, score, detection_reasons)
            
            # Take action if score is high enough
            if score >= HIGH_CONFIDENCE_THRESHOLD:
                handle_detected_threat(pid, score, detection_reasons)
            elif score >= INITIAL_THRESHOLD:
                # For medium scores, just log a warning
                flagged_processes.add(pid)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logging.error(f"Error analyzing process {pid}: {e}")

def handle_detected_threat(pid, score, detection_reasons):
    """Handle a detected ransomware threat"""
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc_path = proc.exe()
        
        # Mark as flagged to avoid duplicate actions
        flagged_processes.add(pid)
        
        # Log the threat
        logging.critical(
            f"RANSOMWARE THREAT DETECTED: Process {pid} ({proc_name}) at {proc_path} "
            f"scored {score} points. Taking protective action."
        )
        
        # Calculate hash of the executable for reporting
        try:
            with open(proc_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                logging.critical(f"Threat file hash (SHA256): {file_hash}")
        except:
            logging.error(f"Unable to calculate hash for {proc_path}")
        
        # Create alert notification for user
        print("\n" + "!"*80)
        print(f"RANSOMWARE THREAT DETECTED: Process {proc_name} (PID: {pid})")
        print(f"Process path: {proc_path}")
        print(f"Detection score: {score} out of {HIGH_CONFIDENCE_THRESHOLD} threshold")
        print(f"Detection reasons: {', '.join(detection_reasons)}")
        print("!"*80 + "\n")
        
        # Kill the process
        try:
            logging.info(f"Attempting to terminate process {pid}")
            proc.terminate()
            
            # Wait up to 3 seconds for graceful termination
            gone, still_alive = psutil.wait_procs([proc], timeout=3)
            
            # If still running, force kill
            if proc in still_alive:
                logging.info(f"Process {pid} still alive after terminate(), killing")
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.error(f"Failed to terminate process {pid}: {e}")
            print(f"FAILED TO TERMINATE PROCESS: {str(e)}")
            print("Try running this program with administrator privileges")
    
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        logging.error(f"Error handling threat for process {pid}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error handling threat: {e}")

def start_monitoring():
    """Start all monitoring threads"""
    initialize_protected_dirs()
    
    logging.info("===== Ransomware Detector Started =====")
    logging.info(f"Current settings: Initial threshold={INITIAL_THRESHOLD}, High confidence threshold={HIGH_CONFIDENCE_THRESHOLD}")
    
    print("Ransomware Detector started")
    print(f"- Monitoring file operations with {FILE_WATCH_INTERVAL}s interval")
    print(f"- Monitoring processes with {PROCESS_CHECK_INTERVAL}s interval")
    print(f"- Alert thresholds: Warning={INITIAL_THRESHOLD}, Critical={HIGH_CONFIDENCE_THRESHOLD}")
    print(f"- Trusted processes: {len(TRUSTED_PROCESSES)}")
    print(f"- Protected directories: {len(PROTECTED_DIRS)}")
    print("Monitoring active... Press Ctrl+C to stop")
    
    # Start monitoring threads
    file_thread = threading.Thread(target=monitor_file_operations, daemon=True)
    process_thread = threading.Thread(target=monitor_processes, daemon=True)
    
    file_thread.start()
    process_thread.start()
    
    try:
        # Main thread waits for Ctrl+C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping ransomware detector...")
        stop_event.set()
        
        # Wait for threads to finish
        file_thread.join(timeout=5)
        process_thread.join(timeout=5)
        
        logging.info("===== Ransomware Detector Stopped =====")
        print("Ransomware Detector stopped")

if __name__ == "__main__":
    try:
        start_monitoring()
    except Exception as e:
        logging.critical(f"Critical error in main process: {e}")
        print(f"Critical error: {e}")
        exit(1)