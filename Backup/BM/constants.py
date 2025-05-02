"""
Constants and configuration settings for the ransomware detector.
"""

import os
import threading
from collections import defaultdict, deque

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

# Protected system directories (initialized in utils.py)
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
    'high_disk_usage': 0,              # High disk I/O operations (Currently disabled by weight)
}

# Configuration of thresholds
INITIAL_THRESHOLD = 15                # Minimum score to trigger an alert
HIGH_CONFIDENCE_THRESHOLD = 25        # Score that strongly indicates ransomware
MAX_HISTORY_ENTRIES = 1000            # Maximum events to track in history
FILE_WATCH_INTERVAL = 0.5             # Seconds between file system checks
PROCESS_CHECK_INTERVAL = 1            # Seconds between process checks
EVENT_EXPIRY_TIME = 60                # Seconds before events expire from memory
REANALYSIS_INTERVAL = 300             # Seconds (5 minutes) between re-analyzing existing processes

# ===== Global state =====
process_history = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
file_operations = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
network_connections = defaultdict(lambda: deque(maxlen=MAX_HISTORY_ENTRIES))
flagged_processes = set()             # PIDs of processes already flagged
scan_lock = threading.Lock()          # Lock for thread safety
stop_event = threading.Event()        # Event to signal threads to stop
