#!/usr/bin/env python3
"""
Configuration and constants for Behavioral Monitor
"""

import logging
import os
import sys
from collections import defaultdict, deque
from datetime import datetime

#------------------------------------------------------------------------------
# LOGGING CONFIGURATION
#------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler("behavior_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BehaviorMonitor")

# Ensure file monitoring logs are properly captured
file_logger = logging.getLogger("BehaviorMonitor.FileMonitor")
file_logger.setLevel(logging.DEBUG)

#------------------------------------------------------------------------------
# DETECTION THRESHOLDS AND TIMING
#------------------------------------------------------------------------------
THRESHOLD = 20              # The threshold score for flagging a process as malicious
MONITOR_INTERVAL = 5        # Seconds between monitoring cycles
HISTORY_WINDOW = 30         # Seconds of history to keep for rate calculations

# File operation monitoring settings
SEQUENTIAL_FILE_THRESHOLD = 5       # Number of sequential file operations that might indicate ransomware
SEQUENTIAL_TIME_WINDOW = 10         # Time window in seconds for sequential operations
PROCESS_IDENTIFICATION_TIMEOUT = 3.0  # Seconds to wait for process identification before giving up
VERBOSE_PROCESS_IDENTIFICATION = True  # Enable detailed logging for process identification

#------------------------------------------------------------------------------
# FEATURE WEIGHTS FOR SCORING
#------------------------------------------------------------------------------
WEIGHTS = {
    "rapid_file_modification": 15,
    "mass_deletion": 25,
    "mass_file_writes": 20,
    "high_cpu_usage": 10,
    "encrypted_file_writes": 20,
    "weird_extension_writes": 15,
    "critical_system_access": 25,
    "api_hooks_triggered": 25,
    "memory_patterns": 20,
    "network_traffic_anomaly": 20
}

#------------------------------------------------------------------------------
# DETECTION LISTS AND PATTERNS
#------------------------------------------------------------------------------
# Suspicious file extensions often used by ransomware
WEIRD_EXTENSIONS = [
    '.fun', '.dog', '.wcry', '.locky', '.cerber', '.cryptolocker', 
    '.crypt', '.encrypted', '.enc', '.locked', '.crypto', '.lol',
    '.aaa', '.ecc', '.ezz', '.exx', '.zzz', '.xyz', '.abc', 
    '.ccc', '.vvv', '.xxx', '.ttt', '.micro', '.encrypted', '.vault'
]

# Critical system paths to monitor closely
CRITICAL_SYSTEM_PATHS = [
    r'C:',
]

#------------------------------------------------------------------------------
# PROCESS FILTER LISTS
#------------------------------------------------------------------------------
# Processes to ignore during monitoring (common system and safe processes)
IGNORED_PROCESSES = [
    # System processes
    'System', 'Registry', 'Memory Compression', 'svchost.exe', 'csrss.exe', 
    'services.exe', 'lsass.exe', 'winlogon.exe', 'explorer.exe', 'dwm.exe',
    'spoolsv.exe', 'smss.exe', 'ntoskrnl.exe', 'wininit.exe', 'taskhost.exe',
    'taskhostw.exe', 'RuntimeBroker.exe', 'SearchIndexer.exe', 'ShellExperienceHost.exe',
    
    # Common applications
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 
    'notepad.exe', 'calc.exe', 'mspaint.exe',
    
    # Background services
    'audiodg.exe', 'SearchUI.exe', 'OneDrive.exe', 'WindowsDefender.exe',
    'MsMpEng.exe', 'SecurityHealthService.exe',
    
    # Additional processes from active list
    'fontdrvhost.exe', 'msedgewebview2.exe', 'smartscreen.exe', 'ShellHost.exe',
    'SearchHost.exe', 'dllhost.exe', 'python3.13.exe', 'Widgets.exe',
    'StartMenuExperienceHost.exe', 'WidgetService.exe', 'ctfmon.exe', 'sihost.exe',
    'NisSrv.exe',
    
    # Safe processes from provided list
    'VBoxService.exe', 'MemCompression', 'AggregatorHost.exe', 'MpDefenderCoreService.exe',
    'MicrosoftEdgeUpdate.exe', 'SecurityHealthSystray.exe', 'VBoxTray.exe', 
    'SystemSettings.exe', 'WindowsTerminal.exe', 'ApplicationFrameHost.exe', 
    'UserOOBEBroker.exe', 'TextInputHost.exe',
]

#------------------------------------------------------------------------------
# GLOBAL STATE
#------------------------------------------------------------------------------
# Global monitoring state
process_data = defaultdict(lambda: {
    "file_ops": deque(maxlen=100),
    "deletions": deque(maxlen=100),
    "file_writes": deque(maxlen=100),
    "cpu_history": deque(maxlen=20),
    "encrypted_writes": deque(maxlen=100),
    "weird_ext_writes": deque(maxlen=100),
    "critical_access": deque(maxlen=100),
    "api_hooks": deque(maxlen=100),
    "memory_patterns": deque(maxlen=100),
    "network_traffic": deque(maxlen=100),
    "last_scores": deque(maxlen=10),
    "timestamp": datetime.now()
})

# Keep track of flagged processes to avoid redundant actions
flagged_processes = set()
