"""
Ransomcare Behavioral Monitor (BM) Package

This package provides modules for detecting ransomware-like behavior 
based on process activity and file system interactions.
"""

# Make key components easily accessible
from .constants import *
from .utils import initialize_protected_dirs, log_suspicious_activity
from .threat_handler import handle_detected_threat
from .monitors.file_monitor import monitor_file_operations
from .monitors.process_monitor import monitor_processes, analyze_process

# Define package version (optional)
__version__ = "1.0.0"

# You could perform initial setup here, but it's often better done
# explicitly when starting the monitoring (e.g., in __main__.py)
# initialize_protected_dirs() 
