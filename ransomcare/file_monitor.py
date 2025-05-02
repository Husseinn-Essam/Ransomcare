"""
File system monitoring functionality for Behavioral Monitor.
Detects and tracks file operations and associates them with processes.
"""

import os
import time
import math
import threading
import logging
from datetime import datetime
from collections import deque, defaultdict
from typing import Optional, List, Dict, Set, Tuple, Any
from watchdog.events import FileSystemEventHandler
import psutil
import re

from ransomcare.config import (
    process_data, WEIRD_EXTENSIONS, CRITICAL_SYSTEM_PATHS, IGNORED_PROCESSES,
    SEQUENTIAL_FILE_THRESHOLD, SEQUENTIAL_TIME_WINDOW,
    PROCESS_IDENTIFICATION_TIMEOUT, VERBOSE_PROCESS_IDENTIFICATION
)

logger = logging.getLogger("BehaviorMonitor.FileMonitor")


class FileMonitorHandler(FileSystemEventHandler):
    """
    Handles file system events and identifies processes responsible for file operations.
    """
    
    def __init__(self):
        """Initialize the file monitor handler with required data structures."""
        super().__init__()
        logger.info("Initializing FileMonitorHandler")
        
        # Data structures for tracking activity
        self.process_cache = {}                         # Cache of process info
        self.directory_activity = defaultdict(list)     # Track file activity by directory
        self.process_activity = defaultdict(int)        # Track process activity levels
        self.last_modification_time = {}                # Last time a file was modified
        self.sequential_operations = defaultdict(int)   # Count sequential operations by directory
        
        # Start background thread for process monitoring
        self._start_process_refresher()

    #--------------------------------------------------------------------------
    # Process Cache Management
    #--------------------------------------------------------------------------
    
    def _start_process_refresher(self) -> None:
        """Start a background thread to continuously refresh the process cache."""
        def refresh():
            while True:
                try:
                    self._refresh_process_cache()
                    time.sleep(1.5)  # Refresh frequency
                except Exception as e:
                    logger.error(f"Process cache refresh failed: {e}")
                    time.sleep(3)  # Wait longer after an error
        
        # Start the thread as a daemon so it exits when the main program exits
        threading.Thread(target=refresh, daemon=True).start()
        logger.info("Started background thread to refresh process cache")
    
    def _refresh_process_cache(self) -> None:
        """Refresh the cache of process information."""
        cache = {}
        process_activity = defaultdict(int)
        
        # Get all running processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent']):
            try:
                pid = proc.info['pid']
                proc_name = proc.info['name']
                
                # Skip processes we want to ignore
                if proc_name.lower() in [p.lower() for p in IGNORED_PROCESSES]:
                    continue
                    
                # Format the command line for better readability
                cmdline = proc.info.get('cmdline', [])
                cmdline_str = ' '.join(str(arg) for arg in cmdline) if cmdline and isinstance(cmdline, (list, tuple)) else ''
                
                # Check if process is suspicious (placeholder for future criteria)
                is_suspicious = False
                
                # Get open files (try-except to handle permission issues)
                open_files = set()
                accessed_dirs = set()
                try:
                    if pid > 1000:  # Skip system processes
                        # Get open file handles
                        for file in proc.open_files():
                            open_files.add(file.path)
                            dir_path = os.path.dirname(file.path)
                            accessed_dirs.add(dir_path)
                        
                        # Monitor CPU activity as an indicator of active processes
                        cpu = proc.cpu_percent(interval=0.1)
                        if cpu > 0:
                            process_activity[pid] += 1
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Store the process info
                cache[pid] = {
                    'name': proc_name,
                    'exe': proc.info.get('exe', ''),
                    'cmdline': cmdline_str,
                    'username': proc.info.get('username', ''),
                    'last_seen': datetime.now(),
                    'open_files': open_files,
                    'accessed_dirs': accessed_dirs,
                    'is_suspicious': is_suspicious
                }
                
                # Update directory activity for this process
                for dir_path in accessed_dirs:
                    if dir_path in self.directory_activity:
                        if pid not in [p for p, _ in self.directory_activity[dir_path]]:
                            self.directory_activity[dir_path].append((pid, datetime.now()))
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        # Update our cache
        self.process_cache = cache
        self.process_activity = process_activity
        
        # Clean up old directory activity
        self._clean_directory_activity()
        
        logger.debug(f"Refreshed process cache: {len(cache)} entries")

    def _clean_directory_activity(self) -> None:
        """Remove old entries from directory activity tracking."""
        now = datetime.now()
        for dir_path in list(self.directory_activity.keys()):
            # Remove entries older than SEQUENTIAL_TIME_WINDOW
            self.directory_activity[dir_path] = [
                (pid, ts) for pid, ts in self.directory_activity[dir_path]
                if (now - ts).total_seconds() < SEQUENTIAL_TIME_WINDOW * 2
            ]
            
            # Remove the directory if there's no activity
            if not self.directory_activity[dir_path]:
                del self.directory_activity[dir_path]

    #--------------------------------------------------------------------------
    # Event Handling
    #--------------------------------------------------------------------------
    
    def on_any_event(self, event) -> None:
        """
        Handle any file system event by identifying the responsible process
        and recording relevant metrics.
        """
        try:
            path = event.src_path
            if self._should_ignore(path):
                return

            start = datetime.now()
            dir_path = os.path.dirname(path)
            
            # Update directory activity tracking
            self._update_activity_tracking(dir_path, start)
            
            logger.info(f"[{start.strftime('%H:%M:%S.%f')[:-3]}] {event.event_type}: {path}")

            # Find the responsible process
            pid = self._identify_process(path, event.event_type, start)
            elapsed = (datetime.now() - start).total_seconds()

            # Process the event based on whether we identified a process
            if pid is not None:
                self._process_identified_event(pid, event, path, elapsed)
            else:
                self._process_unidentified_event(dir_path, event, path, start, elapsed)

        except Exception as e:
            logger.error(f"Exception in event handler: {e}", exc_info=True)

    def _update_activity_tracking(self, dir_path: str, timestamp: datetime) -> None:
        """Update directory activity tracking with new event."""
        self.last_modification_time[dir_path] = timestamp
        
        # Track sequential operations
        if dir_path in self.sequential_operations:
            # If the last operation was recent, increment the counter
            if (timestamp - self.last_modification_time.get(dir_path, datetime.min)).total_seconds() < SEQUENTIAL_TIME_WINDOW:
                self.sequential_operations[dir_path] += 1
            else:
                # Reset if too much time has passed
                self.sequential_operations[dir_path] = 1
        else:
            self.sequential_operations[dir_path] = 1
            
        # If we detect a high number of sequential operations, increase logging
        if self.sequential_operations[dir_path] >= SEQUENTIAL_FILE_THRESHOLD:
            logger.warning(f"High sequential activity detected in {dir_path}: {self.sequential_operations[dir_path]} operations")

    def _process_identified_event(self, pid: int, event, path: str, elapsed: float) -> None:
        """Process an event where we identified the responsible process."""
        proc = self.process_cache.get(pid, {})
        logger.info(f"Detected process {pid} ({proc.get('name', 'unknown')}) -> {event.event_type} {path} [resolved in {elapsed:.2f}s]")
        self._record_event(pid, event)
        self._log_stats(pid)
        
        # Update directory activity with this process
        dir_path = os.path.dirname(path)
        if (pid, datetime.now()) not in self.directory_activity[dir_path]:
            self.directory_activity[dir_path].append((pid, datetime.now()))

    def _process_unidentified_event(self, dir_path: str, event, path: str, start: datetime, elapsed: float) -> None:
        """Process an event where we couldn't identify the responsible process."""
        logger.warning(f"Could not directly determine process for {path} after {elapsed:.2f}s")
        
        # Try to identify by recent activity in the same directory
        heuristic_pid = self._identify_by_heuristics(dir_path, start)
        
        if heuristic_pid:
            proc = self.process_cache.get(heuristic_pid, {})
            logger.info(f"Identified likely process {heuristic_pid} ({proc.get('name', 'unknown')}) for {path} using heuristics")
            self._record_event(heuristic_pid, event)
            self._log_stats(heuristic_pid)
        else:
            logger.info(f"Active processes: {self._active_processes_snapshot()}")
            self._record_event(-1, event)  # Use -1 to indicate unknown process

    def _should_ignore(self, path: str) -> bool:
        """Determine if a file event should be ignored."""
        ignore_patterns = [
            '\\Prefetch\\', '\\AppData\\Local\\Temp\\', '\\WindowsApps\\',
            '.etl', '.log', '.tmp', '.temp', '\\Cookies\\', '\\History\\', '\\Recent\\'
        ]
        return any(p in path for p in ignore_patterns)

    #--------------------------------------------------------------------------
    # Process Identification Strategies
    #--------------------------------------------------------------------------
    
    def _identify_process(self, path: str, event_type: str, event_time: datetime) -> Optional[int]:
        """
        Try multiple strategies to identify the process responsible for a file event.
        Returns the process ID if found, None otherwise.
        """
        # Set a timeout for process identification
        start_time = datetime.now()
        
        # Try various identification strategies in order of reliability
        strategies = [
            (self._check_cache_for_file, "cache check", 0.2),
            (self._check_open_files, "open files check", 0.5),
            (self._check_directory_activity, "directory activity", 0.7),
            (self._check_active_processes, "active processes", 0.8),
            (self._check_suspicious_processes, "suspicious processes", 1.0)
        ]
        
        for strategy_func, strategy_name, timeout_fraction in strategies:
            # Check if we've exceeded the timeout allowance for this stage
            if (datetime.now() - start_time).total_seconds() > PROCESS_IDENTIFICATION_TIMEOUT * timeout_fraction:
                if VERBOSE_PROCESS_IDENTIFICATION:
                    logger.debug(f"Skipping {strategy_name} due to timeout")
                continue
                
            # Try this strategy
            pid = strategy_func(path, event_time)
            if pid is not None:
                if VERBOSE_PROCESS_IDENTIFICATION:
                    logger.debug(f"Process {pid} identified through {strategy_name}")
                return pid
        
        # No strategy worked within timeout
        return None
        
    def _check_cache_for_file(self, path: str, event_time: datetime) -> Optional[int]:
        """Check if any process has the file open in our process cache."""
        for pid, info in self.process_cache.items():
            if path in info.get('open_files', set()):
                return pid
        return None

    def _check_open_files(self, path: str, event_time: datetime) -> Optional[int]:
        """Check which process has the file open directly through psutil."""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                # Skip low PIDs and ignored processes
                if proc.pid < 100 or proc.name().lower() in [p.lower() for p in IGNORED_PROCESSES]:
                    continue
                    
                try:
                    for file in proc.open_files():
                        if file.path == path:
                            return proc.pid
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception as e:
            logger.debug(f"Error checking open files: {e}")
        return None

    def _check_directory_activity(self, path: str, event_time: datetime) -> Optional[int]:
        """Check which processes have been active in the directory."""
        dir_path = os.path.dirname(path)
        if dir_path in self.directory_activity:
            # Sort by recency
            recent_procs = sorted(
                [(pid, ts) for pid, ts in self.directory_activity[dir_path] 
                 if (event_time - ts).total_seconds() < SEQUENTIAL_TIME_WINDOW],
                key=lambda x: x[1], 
                reverse=True
            )
            
            if recent_procs:
                return recent_procs[0][0]
        return None

    def _check_active_processes(self, path: str, event_time: datetime) -> Optional[int]:
        """Check processes with high activity levels."""
        if self.process_activity:
            # Get the process with highest activity
            active_procs = sorted(self.process_activity.items(), key=lambda x: x[1], reverse=True)
            for pid, activity in active_procs:
                if activity > 0 and pid in self.process_cache:
                    return pid
        return None

    def _check_suspicious_processes(self, path: str, event_time: datetime) -> Optional[int]:
        """Check if any suspicious processes are running."""
        suspicious_pids = []
        
        for pid, info in self.process_cache.items():
            if info.get('is_suspicious', False):
                suspicious_pids.append(pid)
                
        if suspicious_pids:
            # Return the first suspicious PID
            return suspicious_pids[0]
        return None

    def _identify_by_heuristics(self, dir_path: str, event_time: datetime) -> Optional[int]:
        """
        Use heuristics to identify the likely process responsible for file activity.
        Returns the process ID of the best candidate.
        """
        candidates = []
        
        # Heuristic 1: Processes that have accessed this directory recently
        if dir_path in self.directory_activity:
            for pid, ts in self.directory_activity[dir_path]:
                if (event_time - ts).total_seconds() < SEQUENTIAL_TIME_WINDOW:
                    # Recent activity gets a high score
                    time_diff = (event_time - ts).total_seconds()
                    score = 10 - time_diff  # Higher score for more recent activity
                    candidates.append((pid, score))

        # Heuristic 2: Processes with high activity levels
        for pid, activity in self.process_activity.items():
            if pid in self.process_cache:  # Make sure the process is still in cache
                # Activity level contributes to score
                score = min(activity, 5)
                # Add more score for suspicious processes
                if self.process_cache[pid].get('is_suspicious', False):
                    score += 5
                candidates.append((pid, score))

        # Heuristic 3: Check for processes with similar file access patterns
        for pid, info in self.process_cache.items():
            if dir_path in info.get('accessed_dirs', set()):
                candidates.append((pid, 8))  # High score for accessing the same directory
                
        # If we have candidates, return the one with highest score
        if candidates:
            # Group by PID and sum scores
            pid_scores = defaultdict(float)
            for pid, score in candidates:
                pid_scores[pid] += score
                
            # Get PID with highest score
            best_pid = max(pid_scores.items(), key=lambda x: x[1])[0]
            return best_pid
            
        return None

    def _infer_from_activity(self, path: str) -> Optional[int]:
        """Infer from recent activity in process_data."""
        dir_path = os.path.dirname(path)
        now = datetime.now()
        candidates = []

        # Check recent activity in process_data
        for pid, data in process_data.items():
            for key in ['file_ops', 'file_writes', 'deletions']:
                for ts, fpath in data.get(key, []):
                    if os.path.dirname(fpath) == dir_path and (now - ts).total_seconds() < SEQUENTIAL_TIME_WINDOW:
                        candidates.append((pid, ts))

        if candidates:
            candidates.sort(key=lambda x: x[1], reverse=True)
            return candidates[0][0]
        return None

    #--------------------------------------------------------------------------
    # Event Recording and Analysis
    #--------------------------------------------------------------------------
    
    def _record_event(self, pid: int, event) -> None:
        """Record a file event for a specific process."""
        now = datetime.now()
        path = event.src_path
        
        # Initialize process data structure if needed
        if pid not in process_data:
            process_data[pid] = {
                'file_ops': deque(maxlen=100),
                'deletions': deque(maxlen=100),
                'file_writes': deque(maxlen=100),
                'encrypted_writes': deque(maxlen=100),
                'weird_ext_writes': deque(maxlen=100),
                'critical_access': deque(maxlen=100),
                'cpu_history': deque(maxlen=100),
                'api_hooks': deque(maxlen=100),
                'memory_patterns': deque(maxlen=100),
                'network_traffic': deque(maxlen=100),
                'last_scores': deque(maxlen=10),
                'timestamp': now
            }

        # Record the event based on its type
        if event.event_type == 'modified':
            process_data[pid]['file_ops'].append((now, path))
        if event.event_type == 'deleted':
            process_data[pid]['deletions'].append((now, path))
        if event.event_type in ('created', 'modified'):
            process_data[pid]['file_writes'].append((now, path))
            if os.path.exists(path) and os.path.isfile(path):
                self._analyze_file(pid, path, now)

    def _log_stats(self, pid: int) -> None:
        """Log statistics about a process's activity."""
        if pid in process_data:
            d = process_data[pid]
            logger.info(
                f"PID {pid} activity -> "
                f"ops: {len(d['file_ops'])}, del: {len(d['deletions'])}, "
                f"writes: {len(d['file_writes'])}, enc: {len(d['encrypted_writes'])}, "
                f"weird: {len(d['weird_ext_writes'])}, critical: {len(d['critical_access'])}"
            )

    def _analyze_file(self, pid: int, path: str, timestamp: datetime) -> None:
        """Analyze a file for suspicious properties."""
        # Check for encrypted content
        if self._is_encrypted(path):
            process_data[pid]['encrypted_writes'].append((timestamp, path))
            logger.warning(f"Encrypted file suspected from PID {pid}: {path}")
        
        # Check for suspicious extensions
        ext = os.path.splitext(path)[1].lower()
        if ext in WEIRD_EXTENSIONS:
            process_data[pid]['weird_ext_writes'].append((timestamp, path))
            logger.warning(f"Suspicious extension {ext} from PID {pid}: {path}")
        
        # Check critical system paths
        self._check_critical_path(pid, path, timestamp)

    def _check_critical_path(self, pid: int, path: str, timestamp: datetime) -> None:
        """Check if a file is in a critical system path."""
        for critical in CRITICAL_SYSTEM_PATHS:
            if path.lower().startswith(critical.lower()):
                process_data[pid]['critical_access'].append((timestamp, path))
                logger.warning(f"Critical system path accessed by PID {pid}: {path}")
                break

    def _is_encrypted(self, path: str) -> bool:
        """Check if a file might be encrypted based on entropy."""
        try:
            if not os.path.isfile(path) or os.path.getsize(path) < 512:
                return False
            with open(path, 'rb') as f:
                data = f.read(8192)
            
            # Calculate Shannon entropy
            entropy = 0.0
            if data:
                for i in range(256):
                    p_x = data.count(i) / len(data)
                    if p_x > 0:
                        entropy -= p_x * math.log2(p_x)
            
            return entropy > 7.8
        except Exception:
            return False

    def _active_processes_snapshot(self) -> str:
        """Get a snapshot of active processes for logging."""
        try:
            # Get active processes, mark suspicious ones with an asterisk
            procs = []
            for pid, info in self.process_cache.items():
                if pid > 1000 and info.get('username') and info.get('name').lower() not in [p.lower() for p in IGNORED_PROCESSES]:
                    name = info.get('name', 'unknown')
                    # Mark suspicious processes with an asterisk
                    if info.get('is_suspicious', False):
                        procs.append(f"{pid}:{name}*")
                    else:
                        procs.append(f"{pid}:{name}")
            
            # Sort by PID
            procs.sort(key=lambda x: int(x.split(':')[0]))
            return ', '.join(procs[:20]) + ('...' if len(procs) > 20 else '')
        except Exception:
            return 'Unavailable'