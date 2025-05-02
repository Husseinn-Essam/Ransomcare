"""
File system monitoring functionality for Behavioral Monitor.

This module provides functionality to detect and track file operations
and associate them with the responsible processes. It uses a combination
of direct process identification and heuristic approaches to identify
which process performed a file operation.
"""

import os
import time
import math
import threading
import logging
from datetime import datetime
from collections import deque, defaultdict
from typing import Optional, Dict
from watchdog.events import FileSystemEventHandler
import psutil

from ransomcare.config import (
    process_data, WEIRD_EXTENSIONS, CRITICAL_SYSTEM_PATHS, IGNORED_PROCESSES,
    SEQUENTIAL_FILE_THRESHOLD, SEQUENTIAL_TIME_WINDOW,
    PROCESS_IDENTIFICATION_TIMEOUT, VERBOSE_PROCESS_IDENTIFICATION
)

logger = logging.getLogger("BehaviorMonitor.FileMonitor")


class FileMonitorHandler(FileSystemEventHandler):
    """
    Handles file system events and identifies processes responsible for operations.
    
    This class tracks file operations, identifies responsible processes,
    and analyzes file modifications for potential ransomware behavior.
    """
    
    def __init__(self):
        """Initialize the file monitor with required data structures."""
        super().__init__()
        logger.info("Initializing FileMonitorHandler")
        
        # Core data structures
        self.process_cache: Dict = {}
        self.directory_activity: Dict = defaultdict(list)
        self.process_activity: Dict = defaultdict(int)
        self.last_modification_time: Dict = {}
        self.sequential_operations: Dict = defaultdict(int)
        
        # Start background monitoring
        self._start_process_refresher()

    # -------------------- Process Cache Management --------------------

    def _start_process_refresher(self) -> None:
        """Start a background thread to continuously refresh the process cache."""
        def refresh():
            while True:
                try:
                    self._refresh_process_cache()
                    time.sleep(1.5)
                except Exception as e:
                    logger.error(f"Process cache refresh failed: {e}")
                    time.sleep(3)
        
        thread = threading.Thread(target=refresh, daemon=True)
        thread.name = "ProcessCacheRefresher"
        thread.start()
        logger.info("Started background thread to refresh process cache")

    def _refresh_process_cache(self) -> None:
        """Refresh the cache of running processes and their details."""
        cache = {}
        process_activity = defaultdict(int)
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'cpu_percent']):
            try:
                pid = proc.info['pid']
                proc_name = proc.info['name']
                
                # Skip ignored processes
                if proc_name.lower() in [p.lower() for p in IGNORED_PROCESSES]:
                    continue
                
                # Get process details
                cmdline = proc.info.get('cmdline', [])
                cmdline_str = ' '.join(str(arg) for arg in cmdline) if cmdline and isinstance(cmdline, (list, tuple)) else ''
                open_files = set()
                accessed_dirs = set()
                
                # Only gather file details for non-system processes
                try:
                    if pid > 1000:  # Heuristic for user processes
                        for file in proc.open_files():
                            open_files.add(file.path)
                            accessed_dirs.add(os.path.dirname(file.path))
                        
                        # Track CPU activity
                        cpu = proc.cpu_percent(interval=0.1)
                        if cpu > 0:
                            process_activity[pid] += 1
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Store process information
                cache[pid] = {
                    'name': proc_name,
                    'exe': proc.info.get('exe', ''),
                    'cmdline': cmdline_str,
                    'username': proc.info.get('username', ''),
                    'last_seen': datetime.now(),
                    'open_files': open_files,
                    'accessed_dirs': accessed_dirs,
                    'is_suspicious': False  # Placeholder for future enhancement
                }
                
                # Update directory activity tracking
                for dir_path in accessed_dirs:
                    if dir_path in self.directory_activity:
                        if pid not in [p for p, _ in self.directory_activity[dir_path]]:
                            self.directory_activity[dir_path].append((pid, datetime.now()))
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        # Update our data structures
        self.process_cache = cache
        self.process_activity = process_activity
        self._clean_directory_activity()
        
        logger.debug(f"Refreshed process cache: {len(cache)} processes")

    def _clean_directory_activity(self) -> None:
        """Remove old entries from directory activity tracking."""
        now = datetime.now()
        cutoff = SEQUENTIAL_TIME_WINDOW * 2
        
        for dir_path in list(self.directory_activity.keys()):
            # Remove entries older than cutoff time
            self.directory_activity[dir_path] = [
                (pid, ts) for pid, ts in self.directory_activity[dir_path]
                if (now - ts).total_seconds() < cutoff
            ]
            
            # Remove empty directory entries
            if not self.directory_activity[dir_path]:
                del self.directory_activity[dir_path]

    # -------------------- Event Handling --------------------

    def on_any_event(self, event) -> None:
        """
        Process any filesystem event.
        
        This is the main entry point for filesystem events, handling all
        types of file operations and routing them for processing.
        """
        try:
            path = event.src_path
            if self._should_ignore(path):
                return
                
            start = datetime.now()
            dir_path = os.path.dirname(path)
            
            # Track sequential activity
            self._update_activity_tracking(dir_path, start)
            
            logger.info(f"[{start.strftime('%H:%M:%S.%f')[:-3]}] {event.event_type}: {path}")
            
            # Find responsible process
            pid = self._identify_process(path, event.event_type, start)
            elapsed = (datetime.now() - start).total_seconds()
            
            # Process the event based on identification result
            if pid is not None:
                self._process_identified_event(pid, event, path, elapsed)
            else:
                self._process_unidentified_event(dir_path, event, path, start, elapsed)
                
        except Exception as e:
            logger.error(f"Exception in event handler: {e}", exc_info=True)

    def _should_ignore(self, path: str) -> bool:
        """Determine if a file event should be ignored based on path patterns."""
        ignore_patterns = [
            '\\Prefetch\\', '\\AppData\\Local\\Temp\\', '\\WindowsApps\\',
            '.etl', '.log', '.tmp', '.temp', '\\Cookies\\', '\\History\\', '\\Recent\\'
        ]
        return any(p in path for p in ignore_patterns)

    def _update_activity_tracking(self, dir_path: str, timestamp: datetime) -> None:
        """Update directory activity tracking with new event."""
        self.last_modification_time[dir_path] = timestamp
        
        # Track sequential operations
        if dir_path in self.sequential_operations:
            # If operations are within time window, increment counter
            time_diff = (timestamp - self.last_modification_time.get(dir_path, datetime.min)).total_seconds()
            if time_diff < SEQUENTIAL_TIME_WINDOW:
                self.sequential_operations[dir_path] += 1
            else:
                # Reset if too much time has passed
                self.sequential_operations[dir_path] = 1
        else:
            self.sequential_operations[dir_path] = 1
            
        # Alert on high sequential activity
        if self.sequential_operations[dir_path] >= SEQUENTIAL_FILE_THRESHOLD:
            logger.warning(
                f"High sequential activity detected in {dir_path}: "
                f"{self.sequential_operations[dir_path]} operations"
            )

    def _process_identified_event(self, pid: int, event, path: str, elapsed: float) -> None:
        """Process an event where we identified the responsible process."""
        proc = self.process_cache.get(pid, {})
        logger.info(
            f"Detected process {pid} ({proc.get('name', 'unknown')}) -> "
            f"{event.event_type} {path} [resolved in {elapsed:.2f}s]"
        )
        
        self._record_event(pid, event)
        self._log_stats(pid)
        
        # Update directory activity tracking
        dir_path = os.path.dirname(path)
        self.directory_activity[dir_path].append((pid, datetime.now()))

    def _process_unidentified_event(self, dir_path: str, event, path: str, start: datetime, elapsed: float) -> None:
        """Process an event where we couldn't directly identify the responsible process."""
        logger.warning(f"Could not directly determine process for {path} after {elapsed:.2f}s")
        
        # Try heuristic identification
        heuristic_pid = self._identify_by_heuristics(dir_path, start)
        
        if heuristic_pid:
            proc = self.process_cache.get(heuristic_pid, {})
            logger.info(
                f"Identified likely process {heuristic_pid} "
                f"({proc.get('name', 'unknown')}) for {path} using heuristics"
            )
            self._record_event(heuristic_pid, event)
            self._log_stats(heuristic_pid)
        else:
            # No process identified
            logger.info(f"Active processes: {self._active_processes_snapshot()}")
            self._record_event(-1, event)  # Use -1 to indicate unknown process

    # -------------------- Process Identification Strategies --------------------

    def _identify_process(self, path: str, event_type: str, event_time: datetime) -> Optional[int]:
        """
        Try multiple strategies to identify the process responsible for a file event.
        
        Returns the process ID if found, None otherwise.
        """
        start_time = datetime.now()
        
        # Define identification strategies in order of reliability
        strategies = [
            (self._check_cache_for_file, 0.2),       # Check process cache first (fastest)
            (self._check_open_files, 0.5),           # Check open file handles
            (self._check_directory_activity, 0.7),   # Check recent directory activity
            (self._check_active_processes, 0.8),     # Check processes with high activity
        ]
        
        # Try each strategy until we identify a process or run out of time
        for strategy_func, timeout_fraction in strategies:
            # Check if we've exceeded the time budget for this strategy
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > PROCESS_IDENTIFICATION_TIMEOUT * timeout_fraction:
                if VERBOSE_PROCESS_IDENTIFICATION:
                    logger.debug(f"Skipping {strategy_func.__name__} due to timeout")
                continue
                
            # Try this strategy
            pid = strategy_func(path, event_time)
            if pid is not None:
                if VERBOSE_PROCESS_IDENTIFICATION:
                    logger.debug(f"Process {pid} identified via {strategy_func.__name__}")
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
                # Skip system processes and ignored processes
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
            # Get processes active in this directory within time window
            recent_procs = sorted(
                [(pid, ts) for pid, ts in self.directory_activity[dir_path]
                 if (event_time - ts).total_seconds() < SEQUENTIAL_TIME_WINDOW],
                key=lambda x: x[1],  # Sort by timestamp
                reverse=True         # Most recent first
            )
            
            if recent_procs:
                return recent_procs[0][0]  # Return most recent process
        return None

    def _check_active_processes(self, path: str, event_time: datetime) -> Optional[int]:
        """Check processes with high activity levels."""
        if self.process_activity:
            # Sort processes by activity level
            active_procs = sorted(
                self.process_activity.items(), 
                key=lambda x: x[1],  # Sort by activity count
                reverse=True         # Highest activity first
            )
            
            # Return first active process still in cache
            for pid, activity in active_procs:
                if activity > 0 and pid in self.process_cache:
                    return pid
        return None

    def _check_suspicious_processes(self, path: str, event_time: datetime) -> Optional[int]:
        """Check if any suspicious processes are running."""
        for pid, info in self.process_cache.items():
            if info.get('is_suspicious', False):
                return pid
        return None

    def _identify_by_heuristics(self, dir_path: str, event_time: datetime) -> Optional[int]:
        """
        Use heuristics to identify the likely process responsible for file activity.
        
        Returns the process ID of the best candidate or None if no good candidate found.
        """
        candidates = []
        
        # Heuristic 1: Processes that accessed this directory recently
        if dir_path in self.directory_activity:
            for pid, ts in self.directory_activity[dir_path]:
                if (event_time - ts).total_seconds() < SEQUENTIAL_TIME_WINDOW:
                    # Recent activity gets a high score
                    time_diff = (event_time - ts).total_seconds()
                    score = 10 - time_diff  # Higher score for more recent activity
                    candidates.append((pid, score))

        # Heuristic 2: Processes with high activity levels
        for pid, activity in self.process_activity.items():
            if pid in self.process_cache:
                # Activity level contributes to score
                score = min(activity, 5)
                # Add more score for suspicious processes
                if self.process_cache[pid].get('is_suspicious', False):
                    score += 5
                candidates.append((pid, score))

        # Heuristic 3: Processes that have accessed similar directories
        for pid, info in self.process_cache.items():
            if dir_path in info.get('accessed_dirs', set()):
                candidates.append((pid, 8))  # High score for directory match
                
        # If we have candidates, calculate total scores and return best match
        if candidates:
            # Group by PID and sum scores
            pid_scores = defaultdict(float)
            for pid, score in candidates:
                pid_scores[pid] += score
                
            # Return PID with highest score
            if pid_scores:
                return max(pid_scores.items(), key=lambda x: x[1])[0]
            
        return None

    # -------------------- Event Recording and Analysis --------------------

    def _record_event(self, pid: int, event) -> None:
        """Record a file event for a specific process in the process data store."""
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
            # Analyze file content if it exists
            if os.path.exists(path) and os.path.isfile(path):
                self._analyze_file(pid, path, now)

    def _log_stats(self, pid: int) -> None:
        """Log statistics about a process's file activity."""
        if pid in process_data:
            d = process_data[pid]
            logger.info(
                f"PID {pid} activity -> "
                f"ops: {len(d['file_ops'])}, "
                f"del: {len(d['deletions'])}, "
                f"writes: {len(d['file_writes'])}, "
                f"enc: {len(d['encrypted_writes'])}, "
                f"weird: {len(d['weird_ext_writes'])}, "
                f"critical: {len(d['critical_access'])}"
            )

    def _analyze_file(self, pid: int, path: str, timestamp: datetime) -> None:
        """Analyze a file for suspicious properties (encryption, extensions, location)."""
        # Check for encrypted content
        if self._is_encrypted(path):
            process_data[pid]['encrypted_writes'].append((timestamp, path))
            logger.warning(f"Encrypted file suspected from PID {pid}: {path}")
        
        # Check for suspicious extensions
        ext = os.path.splitext(path)[1].lower()
        if ext in WEIRD_EXTENSIONS:
            process_data[pid]['weird_ext_writes'].append((timestamp, path))
            logger.warning(f"Suspicious extension {ext} from PID {pid}: {path}")
        
        # Check if file is in a critical system path
        self._check_critical_path(pid, path, timestamp)

    def _check_critical_path(self, pid: int, path: str, timestamp: datetime) -> None:
        """Check if a file is in a critical system path."""
        for critical in CRITICAL_SYSTEM_PATHS:
            if path.lower().startswith(critical.lower()):
                process_data[pid]['critical_access'].append((timestamp, path))
                logger.warning(f"Critical system path accessed by PID {pid}: {path}")
                break

    def _is_encrypted(self, path: str) -> bool:
        """
        Check if a file might be encrypted based on entropy.
        
        High entropy (> 7.8) suggests encryption or compression.
        """
        try:
            # Skip small files or non-existent files
            if not os.path.isfile(path) or os.path.getsize(path) < 512:
                return False
                
            # Read a sample of the file
            with open(path, 'rb') as f:
                data = f.read(8192)  # 8KB sample size
            
            # Calculate Shannon entropy
            entropy = 0.0
            if data:
                byte_counts = [data.count(i) for i in range(256)]
                filesize = len(data)
                for count in byte_counts:
                    if count > 0:
                        probability = count / filesize
                        entropy -= probability * math.log2(probability)
            
            # High entropy suggests encryption or compression
            return entropy > 7.8
            
        except Exception:
            return False

    def _active_processes_snapshot(self) -> str:
        """Get a formatted snapshot of active processes for logging."""
        try:
            procs = []
            # Filter for relevant processes
            for pid, info in self.process_cache.items():
                if (pid > 1000 and 
                    info.get('username') and 
                    info.get('name').lower() not in [p.lower() for p in IGNORED_PROCESSES]):
                    
                    name = info.get('name', 'unknown')
                    # Mark suspicious processes with an asterisk
                    if info.get('is_suspicious', False):
                        procs.append(f"{pid}:{name}*")
                    else:
                        procs.append(f"{pid}:{name}")
            
            # Sort and format output
            procs.sort(key=lambda x: int(x.split(':')[0]))
            result = ', '.join(procs[:20])
            if len(procs) > 20:
                result += '...'
                
            return result
            
        except Exception:
            return 'Unavailable'