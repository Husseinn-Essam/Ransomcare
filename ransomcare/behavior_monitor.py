#!/usr/bin/env python3
"""
Main behavior monitoring component for the Behavioral Monitor
"""

from collections import deque
import sys
import time
import threading
import psutil
import os
from datetime import datetime
from watchdog.observers import Observer

from ransomcare.config import (
    logger, process_data, flagged_processes, THRESHOLD, MONITOR_INTERVAL, 
    HISTORY_WINDOW, WEIGHTS, CRITICAL_SYSTEM_PATHS, IGNORED_PROCESSES
)
from ransomcare.file_monitor import FileMonitorHandler

class BehaviorMonitor:
    """
    Main monitoring class that coordinates all monitors and evaluates behavior.
    
    This class handles file system and process monitoring, behavioral analysis,
    and detection of potentially malicious activities.
    """
    
    def __init__(self, enable_file_monitor=True, enable_process_monitor=True):
        """
        Initialize the behavior monitor.
        
        Args:
            enable_file_monitor (bool): Whether to enable file system monitoring
            enable_process_monitor (bool): Whether to enable process monitoring
        """
        self.file_monitor = None
        self.observer = None
        self.running = False
        self.enable_file_monitor = enable_file_monitor
        self.enable_process_monitor = enable_process_monitor
        self.file_monitor_handlers = []
        
    def start_monitoring(self):
        """Start all enabled monitoring components."""
        logger.info("Starting behavior monitoring system")
        self.running = True
        
        # Start file system monitoring if enabled
        if self.enable_file_monitor:
            self._start_file_monitoring()
        else:
            logger.info("File monitoring disabled")
        
        # Start the main monitoring loop
        monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitor_thread.start()
        
        logger.info("Behavior monitoring started successfully")
        
    def _start_file_monitoring(self):
        """Set up and start the file system monitoring."""
        self.observer = Observer()
        
        # Validate and setup monitoring for each path
        for path in self._get_available_drives():
            try:
                if os.path.exists(path) and os.path.isdir(path):
                    file_handler = FileMonitorHandler()
                    self.file_monitor_handlers.append(file_handler)
                    
                    logger.info(f"Watching folder: {path}")
                    self.observer.schedule(file_handler, path, recursive=True)
                else:
                    logger.warning(f"Path does not exist or is not a directory: {path}")
            except Exception as e:
                logger.error(f"Could not monitor path {path}: {str(e)}")
        
        if self.file_monitor_handlers:
            try:
                self.observer.start()
                logger.info(f"File monitoring enabled with {len(self.file_monitor_handlers)} handlers")
            except Exception as e:
                logger.error(f"Failed to start file monitoring observer: {str(e)}")
        else:
            logger.warning("No valid paths to monitor. File monitoring disabled.")
        
    def stop_monitoring(self):
        """Stop all monitoring components cleanly."""
        self.running = False
        
        # Stop file monitoring
        if self.observer and self.enable_file_monitor:
            try:
                self.observer.stop()
                self.observer.join()
                logger.info("File monitoring stopped")
            except Exception as e:
                logger.error(f"Error stopping file monitoring: {str(e)}")
        
        logger.info("Behavior monitoring stopped")
        
    def _monitoring_loop(self):
        """
        Main monitoring loop that periodically evaluates process behaviors.
        This runs in a separate thread and continues until stopped.
        """
        logger.info(f"Starting monitoring loop with interval of {MONITOR_INTERVAL} seconds")
        
        while self.running:
            try:
                # Skip process monitoring if disabled
                if not self.enable_process_monitor:
                    time.sleep(MONITOR_INTERVAL)
                    continue
                    
                # Log the start of each monitoring cycle
                cycle_start = datetime.now()
                logger.debug(f"Starting monitoring cycle at {cycle_start.strftime('%H:%M:%S')}")
                
                process_count, flagged_count = self._scan_active_processes()
                
                # Log summary for this cycle
                cycle_duration = (datetime.now() - cycle_start).total_seconds()
                logger.info(f"Monitoring cycle complete: {process_count} processes checked, "
                           f"{flagged_count} processes flagged in {cycle_duration:.2f} seconds")
                        
                # Clean up old process data
                removed_count = self._clean_old_data()
                logger.debug(f"Cleaned up {removed_count} terminated processes from monitoring data")
                        
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}", exc_info=True)
                
            time.sleep(MONITOR_INTERVAL)
    
    def _scan_active_processes(self):
        """
        Scan and analyze all active processes.
        
        Returns:
            tuple: (process_count, flagged_count) - Number of processes scanned and flagged
        """
        process_count = 0
        flagged_count = 0
        disk_io_threshold = 10 * 1024 * 1024  # Example: 10MB threshold for disk I/O

        # Scan all active processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
            try:
                pid = proc.pid
                
                # Skip system and ignored processes
                if pid < 10 or proc.name() in ['System', 'Registry', 'Memory Compression'] or proc.name() in IGNORED_PROCESSES:
                    continue

                # Check disk I/O activity
                try:
                    io_counters = proc.io_counters()
                    if io_counters.read_bytes + io_counters.write_bytes < disk_io_threshold:
                        continue  # Skip processes with low disk usage
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                
                process_count += 1
                logger.debug(f"Monitoring process: {pid} ({proc.name()})")
                
                # Initialize process data structure if not exists
                self._initialize_process_data(pid)
                
                # Record CPU usage
                process_data[pid]["cpu_history"].append((datetime.now(), proc.cpu_percent()))
                
                # Calculate behavior score for this process
                score = self._calculate_score(pid, proc)
                logger.debug(f"Process {pid} ({proc.name()}) score: {score:.2f}")
                
                # Ensure last_scores exists
                if "last_scores" not in process_data[pid]:
                    process_data[pid]["last_scores"] = deque(maxlen=10)
                    
                process_data[pid]["last_scores"].append(score)
                
                # Check if score exceeds threshold
                if score >= THRESHOLD and pid not in flagged_processes:
                    logger.warning(f"Process {pid} ({proc.name()}) exceeded threshold with score {score:.2f}")
                    self._handle_malicious_process(pid, proc, score)
                    flagged_count += 1
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.error(f"Error monitoring process {pid}: {str(e)}", exc_info=True)
        
        return process_count, flagged_count

    def _initialize_process_data(self, pid):
        """
        Initialize the data structure for a new process if it doesn't exist.
        
        Args:
            pid (int): Process ID to initialize
        """
        if pid not in process_data:
            process_data[pid] = {
                "file_ops": deque(maxlen=100),
                "deletions": deque(maxlen=100),
                "file_writes": deque(maxlen=100),
                "cpu_history": deque(maxlen=20),
                "encrypted_writes": deque(maxlen=100),
                "weird_ext_writes": deque(maxlen=100),
                "critical_access": deque(maxlen=100),
                "timestamp": datetime.now()
            }
####################### SCORE CALCULATION #############################################################################    
    def _calculate_score(self, pid, proc):
        """
        Calculate the malicious behavior score for a process.
        
        Args:
            pid (int): Process ID
            proc (psutil.Process): Process object
            
        Returns:
            float: Calculated maliciousness score
        """
        try:
            data = process_data[pid]
            now = datetime.now()
            window_start = now.timestamp() - HISTORY_WINDOW
            
            # Dictionary to store component scores for logging
            component_scores = {}
            total_score = 0
            
            # Calculate scores for various behavioral components
            total_score += self._score_file_modifications(pid, data, window_start, component_scores)
            total_score += self._score_file_deletions(pid, data, window_start, component_scores)
            total_score += self._score_file_writes(pid, data, window_start, component_scores)
            total_score += self._score_cpu_usage(pid, data, component_scores)
            total_score += self._score_encrypted_writes(pid, data, window_start, component_scores)
            total_score += self._score_suspicious_extensions(pid, data, window_start, component_scores)
            total_score += self._score_critical_access(pid, data, window_start, component_scores)
            total_score += self._score_disk_usage(pid,data,component_scores)
            # Log the final score breakdown if it's significant
            if total_score > 0:
                logger.info(f"Process {pid} ({proc.name()}) score breakdown: {component_scores}, total: {total_score:.2f}")
            
            return total_score
            
        except Exception as e:
            logger.error(f"Error calculating score for process {pid}: {str(e)}", exc_info=True)
            return 0
    
    def _score_file_modifications(self, pid, data, window_start, component_scores):
        """Calculate score component for rapid file modifications."""
        recent_mods = sum(1 for ts, _ in data.get("file_ops", []) if ts.timestamp() > window_start)
        if recent_mods > 0:  # Changed from 20 to catch any modifications
            mod_score = min(recent_mods / 5, 10) * WEIGHTS["rapid_file_modification"] / 10
            component_scores["rapid_file_modification"] = mod_score
            logger.debug(f"PID {pid}: {recent_mods} file modifications in window, score: {mod_score:.2f}")
            return mod_score
        return 0
    
    def _score_file_deletions(self, pid, data, window_start, component_scores):
        """Calculate score component for mass file deletions."""
        recent_dels = sum(1 for ts, _ in data.get("deletions", []) if ts.timestamp() > window_start)
        if recent_dels > 0:  # Changed from 10 to catch any deletions
            del_score = min(recent_dels / 2, 10) * WEIGHTS["mass_deletion"] / 10
            component_scores["mass_deletion"] = del_score
            logger.debug(f"PID {pid}: {recent_dels} file deletions in window, score: {del_score:.2f}")
            return del_score
        return 0
    
    def _score_file_writes(self, pid, data, window_start, component_scores):
        """Calculate score component for mass file writes."""
        recent_writes = sum(1 for ts, _ in data.get("file_writes", []) if ts.timestamp() > window_start)
        if recent_writes > 0:  # Changed from 30 to catch any writes
            write_score = min(recent_writes / 10, 10) * WEIGHTS["mass_file_writes"] / 10
            component_scores["mass_file_writes"] = write_score
            logger.debug(f"PID {pid}: {recent_writes} file writes in window, score: {write_score:.2f}")
            return write_score
        return 0
    
    def _score_cpu_usage(self, pid, data, component_scores):
        """Calculate score component for high CPU usage."""
        cpu_values = [cpu for _, cpu in data.get("cpu_history", []) if cpu > 0]
        if cpu_values:
            avg_cpu = sum(cpu_values) / len(cpu_values)
            # Lower threshold to catch more potentially suspicious CPU usage
            if avg_cpu > 30:  # Changed from 70 to be more sensitive
                cpu_score = min(avg_cpu / 10, 10) * WEIGHTS["high_cpu_usage"] / 10
                component_scores["high_cpu_usage"] = cpu_score
                logger.debug(f"PID {pid}: Average CPU {avg_cpu:.1f}%, score: {cpu_score:.2f}")
                return cpu_score
        return 0

    def _score_disk_usage(self, pid, data, component_scores):
        """Calculate score component for high disk I/O operations."""
        try:
            proc = psutil.Process(pid)
            io_counters = proc.io_counters()
            total_read_bytes = io_counters.read_bytes
            total_write_bytes = io_counters.write_bytes

            # Combined I/O rate (with higher weight for writes)
            combined_rate_mb = (total_write_bytes * 2 + total_read_bytes) / (1024 * 1024)

            if combined_rate_mb > 0:
                # Score scales with I/O rate, capped at 10
                disk_score = min(combined_rate_mb / 2, 10) * WEIGHTS["high_disk_usage"] / 10
                component_scores["high_disk_usage"] = disk_score
                logger.debug(f"PID {pid}: Disk I/O {combined_rate_mb:.1f} MB, score: {disk_score:.2f}")
                return disk_score

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.debug(f"Unable to access disk I/O for PID {pid}")
            return 0

        return 0

    def _score_encrypted_writes(self, pid, data, window_start, component_scores):
        """Calculate score component for encrypted file writes."""
        recent_enc = sum(1 for ts, _ in data.get("encrypted_writes", []) if ts.timestamp() > window_start)
        if recent_enc > 0:
            enc_score = min(recent_enc * 2, 10) * WEIGHTS["encrypted_file_writes"] / 10
            component_scores["encrypted_file_writes"] = enc_score
            logger.debug(f"PID {pid}: {recent_enc} encrypted writes in window, score: {enc_score:.2f}")
            return enc_score
        return 0
    
    def _score_suspicious_extensions(self, pid, data, window_start, component_scores):
        """Calculate score component for writes with suspicious file extensions."""
        recent_weird = sum(1 for ts, _ in data.get("weird_ext_writes", []) if ts.timestamp() > window_start)
        if recent_weird > 0:
            weird_score = min(recent_weird * 2, 10) * WEIGHTS["weird_extension_writes"] / 10
            component_scores["weird_extension_writes"] = weird_score
            logger.debug(f"PID {pid}: {recent_weird} suspicious extensions in window, score: {weird_score:.2f}")
            return weird_score
        return 0
    
    def _score_critical_access(self, pid, data, window_start, component_scores):
        """Calculate score component for access to critical system paths."""
        recent_crit = sum(1 for ts, _ in data.get("critical_access", []) if ts.timestamp() > window_start)
        if recent_crit > 0:
            crit_score = min(recent_crit * 2, 10) * WEIGHTS["critical_system_access"] / 10
            component_scores["critical_system_access"] = crit_score
            logger.debug(f"PID {pid}: {recent_crit} critical system accesses in window, score: {crit_score:.2f}")
            return crit_score
        return 0
###########################################################################################################################   
    def _handle_malicious_process(self, pid, proc, score):
        """
        Handle a process that has been flagged as potentially malicious.
        
        Args:
            pid (int): Process ID
            proc (psutil.Process): Process object
            score (float): Calculated maliciousness score
        """
        try:
            # Get process details for logging
            process_details = self._get_process_details(pid, proc)
            
            # Log complete process information
            self._log_malicious_process(pid, proc, score, process_details)
            
            # Add to flagged set to avoid duplicate actions
            flagged_processes.add(pid)
            logger.warning(f"Added PID {pid} to flagged processes list. Current count: {len(flagged_processes)}")
            
            # Kill the process
            try:
                logger.critical(f"Attempting to terminate process {pid}...")
                proc.kill()
                logger.critical(f"Successfully terminated malicious process {pid}")
            except Exception as e:
                logger.critical(f"Failed to terminate process {pid}: {str(e)}", exc_info=True)
                
        except Exception as e:
            logger.error(f"Error handling malicious process {pid}: {str(e)}", exc_info=True)
    
    def _get_process_details(self, pid, proc):
        """Collect detailed information about a process."""
        try:
            return {
                "exe_path": proc.exe() if hasattr(proc, 'exe') else "Unknown",
                "creation_time": datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S') 
                                if hasattr(proc, 'create_time') else "Unknown",
                "cmdline": " ".join(proc.cmdline()) if hasattr(proc, 'cmdline') else "Unknown",
                "username": proc.username() if hasattr(proc, 'username') else "Unknown",
                "name": proc.name() if hasattr(proc, 'name') else "Unknown"
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"Could not get all process details for PID {pid}: {str(e)}")
            return {
                "exe_path": "Unknown",
                "creation_time": "Unknown",
                "cmdline": "Unknown",
                "username": "Unknown",
                "name": "Unknown"
            }
    
    def _log_malicious_process(self, pid, proc, score, details):
        """Log detailed information about a detected malicious process."""
        # Log complete process information
        logger.warning(f"MALICIOUS PROCESS DETECTED:")
        logger.warning(f"  PID: {pid}")
        logger.warning(f"  Name: {details['name']}")
        logger.warning(f"  Path: {details['exe_path']}")
        logger.warning(f"  User: {details['username']}")
        logger.warning(f"  Started: {details['creation_time']}")
        logger.warning(f"  Command Line: {details['cmdline']}")
        logger.warning(f"  Malicious Score: {score:.2f}")
        
        # Log behavior details that contributed to flagging
        if pid in process_data:
            self._log_process_activity(pid)
        
        # Log to console for immediate attention
        print(f"\n[!] MALICIOUS PROCESS DETECTED: PID {pid} ({details['name']})")
        print(f"    Path: {details['exe_path']}")
        print(f"    Score: {score:.2f}\n")
    
    def _log_process_activity(self, pid):
        """Log recent activity for a process."""
        data = process_data[pid]
        now = datetime.now()
        window_start = now.timestamp() - HISTORY_WINDOW
        
        recent_ops = sum(1 for ts, _ in data.get("file_ops", []) if ts.timestamp() > window_start)
        recent_dels = sum(1 for ts, _ in data.get("deletions", []) if ts.timestamp() > window_start)
        recent_writes = sum(1 for ts, _ in data.get("file_writes", []) if ts.timestamp() > window_start)
        recent_enc = sum(1 for ts, _ in data.get("encrypted_writes", []) if ts.timestamp() > window_start)
        
        logger.warning(f"  Recent Activity: {recent_ops} modifications, {recent_dels} deletions, "
                      f"{recent_writes} writes, {recent_enc} encrypted files")
        
        # Log specific files that were accessed if available
        recent_files = []
        for ts, path in list(data.get("file_ops", []))[-5:]:
            if ts.timestamp() > window_start:
                recent_files.append(path)
        if recent_files:
            logger.warning(f"  Recent accessed files: {', '.join(recent_files)}")
    
    def _clean_old_data(self):
        """
        Clean up data for processes that no longer exist.
        
        Returns:
            int: Number of processes removed from tracking
        """
        current_pids = set(p.pid for p in psutil.process_iter())
        removed_count = 0
        
        for pid in list(process_data.keys()):
            if pid not in current_pids:
                # Process no longer exists
                if pid in flagged_processes:
                    logger.info(f"Removing terminated flagged process {pid} from tracking")
                    flagged_processes.remove(pid)
                else:
                    logger.debug(f"Removing terminated process {pid} from tracking")
                
                # Log some stats before removal
                data = process_data[pid]
                logger.debug(f"Process {pid} final stats: {len(data.get('file_ops', []))} operations, "
                            f"{len(data.get('deletions', []))} deletions, {len(data.get('file_writes', []))} writes")
                
                del process_data[pid]
                removed_count += 1
                
        return removed_count
    
    def _get_available_drives(self):
        """
        Get a list of folders to monitor.
        
        Returns:
            list: List of valid directories to monitor
        """
        valid_paths = []
        
        # Check if all paths in CRITICAL_SYSTEM_PATHS exist
        for path in CRITICAL_SYSTEM_PATHS:
            if os.path.exists(path) and os.path.isdir(path):
                valid_paths.append(path)
            else:
                logger.warning(f"Path in CRITICAL_SYSTEM_PATHS does not exist or is not a directory: {path}")
        
        if not valid_paths:
            logger.warning("No valid paths found in CRITICAL_SYSTEM_PATHS. Falling back to current directory.")
            valid_paths.append(os.getcwd())
            
        return valid_paths

# Main entry point for running the monitor standalone
if __name__ == "__main__":
    try:
        # Create and start the behavior monitor
        monitor = BehaviorMonitor(
            enable_file_monitor=True,
            enable_process_monitor=True
        )
        monitor.start_monitoring()
        
        # Keep the main thread alive
        print("Behavior Monitor started. Press Ctrl+C to exit.")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down Behavior Monitor...")
        if 'monitor' in locals():
            monitor.stop_monitoring()
        print("Shutdown complete.")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)