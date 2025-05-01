import psutil
import os
import logging
import random
import time
import math
import collections
from datetime import datetime
import socket
import struct

# Try to import Windows-specific modules safely
try:
    import winreg
    import win32process
    import win32con
    import win32security
    import win32api
    WINDOWS_MODULES_AVAILABLE = True
except ImportError:
    WINDOWS_MODULES_AVAILABLE = False
    logging.warning("Windows-specific modules not available - some checks will be limited")

logging.basicConfig(filename='bm_log.txt', level=logging.INFO)

# Weight assignment for each feature
FEATURE_WEIGHTS = {
    'rapid_file_modification': 3,
    'mass_deletion': 4,
    'mass_file_writes': 4,
    'high_cpu_usage': 2,
    'high_entropy_files': 5,
    'weird_extensions': 4,
    'unauthorized_sys_access': 3,
    'api_hooks_detected': 5,
    'memory_file_buffers': 4,
    'network_traffic_anomaly': 3,
}

THRESHOLD_SCORE = 10  # Tunable based on testing and calibration

def score_process(proc):
    score = 0

    try:
        # Skip System Idle Process and other system processes that may cause errors
        if proc.pid <= 4:  # System and System Idle Process usually have PIDs 0 and 4
            return
            
        pid = proc.pid
        
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe = "Access Denied"
            
        name = proc.name()
        
        # Make all function calls safe with try/except blocks
        try:
            if detect_rapid_file_modification(pid): 
                score += FEATURE_WEIGHTS['rapid_file_modification']
        except Exception as e:
            logging.debug(f"Error in rapid_file_modification: {e}")
            
        try:
            if detect_mass_deletion(pid): 
                score += FEATURE_WEIGHTS['mass_deletion']
        except Exception as e:
            logging.debug(f"Error in mass_deletion: {e}")
            
        try:
            if detect_mass_file_writes(pid): 
                score += FEATURE_WEIGHTS['mass_file_writes']
        except Exception as e:
            logging.debug(f"Error in mass_file_writes: {e}")
            
        try:
            if is_high_cpu(proc): 
                score += FEATURE_WEIGHTS['high_cpu_usage']
        except Exception as e:
            logging.debug(f"Error in is_high_cpu: {e}")
            
        try:
            if writes_high_entropy_files(pid): 
                score += FEATURE_WEIGHTS['high_entropy_files']
        except Exception as e:
            logging.debug(f"Error in writes_high_entropy_files: {e}")
            
        try:
            if writes_weird_extensions(pid): 
                score += FEATURE_WEIGHTS['weird_extensions']
        except Exception as e:
            logging.debug(f"Error in writes_weird_extensions: {e}")
            
        try:
            if accesses_protected_dirs(pid): 
                score += FEATURE_WEIGHTS['unauthorized_sys_access']
        except Exception as e:
            logging.debug(f"Error in accesses_protected_dirs: {e}")
            
        try:
            if api_hooks_detected(pid): 
                score += FEATURE_WEIGHTS['api_hooks_detected']
        except Exception as e:
            logging.debug(f"Error in api_hooks_detected: {e}")
            
        try:
            if memory_buffer_patterns(pid): 
                score += FEATURE_WEIGHTS['memory_file_buffers']
        except Exception as e:
            logging.debug(f"Error in memory_buffer_patterns: {e}")
            
        try:
            if network_volume_anomaly(pid): 
                score += FEATURE_WEIGHTS['network_traffic_anomaly']
        except Exception as e:
            logging.debug(f"Error in network_volume_anomaly: {e}")

        if score >= THRESHOLD_SCORE:
            logging.info(f"PID: {pid} Whose Executable: {exe} Flagged as Malicious")
            try:
                proc.kill()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                logging.warning(f"Could not kill process {pid} - requires elevation")

    except Exception as e:
        logging.error(f"Failed to score process {proc.pid}: {e}")

def detect_rapid_file_modification(pid):
    try:
        proc = psutil.Process(pid)
        open_files = proc.open_files()
        
        modifications_count = 0
        tracked_files = {}
        
        for file in open_files:
            if os.path.exists(file.path):
                mod_time = os.path.getmtime(file.path)
                current_time = time.time()
                
                if current_time - mod_time < 5:
                    modifications_count += 1
                    
                if file.path in tracked_files:
                    if current_time - tracked_files[file.path] < 30:
                        modifications_count += 2
                
                tracked_files[file.path] = current_time
        
        return modifications_count > 10 
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        # Silent handling for common access issues
        return False
    except Exception as e:
        logging.error(f"Error in rapid file modification detection: {e}")
        return False

def detect_mass_deletion(pid):
    try:
        proc = psutil.Process(pid)
        open_files = proc.open_files()
        
        deletion_count = 0
        checked_dirs = set()
        
        for file in open_files:
            directory = os.path.dirname(file.path)
            
            if directory not in checked_dirs and os.path.exists(directory):
                checked_dirs.add(directory)
                try:
                    before_count = len(os.listdir(directory))
                    time.sleep(0.1)  # Reduced from 1s to 0.1s to avoid long delays
                    after_count = len(os.listdir(directory))
                    
                    if before_count > after_count:
                        deletion_count += (before_count - after_count)
                except (PermissionError, FileNotFoundError):
                    pass
        
        return deletion_count > 5
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False
    except Exception as e:
        logging.error(f"Error in mass deletion detection: {e}")
        return False

def detect_mass_file_writes(pid):
    try:
        proc = psutil.Process(pid)
        open_files = proc.open_files()
        
        write_count = 0
        unique_dirs_written = set()
        
        for file in open_files:
            # Fix for 'popenfile' object has no attribute 'mode'
            # Instead, check if file has write access by examining filename
            # psutil doesn't directly provide file modes in all cases
            try:
                # Check if file path is writable by process
                dir_path = os.path.dirname(file.path)
                unique_dirs_written.add(dir_path)
                
                # Count all file operations as potential writes
                # This is less accurate but prevents the mode attribute error
                write_count += 1
            except Exception:
                pass
        
        return write_count > 15 or len(unique_dirs_written) > 5
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False
    except Exception as e:
        logging.error(f"Error in mass file writes detection: {e}")
        return False

def is_high_cpu(proc):
    try:
        return proc.cpu_percent(interval=0.1) > 80  # Reduced interval for faster scanning
    except:
        return False

def calculate_entropy(data):
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    
    return entropy

def writes_high_entropy_files(pid):
    try:
        proc = psutil.Process(pid)
        open_files = proc.open_files()
        
        for file in open_files:
            if os.path.exists(file.path) and os.path.getsize(file.path) > 0:
                try:
                    with open(file.path, 'rb') as f:
                        data = f.read(8192)
                        entropy = calculate_entropy(data)
                        
                        if entropy > 7.5:
                            return True
                except (PermissionError, FileNotFoundError):
                    pass
        
        return False
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False
    except Exception as e:
        logging.error(f"Error in entropy detection: {e}")
        return False

def writes_weird_extensions(pid):
    suspicious_exts = {'.fun', '.dog', '.wcry', '.locked', '.encrypted', '.crypted', 
                      '.crypt', '.enc', '.locky', '.zepto', '.cerber', '.cerber3', 
                      '.cryptowall', '.aaa', '.ecc', '.ezz', '.exx', '.zzz', 
                      '.xyz', '.abc', '.pzdc', '.2020', '.ctbl', '.djvu'}
    
    try:
        proc = psutil.Process(pid)
        open_files = proc.open_files()
        
        for file in open_files:
            ext = os.path.splitext(file.path)[1].lower()
            if ext in suspicious_exts:
                return True
                
        return False
    except Exception as e:
        logging.error(f"Error in extension detection: {e}")
        return False

def accesses_protected_dirs(pid):
    protected_dirs = [
        os.environ.get('WINDIR', 'C:\\Windows'),
        os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32'),
        os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Syswow64'),
        'C:\\ProgramData',
        'C:\\Program Files',
        'C:\\Program Files (x86)'
    ]
    
    try:
        proc = psutil.Process(pid)
        is_admin = False
        
        if WINDOWS_MODULES_AVAILABLE:
            try:
                proc_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
                token = win32security.OpenProcessToken(proc_handle, win32con.TOKEN_QUERY)
                privileges = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
                
                for priv_id, flags in privileges:
                    if win32security.LookupPrivilegeName(None, priv_id) == "SeDebugPrivilege":
                        is_admin = True
                        break
            except:
                pass
        
        if is_admin:
            return False
            
        open_files = proc.open_files()
        
        for file in open_files:
            file_path = file.path.lower()
            for protected_dir in protected_dirs:
                if file_path.startswith(protected_dir.lower()):
                    return True
                    
        return False
    except Exception as e:
        logging.error(f"Error in protected dir access detection: {e}")
        return False

def api_hooks_detected(pid):
    try:
        if not WINDOWS_MODULES_AVAILABLE:
            return False
        
        system32_dir = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32')
        suspicious_dll_mods = False
        
        important_dlls = ['ntdll.dll', 'kernel32.dll', 'user32.dll', 'advapi32.dll']
        
        for dll in important_dlls:
            dll_path = os.path.join(system32_dir, dll)
            if os.path.exists(dll_path):
                mod_time = os.path.getmtime(dll_path)
                if time.time() - mod_time < 86400:
                    suspicious_dll_mods = True
                    break
        
        return suspicious_dll_mods
    except Exception as e:
        logging.error(f"Error in API hooks detection: {e}")
        return False

def memory_buffer_patterns(pid):
    try:
        patterns = [
            b"encrypt", b"bitcoin", b"ransom", b"payment", 
            b"decrypt", b".onion", b"wallet", b"btc", 
            b"locked", b"files", b"pay", b"restore"
        ]
        
        proc = psutil.Process(pid)
        mem_maps = []
        
        try:
            mem_maps = proc.memory_maps()
        except:
            pass
            
        if mem_maps:
            for mapping in mem_maps:
                if any(pattern in mapping.path.lower().encode() for pattern in patterns):
                    return True
        
        if proc.memory_info().rss > 500 * 1024 * 1024:
            return True
                
        return False
    except Exception as e:
        logging.error(f"Error in memory pattern detection: {e}")
        return False

def network_volume_anomaly(pid):
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind='all')
        
        foreign_ips = set()
        local_ips = set()
        high_ports = 0
        connection_count = 0
        
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                connection_count += 1
                if conn.raddr:
                    foreign_ips.add(conn.raddr.ip)
                    
                    if conn.raddr.port > 49000:
                        high_ports += 1
                        
                if conn.laddr:
                    local_ips.add(conn.laddr.ip)
        
        if connection_count > 15 or len(foreign_ips) > 10 or len(local_ips) > 5 or high_ports > 5:
            return True
                
        return False
    except Exception as e:
        logging.error(f"Error in network anomaly detection: {e}")
        return False

def monitor_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            score_process(proc)
        except Exception as e:
            logging.error(f"Error processing {proc.pid}: {e}")

if __name__ == "__main__":
    try:
        logging.info("Behavioral monitoring started")
        while True:
            monitor_processes()
            time.sleep(1)  # Add a small delay to reduce CPU usage
    except KeyboardInterrupt:
        logging.info("Behavioral monitoring stopped by user")
    except Exception as e:
        logging.critical(f"Monitoring stopped due to error: {e}")
