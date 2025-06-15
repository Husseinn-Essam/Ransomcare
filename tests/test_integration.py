import os
import time
import pytest
import tempfile
import shutil
import subprocess
import psutil
import threading
import platform
from pathlib import Path

from ransomcare.behavior_monitor import BehaviorMonitor
from ransomcare.file_monitor import FileMonitorHandler
from ransomcare.config import process_data, flagged_processes, THRESHOLD

class TestIntegration:
    """Integration tests for the Ransomcare system."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        test_dir = tempfile.mkdtemp()
        yield test_dir
        shutil.rmtree(test_dir)
    
    @pytest.fixture
    def behavior_monitor(self):
        """Create a behavior monitor instance with file monitoring disabled for testing."""
        process_data.clear()
        flagged_processes.clear()
        
        monitor = BehaviorMonitor(enable_file_monitor=False, enable_process_monitor=True)
        yield monitor
        
        # Clean up
        if monitor.running:
            monitor.stop_monitoring()
    
    def test_behavior_monitor_initialization(self):
        """Test that the behavior monitor initializes correctly."""
        process_data.clear()
        flagged_processes.clear()
        
        monitor = BehaviorMonitor(enable_file_monitor=False, enable_process_monitor=False)
        assert monitor is not None
        assert monitor.enable_file_monitor == False
        assert monitor.enable_process_monitor == False
        assert monitor.running == False
        
    def test_start_stop_monitoring(self):
        """Test starting and stopping the monitoring process."""
        process_data.clear()
        flagged_processes.clear()
        
        monitor = BehaviorMonitor(enable_file_monitor=False, enable_process_monitor=True)
        monitor.start_monitoring()
        assert monitor.running == True
        
        time.sleep(1)
        
        monitor.stop_monitoring()
        assert monitor.running == False
    
    def test_real_process_monitoring(self, behavior_monitor, temp_dir):
        """Test monitoring of real processes."""
        behavior_monitor.start_monitoring()
        time.sleep(1)  
        
        script_path = os.path.join(temp_dir, "test_script.py")
        with open(script_path, "w") as f:
            f.write("""
import os
import time
import sys

# Get the directory to work in
test_dir = sys.argv[1]

# Create multiple files
for i in range(10):
    file_path = os.path.join(test_dir, f"test_file_{i}.txt")
    with open(file_path, "w") as f:
        f.write(f"Content for file {i}")
    
    # Small delay
    time.sleep(0.1)

# Modify files
for i in range(10):
    file_path = os.path.join(test_dir, f"test_file_{i}.txt")
    with open(file_path, "a") as f:
        f.write("\\nModified content")
    time.sleep(0.1)

# Delete some files
for i in range(5):
    file_path = os.path.join(test_dir, f"test_file_{i}.txt")
    os.remove(file_path)
    time.sleep(0.1)
""")
        
        process = None
        try:
            python_exe = sys.executable if 'sys' in globals() else 'python'
            
            process = subprocess.Popen([python_exe, script_path, temp_dir])
            
            time.sleep(3)
            
            pid = process.pid
            assert pid in process_data, f"Process {pid} not found in process_data"
            
            time.sleep(1)  
            assert len(process_data[pid]['file_writes']) > 0, "No file writes recorded"
            assert len(process_data[pid]['deletions']) > 0, "No deletions recorded"
            
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    
    def test_score_calculation(self, behavior_monitor):
        """Test the process scoring system with actual data."""
        test_pid = 99999  #
        from datetime import datetime
        from collections import deque
        
        now = datetime.now()
        process_data[test_pid] = {
            "file_ops": deque([(now, "file1.txt"), (now, "file2.txt"), (now, "file3.txt")], maxlen=100),
            "deletions": deque([(now, "deleted1.txt"), (now, "deleted2.txt")], maxlen=100),
            "file_writes": deque([(now, "written1.txt"), (now, "written2.txt")], maxlen=100),
            "cpu_history": deque([(now, 80.0), (now, 85.0)], maxlen=20),
            "encrypted_writes": deque([(now, "encrypted1.txt")], maxlen=100),
            "weird_ext_writes": deque([(now, "suspicious.locky")], maxlen=100),
            "critical_access": deque([(now, r"C:\Windows\System32\test.dll")], maxlen=100),
            "timestamp": now,
            "last_scores": deque(maxlen=10)
        }
        
        class MockProcess:
            def __init__(self):
                self.pid = test_pid
                self.name = lambda: "test_process.exe"
                
        mock_process = MockProcess()
        
        score = behavior_monitor._calculate_score(test_pid, mock_process)
        
        assert score > 0, "Score calculation failed to produce a positive score"
        
        component_scores = {}
        window_start = now.timestamp() - 60  
        
        file_mod_score = behavior_monitor._score_file_modifications(
            test_pid, process_data[test_pid], window_start, component_scores
        )
        assert file_mod_score > 0, "File modification score should be positive"
        
        deletion_score = behavior_monitor._score_file_deletions(
            test_pid, process_data[test_pid], window_start, component_scores
        )
        assert deletion_score > 0, "Deletion score should be positive"
        
        del process_data[test_pid]
    
