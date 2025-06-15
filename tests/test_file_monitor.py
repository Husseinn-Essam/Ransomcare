import os
import time
import tempfile
import shutil
import pytest
from pathlib import Path
from datetime import datetime
import random
import string

from ransomcare.file_monitor import FileMonitorHandler
from watchdog.events import FileModifiedEvent, FileCreatedEvent, FileDeletedEvent


class TestFileMonitorHandler:
    """Tests for the FileMonitorHandler class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        test_dir = tempfile.mkdtemp()
        yield test_dir
        # Clean up
        shutil.rmtree(test_dir)
    
    @pytest.fixture
    def file_monitor(self):
        """Create a FileMonitorHandler instance for testing."""
        handler = FileMonitorHandler()
        time.sleep(0.5)
        yield handler

    def test_init(self):
        """Test initialization of FileMonitorHandler."""
        handler = FileMonitorHandler()
        assert handler is not None
        assert isinstance(handler.process_cache, dict)
        assert isinstance(handler.directory_activity, dict)
        assert isinstance(handler.process_activity, dict)
        assert isinstance(handler.last_modification_time, dict)
        assert isinstance(handler.sequential_operations, dict)

    def test_should_ignore(self):
        """Test file path ignore functionality."""
        handler = FileMonitorHandler()
        
        assert handler._should_ignore(r"C:\Windows\Prefetch\something.pf") == True
        assert handler._should_ignore(r"C:\Users\User\AppData\Local\Temp\temp.txt") == True
        
        assert handler._should_ignore(r"C:\Users\User\Documents\important.docx") == False
        assert handler._should_ignore(r"C:\Program Files\App\config.ini") == False

    def test_update_activity_tracking(self):
        """Test directory activity tracking."""
        handler = FileMonitorHandler()
        now = datetime.now()
        dir_path = r"C:\test\dir"
        
        handler._update_activity_tracking(dir_path, now)
        assert dir_path in handler.sequential_operations
        assert handler.sequential_operations[dir_path] == 1
        assert handler.last_modification_time[dir_path] == now
        
        handler._update_activity_tracking(dir_path, now)
        assert handler.sequential_operations[dir_path] == 2

    def test_real_file_operations(self, file_monitor, temp_dir):
        """Test file monitor with real file operations."""
        test_file = os.path.join(temp_dir, "test_file.txt")
        with open(test_file, "w") as f:
            f.write("Initial content")
        
        event = FileModifiedEvent(test_file)
        file_monitor.on_any_event(event)
        
        time.sleep(0.5)
        
        with open(test_file, "a") as f:
            f.write("\nAdditional content")
        
        event = FileModifiedEvent(test_file)
        file_monitor.on_any_event(event)
        
        dir_path = os.path.dirname(test_file)
        assert dir_path in file_monitor.sequential_operations
        assert file_monitor.sequential_operations[dir_path] >= 1
    
    def test_is_encrypted(self, temp_dir):
        """Test encrypted file detection with real files."""
        handler = FileMonitorHandler()
        
        encrypted_file = os.path.join(temp_dir, "encrypted.bin")
        with open(encrypted_file, "wb") as f:
            f.write(os.urandom(8192))
        
        text_file = os.path.join(temp_dir, "text.txt")
        with open(text_file, "w") as f:
            f.write("A" * 8192)
        
        assert handler._is_encrypted(encrypted_file) == True
        
        assert handler._is_encrypted(text_file) == False
        
        assert handler._is_encrypted(os.path.join(temp_dir, "nonexistent.txt")) == False

    def test_multiple_file_operations(self, file_monitor, temp_dir):
        """Test monitoring multiple file operations in sequence."""
        files = []
        for i in range(5):
            file_path = os.path.join(temp_dir, f"test_file_{i}.txt")
            with open(file_path, "w") as f:
                f.write(f"Content for file {i}")
            files.append(file_path)
        
        for file_path in files:
            with open(file_path, "a") as f:
                f.write("\nModified content")
            file_monitor.on_any_event(FileModifiedEvent(file_path))
            
            time.sleep(0.1)
        
        for file_path in files[:2]:
            os.remove(file_path)
            file_monitor.on_any_event(FileDeletedEvent(file_path))
            time.sleep(0.1)
        
        dir_path = os.path.dirname(files[0])
        assert dir_path in file_monitor.sequential_operations
        assert file_monitor.sequential_operations[dir_path] >= 5
    
    def test_weird_extensions(self, file_monitor, temp_dir):
        """Test detection of files with suspicious extensions."""
        weird_extensions = [".encrypted", ".locked", ".cerber", ".zepto", ".locky"]
        files = []
        
        for ext in weird_extensions:
            file_path = os.path.join(temp_dir, f"test_file{ext}")
            with open(file_path, "w") as f:
                f.write(f"This file has a suspicious extension: {ext}")
            files.append(file_path)
        
        random_content = ''.join(random.choices(string.ascii_letters + string.digits, k=1024))
        
        for file_path in files:
            with open(file_path, "w") as f:
                f.write(random_content)
            
            event = FileCreatedEvent(file_path)
            file_monitor.on_any_event(event)
            
            time.sleep(0.2)

