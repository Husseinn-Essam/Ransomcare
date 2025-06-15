import os
import shutil
import tempfile
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch
from collections import deque
from watchdog.events import FileCreatedEvent, FileModifiedEvent, FileDeletedEvent


@pytest.fixture
def temp_dir():
    """Provide a clean temporary directory for tests."""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    if os.path.exists(temp_path):
        shutil.rmtree(temp_path)


@pytest.fixture
def sample_file(temp_dir):
    """Create a sample file for testing."""
    file_path = os.path.join(temp_dir, "sample.txt")
    with open(file_path, "w") as f:
        f.write("This is a test file for monitoring.")
    return file_path


@pytest.fixture
def mock_process():
    """Create a mock process for testing."""
    process = MagicMock()
    process.pid = 1234
    process.name.return_value = "test_process.exe"
    process.exe.return_value = "C:\\test\\test_process.exe"
    process.cmdline.return_value = ["C:\\test\\test_process.exe", "--test"]
    process.username.return_value = "test_user"
    process.create_time.return_value = datetime.now().timestamp()
    process.cpu_percent.return_value = 10.0
    return process


@pytest.fixture
def mock_file_events(temp_dir):
    """Create mock file events for testing."""
    test_file = os.path.join(temp_dir, "test_file.txt")

    created_event = FileCreatedEvent(test_file)
    modified_event = FileModifiedEvent(test_file)
    deleted_event = FileDeletedEvent(test_file)

    return {
        "file_path": test_file,
        "created": created_event,
        "modified": modified_event,
        "deleted": deleted_event,
    }


@pytest.fixture
def mock_process_data():
    """Create mock process data for testing."""
    now = datetime.now()
    data = {
        "file_ops": deque(
            [(now, "C:\\test\\file1.txt"), (now, "C:\\test\\file2.txt")], maxlen=100
        ),
        "deletions": deque([(now, "C:\\test\\deleted.txt")], maxlen=100),
        "file_writes": deque([(now, "C:\\test\\written.txt")], maxlen=100),
        "cpu_history": deque([(now, 15.0), (now, 25.0)], maxlen=20),
        "encrypted_writes": deque([(now, "C:\\test\\encrypted.txt")], maxlen=100),
        "weird_ext_writes": deque([(now, "C:\\test\\weird.cerber")], maxlen=100),
        "critical_access": deque(
            [(now, "C:\\Windows\\system32\\important.dll")], maxlen=100
        ),
        "timestamp": now,
    }
    return data
