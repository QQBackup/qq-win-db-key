"""Shared pytest fixtures and configuration."""
import os
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any
import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files.
    
    Yields:
        Path: Path to the temporary directory
    """
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def test_data_dir() -> Path:
    """Get the path to test data directory.
    
    Returns:
        Path: Path to the test data directory
    """
    return Path(__file__).parent / "data"


@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Provide mock configuration for testing.
    
    Returns:
        Dict[str, Any]: Mock configuration dictionary
    """
    return {
        "db_path": "/tmp/test.db",
        "key_length": 32,
        "encryption_enabled": True,
        "platform": "test",
        "version": "1.0.0",
    }


@pytest.fixture
def sample_db_key() -> bytes:
    """Provide a sample database encryption key.
    
    Returns:
        bytes: Sample 32-byte encryption key
    """
    return b"0123456789abcdef0123456789abcdef"


@pytest.fixture
def mock_env_vars(monkeypatch) -> Dict[str, str]:
    """Mock environment variables for testing.
    
    Args:
        monkeypatch: Pytest monkeypatch fixture
        
    Returns:
        Dict[str, str]: Dictionary of mocked environment variables
    """
    env_vars = {
        "QQ_DB_PATH": "/tmp/qq_test.db",
        "NTQQ_KEY_PATH": "/tmp/keys",
        "DEBUG_MODE": "true",
    }
    
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    
    return env_vars


@pytest.fixture
def create_test_file(temp_dir: Path) -> Generator[callable, None, None]:
    """Factory fixture to create test files.
    
    Args:
        temp_dir: Temporary directory fixture
        
    Yields:
        callable: Function to create test files
    """
    def _create_file(filename: str, content: str = "") -> Path:
        file_path = temp_dir / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
        return file_path
    
    yield _create_file


@pytest.fixture(autouse=True)
def reset_imports():
    """Reset imports between tests to ensure clean state."""
    import sys
    modules_to_remove = [
        mod for mod in sys.modules.keys() 
        if mod.startswith("src.") or mod == "src"
    ]
    for mod in modules_to_remove:
        del sys.modules[mod]


@pytest.fixture
def capture_logs():
    """Capture log messages during tests.
    
    Returns:
        list: List to store captured log records
    """
    import logging
    
    logs = []
    handler = logging.Handler()
    handler.emit = lambda record: logs.append(record)
    
    logger = logging.getLogger()
    original_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    
    yield logs
    
    logger.removeHandler(handler)
    logger.setLevel(original_level)


@pytest.fixture
def mock_platform(monkeypatch):
    """Mock platform detection for cross-platform testing.
    
    Args:
        monkeypatch: Pytest monkeypatch fixture
        
    Returns:
        callable: Function to set mock platform
    """
    def _set_platform(platform_name: str):
        import sys
        if platform_name == "windows":
            monkeypatch.setattr(sys, "platform", "win32")
        elif platform_name == "linux":
            monkeypatch.setattr(sys, "platform", "linux")
        elif platform_name == "macos":
            monkeypatch.setattr(sys, "platform", "darwin")
        elif platform_name == "android":
            monkeypatch.setattr(sys, "platform", "linux")
            monkeypatch.setenv("ANDROID_ROOT", "/system")
    
    return _set_platform


@pytest.fixture
def benchmark_timer():
    """Simple benchmark timer for performance testing.
    
    Yields:
        dict: Dictionary with start/stop methods and elapsed time
    """
    import time
    
    data = {"start_time": None, "elapsed": None}
    
    def start():
        data["start_time"] = time.time()
    
    def stop():
        if data["start_time"] is not None:
            data["elapsed"] = time.time() - data["start_time"]
            return data["elapsed"]
        return None
    
    data["start"] = start
    data["stop"] = stop
    
    yield data