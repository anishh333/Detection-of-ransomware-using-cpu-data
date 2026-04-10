import pytest
from unittest.mock import patch, MagicMock
from monitor import SystemMonitor

@pytest.fixture
def monitor():
    return SystemMonitor()

def test_ignored_pids_are_skipped(monitor):
    """
    Test that if the user clicks 'Ignore' on the dashboard, 
    the backend strictly drops that PID from scanning, bypassing AI false positives.
    """
    # Setup test condition
    monitor.ignored_pids.add(1234)
    
    # Mock psutil
    mock_proc = MagicMock()
    mock_proc.info = {
        'pid': 1234, 
        'name': 'svchost.exe', 
        'cpu_percent': 99, 
        'io_counters': None, 
        'username': 'USER', 
        'exe': 'C:\\bad_path\\svchost.exe'
    }
    
    # Run threat identification with mock
    with patch('psutil.process_iter', return_value=[mock_proc]):
        threat = monitor._identify_threat()
        
    # Assertion: PID 1234 should NOT be flagged because it's in the ignore set
    assert threat['pid'] == -1
    
def test_path_verification_catches_spoofing(monitor):
    """
    Test that the path verification correctly rejects spoofed system files
    if they are not inside Windows System32 / Program Files.
    """
    mock_proc = MagicMock()
    mock_proc.info = {
        'pid': 9999, 
        'name': 'svchost.exe', # Spoofed name
        'cpu_percent': 80, 
        'io_counters': MagicMock(write_bytes=1000000), 
        'username': 'EVIL_USER', 
        'exe': 'C:\\Users\\Temp\\Downloads\\svchost.exe' # EVIL PATH
    }
    mock_proc.exe.return_value = 'C:\\Users\\Temp\\Downloads\\svchost.exe'
    
    with patch('psutil.process_iter', return_value=[mock_proc]):
        threat = monitor._identify_threat()
        
    # Assertion: The spoofed process should be caught because its path is not C:\windows\system32
    assert threat['pid'] == 9999
    assert threat['name'] == 'svchost.exe'
    assert threat['is_signed'] == False

def test_path_verification_allows_real_system_files(monitor):
    """
    Test that the path verification correctly allows real system files
    if they ARE inside Windows System32.
    """
    mock_proc = MagicMock()
    mock_proc.info = {
        'pid': 1111, 
        'name': 'svchost.exe', # Real name
        'cpu_percent': 80, 
        'io_counters': MagicMock(write_bytes=1000000), 
        'username': 'USER', 
        'exe': 'C:\\Windows\\System32\\svchost.exe' # REAL PATH
    }
    mock_proc.exe.return_value = 'C:\\Windows\\System32\\svchost.exe'
    
    with patch('psutil.process_iter', return_value=[mock_proc]):
        threat = monitor._identify_threat()
        
    # Assertion: The real process should NOT be caught because it matched the safe path check
    assert threat['pid'] == -1
