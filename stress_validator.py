"""
Stress and False Positive Validator
Tests the resource overhead of the background monitor and 
verifies that heavy benign tasks do not falsely trigger ransomware alerts.
"""

import time
import os
import zipfile
import tempfile
import psutil
from monitor import SystemMonitor
import shutil

class StressValidator:
    def __init__(self):
        self.monitor = SystemMonitor()

    def test_a_overhead(self):
        print("\n" + "-"*50)
        print("  TEST A: System Overhead Monitor (10 seconds)")
        print("-" * 50)
        print("Starting background monitoring thread...")
        self.monitor.start_background_monitoring()
        
        my_pid = os.getpid()
        me = psutil.Process(my_pid)
        
        cpu_samples = []
        mem_samples = []
        
        # Initial dump
        me.cpu_percent(interval=None)
        
        start_time = time.time()
        while time.time() - start_time < 10:
            cpu = me.cpu_percent(interval=0.5)
            mem = me.memory_info().rss / (1024 * 1024)
            cpu_samples.append(cpu)
            mem_samples.append(mem)
        
        print("\nResults:")
        print(f"  Average CPU Usage (Monitor Thread): {sum(cpu_samples)/len(cpu_samples):.2f}%")
        print(f"  Max CPU Usage: {max(cpu_samples):.2f}%")
        print(f"  Memory Footprint: ~{sum(mem_samples)/len(mem_samples):.2f} MB")
        
        if sum(cpu_samples)/len(cpu_samples) > 10.0:
            print("  [!] WARNING: Overhead is quite high.")
        else:
            print("  [+] SUCCESS: Overhead is acceptable.")

    def test_b_false_positive(self):
        print("\n" + "-" * 50)
        print("  TEST B: False Positive Simulator (Heavy Benign I/O)")
        print("-" * 50)
        print("Simulating a heavy benign task (rapid file creation & zipping)...")
        
        # Clear history to watch for new alerts
        self.monitor.detection_history.clear()
        
        temp_dir = tempfile.mkdtemp()
        dummy_files_dir = os.path.join(temp_dir, "dummy_files")
        os.makedirs(dummy_files_dir)
        
        zip_path = os.path.join(temp_dir, "massive.zip")
        
        try:
            # 1. Create a lot of data quickly
            print("  [1/2] Creating 50MB of dummy files...")
            for i in range(50):
                with open(os.path.join(dummy_files_dir, f"file_{i}.bin"), "wb") as f:
                    f.write(os.urandom(1024 * 1024)) # 1MB each
                    
            # 2. Zip them up fast
            print("  [2/2] Zipping files (Intense CPU + Disk I/O spike)...")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(dummy_files_dir):
                    for file in files:
                        zipf.write(os.path.join(root, file), file)
                        
            print("  Task completed. Analyzing detection history...")
        finally:
            shutil.rmtree(temp_dir)

        # Let the monitor finish any last cycle
        time.sleep(1)
        
        history = self.monitor.detection_history
        ransomware_alerts = [d for d in history if d.get('is_ransomware') == True]
        
        print("\nResults:")
        print(f"  Total Monitoring Cycles during task: {len(history)}")
        print(f"  Ransomware Alerts Triggered: {len(ransomware_alerts)}")
        
        if len(ransomware_alerts) > 0:
            print("  [!] FAILED: The system generated a False Positive on a benign task!")
        else:
            print("  [+] SUCCESS: The system correctly ignored the heavy benign task.")

        self.monitor.stop_background_monitoring()


if __name__ == "__main__":
    print("=" * 60)
    print("  RANSOMWARE CONFIGURATION STRESS TEST")
    print("=" * 60)
    
    validator = StressValidator()
    if not validator.monitor.model_loaded:
        print("Error: Trained ML model not found. Cannot run test.")
    else:
        validator.test_a_overhead()
        validator.test_b_false_positive()
    
    print("\n" + "=" * 60)
