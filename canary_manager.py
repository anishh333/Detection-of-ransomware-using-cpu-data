"""
canary_manager.py
Implements a deterministic "Honeypot" file-system watcher using watchdog.
If any managed canary files are modified, deleted, or encrypted, it triggers the
monitor to instantly identify the high-IO process and terminate it, bypassing ML models.
"""
import os
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, manager):
        self.manager = manager
        
    def on_modified(self, event):
        if not event.is_directory and self.manager.is_canary(event.src_path):
            self.manager.trigger_kill(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory and self.manager.is_canary(event.src_path):
            self.manager.trigger_kill(event.src_path, "deleted")

    def on_moved(self, event):
        if not event.is_directory and self.manager.is_canary(event.src_path):
            self.manager.trigger_kill(event.src_path, "moved")

class CanaryManager:
    def __init__(self, monitor_dependency, watch_dir=None):
        self.monitor = monitor_dependency
        self.watch_dir = watch_dir or os.path.join(os.path.abspath(os.path.dirname(__file__)), "canary_trap")
        self.canary_files = [
            os.path.join(self.watch_dir, "_DO_NOT_DELETE_RANSOMWARE_CHECK.txt"),
            os.path.join(self.watch_dir, "_IMPORTANT_FINANCIALS.docx"),
            os.path.join(self.watch_dir, "000_BACKUP_KEY.key")
        ]
        self.observer = Observer()
        self.is_running = False

    def is_canary(self, path):
        return os.path.basename(path) in [os.path.basename(p) for p in self.canary_files]

    def setup(self):
        if not os.path.exists(self.watch_dir):
            os.makedirs(self.watch_dir)
            
        for cf in self.canary_files:
            if not os.path.exists(cf):
                with open(cf, "w") as f:
                    f.write("HONEYPOT FILE. DO NOT MODIFY OR YOUR PROCESS WILL BE KILLED.")

        # Hide directory on Windows
        if os.name == 'nt':
            os.system(f'attrib +h "{self.watch_dir}"')

    def start(self):
        if self.is_running:
            return
        self.setup()
        event_handler = CanaryHandler(self)
        self.observer.schedule(event_handler, self.watch_dir, recursive=False)
        self.observer.start()
        self.is_running = True
        print(f"[*] Canary Manager active on {self.watch_dir}")

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join(timeout=1.0)
            self.is_running = False

    def trigger_kill(self, path, action_type):
        """
        When a canary is touched, figure out who did it and kill them.
        Watchdog doesn't give us the PID of the modifier natively.
        We will rely on the SystemMonitor's highest I/O delta heuristic.
        """
        print(f"[!] CANARY TRIPPED: {path} was {action_type}!")
        if self.monitor:
            threat = self.monitor._identify_threat()
            if threat and threat.get('pid') != -1:
                pid = threat['pid']
                print(f"[!] CANARY KILL: Terminating culprit PID {pid} ({threat.get('name')})")
                try:
                    p = psutil.Process(pid)
                    # Protect against killing self
                    if p.pid != os.getpid():
                        p.terminate()
                except Exception as e:
                    print(f"Failed to kill canary culprit: {e}")
                    
                alert = {
                    "timestamp": time.time(),
                    "hpc_sample": {},
                    "io_sample": {},
                    "prediction": 1,
                    "probability": 1.0,
                    "is_ransomware": True,
                    "threat_info": {
                        "name": threat.get('name', 'Unknown'),
                        "pid": pid,
                        "path": path, # The canary file path where the detection happened
                        "category": f"Honeypot Canary Tripped ({action_type})",
                        "is_signed": threat.get('is_signed', False),
                        "killed_by_ai": True
                    }
                }
                self.monitor.detection_history.append(alert)
