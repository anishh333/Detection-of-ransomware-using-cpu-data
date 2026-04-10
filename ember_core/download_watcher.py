import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    from ember_core.static_scanner import scan_file_static
except ImportError:
    from static_scanner import scan_file_static

class RansomwareDownloadHandler(FileSystemEventHandler):
    def __init__(self, log_list=None):
        """
        log_list is an optional shared list that we can append results to,
        so the Flask UI can display the recent scans.
        """
        self.log_list = log_list if log_list is not None else []
        self.extensions_to_monitor = ['.exe', '.dll']

    def process_file(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.extensions_to_monitor:
            return

        print(f"[WATCHDOG] New executable detected: {file_path}")
        
        # Give the filesystem a moment to finish writing the file
        time.sleep(1)
        
        try:
            result = scan_file_static(file_path)
            
            log_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "file": os.path.basename(file_path),
                "status": "Scanned",
                "prediction": result.get("prediction", "Error"),
                "risk_score": result.get("risk_score", 0),
                "action_taken": "None"
            }

            if result.get("prediction") == "Malicious":
                # AUTO-KILL: Delete the file before it can run
                try:
                    os.remove(file_path)
                    print(f"[WATCHDOG] 🛑 MALICIOUS FILE DELETED: {file_path}")
                    log_entry["action_taken"] = "Quarantined/Deleted"
                except Exception as e:
                    print(f"[WATCHDOG] Failed to delete {file_path}: {e}")
                    log_entry["action_taken"] = f"Failed to delete: {e}"
            else:
                print(f"[WATCHDOG] ✅ File looks benign: {file_path}")
                log_entry["action_taken"] = "Allowed"

            # Optional UI hook
            self.log_list.insert(0, log_entry)
            # Keep log small
            if len(self.log_list) > 50:
                self.log_list.pop()

        except Exception as e:
            print(f"[WATCHDOG] Error scanning file: {e}")

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        # Browsers often create a .crdownload and rename it to .exe
        # Watchdog triggers modified/moved events. 
        if not event.is_directory and event.src_path.endswith('.exe'):
            self.process_file(event.src_path)
    
    def on_moved(self, event):
        # A file was renamed from .crdownload to .exe
        if not event.is_directory:
            self.process_file(event.dest_path)


def start_watcher(path_to_watch=None, shared_logs=None):
    if path_to_watch is None:
        # Default to the current user's Downloads folder on Windows
        path_to_watch = os.path.join(os.path.expanduser('~'), 'Downloads')
    
    if not os.path.exists(path_to_watch):
        print(f"Watch directory {path_to_watch} does not exist. Watchdog skipping.")
        return

    event_handler = RansomwareDownloadHandler(shared_logs)
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=False)
    
    observer.start()
    print(f"\n[EMBER] Real-Time Static Protection running. Monitoring: {path_to_watch}")
    
    # Normally observer.join() blocks the thread, so we return the observer
    # and let the caller manage it (for Flask background running)
    return observer

if __name__ == "__main__":
    obs = start_watcher()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
