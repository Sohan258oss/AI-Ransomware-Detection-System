import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
from monitor.entropy_checker import is_suspicious_entropy

class RansomwareFileHandler(FileSystemEventHandler):
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.event_counts = defaultdict(int)
        self.window_start = time.time()
        self.WINDOW_SECONDS = 5
        self.THRESHOLD_EVENTS = 50

    def _check_rate(self, event_type):
        now = time.time()
        if now - self.window_start > self.WINDOW_SECONDS:
            self.event_counts.clear()
            self.window_start = now
        
        self.event_counts[event_type] += 1
        total = sum(self.event_counts.values())
        
        if total >= self.THRESHOLD_EVENTS:
            self.alert_callback(f"HIGH FILE ACTIVITY: {total} events in {self.WINDOW_SECONDS}s")

    def on_modified(self, event):
        if not event.is_directory:
            self._check_rate('modified')
            suspicious, entropy = is_suspicious_entropy(event.src_path)
            if suspicious:
                self.alert_callback(f"HIGH ENTROPY FILE: {event.src_path} (entropy={entropy})")

    def on_created(self, event):
        if not event.is_directory:
            self._check_rate('created')

    def on_deleted(self, event):
        self._check_rate('deleted')

    def on_moved(self, event):
        self._check_rate('renamed')
        dst = event.dest_path
        suspicious_extensions = ['.locked', '.enc', '.crypt', '.crypto', '.encrypted', '.zzzzz']
        if any(dst.endswith(ext) for ext in suspicious_extensions):
            self.alert_callback(f"SUSPICIOUS RENAME: {event.src_path} → {dst}")


def start_file_monitor(watch_path, alert_callback):
    handler = RansomwareFileHandler(alert_callback)
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()
    print(f"[*] Monitoring: {watch_path}")
    return observer