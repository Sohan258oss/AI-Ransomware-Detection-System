import psutil
import time

SUSPICIOUS_APIS = ['vssadmin', 'bcdedit', 'wbadmin', 'cipher']

def get_process_features(pid):
    """Extract behavioral features from a process."""
    try:
        proc = psutil.Process(pid)
        return {
            'pid': pid,
            'name': proc.name(),
            'cpu_percent': proc.cpu_percent(interval=0.5),
            'memory_mb': proc.memory_info().rss / (1024 * 1024),
            'open_files': len(proc.open_files()),
            'connections': len(proc.connections()),
            'status': proc.status()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def scan_processes(alert_callback):
    """Continuously scan all processes for anomalies."""
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                
                for api in SUSPICIOUS_APIS:
                    if api in name or api in cmdline:
                        alert_callback(f"SUSPICIOUS PROCESS: {name} | CMD: {cmdline}")
                
                features = get_process_features(proc.info['pid'])
                if features:
                    if features['cpu_percent'] > 80 and features['open_files'] > 50:
                        alert_callback(
                            f"SUSPICIOUS BEHAVIOR: {features['name']} "
                            f"CPU={features['cpu_percent']}% Files={features['open_files']}"
                        )
            except Exception:
                pass
        time.sleep(2)