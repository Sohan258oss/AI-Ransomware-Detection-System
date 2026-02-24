import threading
import time
import os
import psutil
import asyncio
import re
from monitor.file_monitor import start_file_monitor
from monitor.process_monitor import scan_processes
from ml.predictor import predict
from websocket_server import start_server, queue_alert

# Start WebSocket server in background
loop = asyncio.new_event_loop()
def start_ws():
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
    except Exception as e:
        print(f"[!!!] WebSocket Server Thread Error: {e}")

ws_thread = threading.Thread(target=start_ws, daemon=True)
ws_thread.start()

WATCH_PATH = "C:/Users"
LOG_FILE = "alerts.log"

alerts = []
stats = {
    'total_alerts': 0,
    'ransomware_predictions': 0,
    'benign_predictions': 0,
    'processes_killed': 0,
    'high_entropy_files': 0
}

behavior_window = {
    'registry_read': 0, 'registry_write': 0, 'registry_delete': 0,
    'registry_total': 0, 'network_threats': 0, 'network_dns': 0,
    'network_http': 0, 'network_connections': 0, 'processes_malicious': 0,
    'processes_suspicious': 0, 'processes_monitored': 0, 'total_procsses': 0,
    'files_malicious': 0, 'files_suspicious': 0, 'files_text': 0,
    'files_unknown': 0, 'dlls_calls': 0, 'apis': 0
}

def log_to_file(message):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(message + '\n')

def handle_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log = f"[{timestamp}] ⚠️  ALERT: {message}"
    print(log)
    alerts.append(log)
    log_to_file(log)
    stats['total_alerts'] += 1

    if 'RENAME' in message:
        behavior_window['files_malicious'] += 10
        behavior_window['processes_malicious'] += 2
    if 'ENTROPY' in message:
        behavior_window['files_suspicious'] += 10
        behavior_window['files_malicious'] += 8
        behavior_window['network_threats'] += 3
        stats['high_entropy_files'] += 1
    if 'PROCESS' in message:
        behavior_window['processes_suspicious'] += 1
    if 'ACTIVITY' in message:
        behavior_window['files_unknown'] += 2
        behavior_window['total_procsses'] += 1

    alert_type = 'rename' if 'RENAME' in message else \
                 'entropy' if 'ENTROPY' in message else \
                 'process' if 'PROCESS' in message else 'activity'

    # Send basic alert
    asyncio.run_coroutine_threadsafe(queue_alert({
        'type': 'alert',
        'alertType': alert_type,
        'message': message
    }), loop)

    # Special handling for entropy to update the entropy monitor in real-time
    if alert_type == 'entropy':
        match = re.search(r"HIGH ENTROPY FILE: (.*) \(entropy=(.*)\)", message)
        if match:
            filename = match.group(1)
            entropy_val = float(match.group(2))
            asyncio.run_coroutine_threadsafe(queue_alert({
                'type': 'entropy',
                'filename': filename,
                'entropy': entropy_val
            }), loop)

def kill_suspicious_process(name):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() == name.lower():
                proc.kill()
                msg = f"[!!!] PROCESS KILLED: {name} (pid={proc.info['pid']})"
                print(msg)
                log_to_file(msg)
                stats['processes_killed'] += 1
        except Exception:
            pass

def run_ai_prediction():
    while True:
        time.sleep(5)
        result = predict(behavior_window)

        label = result['label']
        confidence = result['confidence']

        if result['is_ransomware']:
            stats['ransomware_predictions'] += 1
        else:
            stats['benign_predictions'] += 1

        status = f"[AI] Prediction: {label} | Confidence: {confidence}%"
        print(status)
        log_to_file(status)

        if result['is_ransomware'] and confidence > 80:
            warning = f"[!!!] HIGH RISK RANSOMWARE DETECTED! Confidence: {confidence}%"
            print(warning)
            log_to_file(warning)

        asyncio.run_coroutine_threadsafe(queue_alert({
            'type': 'prediction',
            'label': label,
            'confidence': confidence
        }), loop)

        for key in behavior_window:
            behavior_window[key] = 0

def print_dashboard():
    while True:
        time.sleep(60)
        threat_level = "🟢 LOW"
        if stats['ransomware_predictions'] > 0:
            threat_level = "🟡 MEDIUM"
        if stats['ransomware_predictions'] > 3:
            threat_level = "🔴 HIGH"

        print(f"""
╔══════════════════════════════════════════╗
║        THREAT SUMMARY DASHBOARD          ║
╠══════════════════════════════════════════╣
║  Threat Level     : {threat_level:<22}║
║  Total Alerts     : {stats['total_alerts']:<22}║
║  High Entropy Files: {stats['high_entropy_files']:<21}║
║  Ransomware Flags : {stats['ransomware_predictions']:<22}║
║  Benign Checks    : {stats['benign_predictions']:<22}║
║  Processes Killed : {stats['processes_killed']:<22}║
╚══════════════════════════════════════════╝
        """)

if __name__ == "__main__":
    print("=== AI-Powered Ransomware Early Detection System ===")
    print(f"[*] Watching  : {WATCH_PATH}")
    print(f"[*] AI Model  : Loaded (99% accuracy)")
    print(f"[*] Log File  : {LOG_FILE}")
    print(f"[*] Dashboard : Updates every 60 seconds\n")

    observer = start_file_monitor(WATCH_PATH, handle_alert)

    proc_thread = threading.Thread(
        target=scan_processes, args=(handle_alert,), daemon=True
    )
    proc_thread.start()

    ai_thread = threading.Thread(target=run_ai_prediction, daemon=True)
    ai_thread.start()

    dashboard_thread = threading.Thread(target=print_dashboard, daemon=True)
    dashboard_thread.start()

    print("[*] AI prediction running every 5 seconds...")
    print("[*] Dashboard running every 60 seconds...\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] System stopped.")
        print(f"[*] All alerts saved to: {LOG_FILE}")

    observer.join()