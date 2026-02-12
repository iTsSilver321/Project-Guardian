import subprocess
import time
import sys
import os
import signal
import json
import socket
import ctypes

# Configuration
API_PORT = 8080
DASHBOARD_PORT = 8501
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(ROOT_DIR, "guardian_pids.json")

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def get_pids():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_pids(pids):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(pids, f)

def start(iface_index=None):
    pids = get_pids()
    if pids:
        print("Guardian is already running or pids.json exists. Try 'stop' first.")
        # return

    print("🚀 Starting Project Guardian in background...")
    
    # Check Admin Privileges
    is_admin = False
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        pass
        
    if not is_admin:
        print("⚠️ WARNING: Not running as Administrator!")
        print("   - Firewall blocking WILL FAIL.")
        print("   - Packet capture might be limited.")
        print("   - Please restart your terminal as Administrator for full protection.")
    # 1. Start API
    print(" - Starting API Server (Brain)...")
    api_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server.api:app", "--host", "0.0.0.0", "--port", str(API_PORT)],
        cwd=ROOT_DIR,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    pids['api'] = api_proc.pid

    # 2. Start Dashboard
    print(" - Starting Dashboard (UI)...")
    dash_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "dashboard/app.py", "--server.port", str(DASHBOARD_PORT), "--server.headless", "true"],
        cwd=ROOT_DIR,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    pids['dashboard'] = dash_proc.pid

    # 3. Start Sniffer (Sensor)
    print(" - Starting Sniffer (Sensor)...")
    
    # Open log file for sniffer
    log_path = os.path.join(ROOT_DIR, "sniffer.log")
    sniffer_log = open(log_path, "a")
    sniffer_log.write(f"\n--- Guardian Start: {time.ctime()} ---\n")
    sniffer_log.flush()

    # Using 'cargo run' via Popen to ensure latest code is used
    sniffer_cmd = ["cargo", "run", "--", "--server", f"http://localhost:{API_PORT}", "--token", "SECRET_GUARDIAN_TOKEN"]
    if iface_index is not None:
        sniffer_cmd.extend(["--iface", str(iface_index)])

    sniffer_proc = subprocess.Popen(
        sniffer_cmd,
        cwd=os.path.join(ROOT_DIR, "sniffer"),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
        stdout=sniffer_log,
        stderr=sniffer_log
    )
    pids['sniffer'] = sniffer_proc.pid
    
    with open(CONFIG_FILE, "w") as f:
        json.dump(pids, f)
    
    print(f"✅ Project Guardian is now running in the background.")
    print(f" - Dashboard: http://localhost:{DASHBOARD_PORT}")
    print(f" - API: http://localhost:{API_PORT}")
    print(f" - Log: {log_path}")
    print(f"You can close this terminal now.")

def stop():
    pids = get_pids()
    if not pids:
        print("No PID file found. Guardian might not be running via this manager.")
        return

    print("🛑 Stopping Project Guardian...")
    for name, pid in pids.items():
        try:
            print(f" - Terminating {name} (PID: {pid})...")
            if os.name == 'nt':
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                os.kill(pid, signal.SIGTERM)
        except Exception as e:
            print(f"   Failed to stop {name}: {e}")
    
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
    print("✅ System stopped.")

def status():
    pids = get_pids()
    print("📊 Project Guardian Status:")
    if not pids:
        print(" - Manager: Not running")
    
    api_live = is_port_in_use(API_PORT)
    dash_live = is_port_in_use(DASHBOARD_PORT)
    
    print(f" - API Server ({API_PORT}): {'ONLINE' if api_live else 'OFFLINE'}")
    print(f" - Dashboard ({DASHBOARD_PORT}): {'ONLINE' if dash_live else 'OFFLINE'}")
    
    if pids:
        for name, pid in pids.items():
            print(f" - {name.capitalize()} PID: {pid}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python guardian.py [start|stop|status] [interface_index]")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    if cmd == "start":
        iface = int(sys.argv[2]) if len(sys.argv) > 2 else None
        start(iface)
    elif cmd == "stop":
        stop()
    elif cmd == "status":
        status()
    else:
        print(f"Unknown command: {cmd}")
