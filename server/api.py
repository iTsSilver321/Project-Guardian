from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from pydantic import BaseModel
import sqlite3
import collections
import time
from typing import Optional, List
import uvicorn
import databases
import sqlalchemy
import sys
import os

# Enable importing from Analyzer
# Ensure sys.path uses absolute path for the project root
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

try:
    from analyzer.ml_engine import MLEngine
    from analyzer import firewall
    from analyzer.reputation import ReputationEngine
except ImportError as e:
    print(f"Failed to import analyzer modules: {e}")
    class MLEngine:
        def __init__(self): pass
        def add_packet(self, *args): return 0
        def reinforce(self, *args): pass
    class firewall:
        @staticmethod
        def block_ip(ip): return False
        @staticmethod
        def unblock_ip(ip): return False
    class ReputationEngine:
        def __init__(self, *args): pass
        def update_score(self, *args): return 100
        def get_score(self, *args): return 100
        def is_blocked(self, *args): return False

# Database Configuration
DATABASE_URL = "sqlite:///./guardian.db"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

packets = sqlalchemy.Table(
    "packets",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("time", sqlalchemy.Float),
    sqlalchemy.Column("src_ip", sqlalchemy.String),
    sqlalchemy.Column("dst_ip", sqlalchemy.String),
    sqlalchemy.Column("dst_port", sqlalchemy.Integer),
    sqlalchemy.Column("protocol", sqlalchemy.String),
    sqlalchemy.Column("flags", sqlalchemy.Integer),
    sqlalchemy.Column("length", sqlalchemy.Integer),
)

alerts = sqlalchemy.Table(
    "alerts",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("time", sqlalchemy.Float),
    sqlalchemy.Column("type", sqlalchemy.String),
    sqlalchemy.Column("src_ip", sqlalchemy.String),
    sqlalchemy.Column("message", sqlalchemy.String),
)

app = FastAPI(title="Project Guardian API (Brain)")

# --- Analysis State ---
ml = MLEngine()
rep = ReputationEngine(block_threshold=0) # Auto-block at 0 trust
packet_history = collections.defaultdict(list)
PORT_SCAN_THRESHOLD = 5
PORT_SCAN_WINDOW = 5
PAYLOAD_SIGNATURES = [
    "UNION SELECT", "eval(", "/etc/passwd", "<script>", 
    "User-Agent: python-requests", "Log4j", "cmd.exe", "/bin/sh"
]

class PacketLog(BaseModel):
    src: str
    dst: str
    src_port: Optional[int] = 0
    dst_port: Optional[int] = 0
    proto: str
    flags: Optional[int] = 0
    len: int
    payload: Optional[str] = ""

API_TOKEN = "SECRET_GUARDIAN_TOKEN"

async def verify_token(authorization: str = Header(None)):
    if authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=403, detail="Invalid Token")

@app.on_event("startup")
async def startup():
    await database.connect()
    conn = sqlite3.connect("guardian.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, time REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT, flags INTEGER, length INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, time REAL, type TEXT, src_ip TEXT, message TEXT)''')
    # Add Index for Performance
    c.execute('''CREATE INDEX IF NOT EXISTS idx_packet_time ON packets(time)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(time)''')
    conn.commit()
    conn.close()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

async def analyze_packet(packet: PacketLog):
    """Run detections on the packet in background."""
    src = packet.src
    dst = packet.dst
    dst_port = packet.dst_port
    length = packet.len
    payload = packet.payload or ""
    current_time = time.time()
    
    # 1. DPI Check (High Confidence - Heavy Penalty)
    for sig in PAYLOAD_SIGNATURES:
        if sig in payload:
            msg = f"DPI Alert! Signature: '{sig}'"
            print(f"[API ALERT] {msg}")
            await log_alert_internal("Deep Packet Inspection", src, msg)
            new_score = rep.update_score(src, 50) # -50 for signature match
            if rep.is_blocked(src):
                block_res = firewall.block_ip(src)
                if block_res == "NEW":
                    await log_alert_internal("FIREWALL_BLOCK", src, f"Blocked: Trust Score 0 (DPI: {sig})")
                elif block_res == "FAILED":
                    await log_alert_internal("FIREWALL_ERROR", src, "Failed to Block (No Admin Rights?)")
            return

    # 2. Advanced Analytics
    proto_num = 6 if "TCP" in packet.proto else 17 if "UDP" in packet.proto else 0
    analysis_res = ml.add_packet(src, length, packet.src_port, dst_port, proto_num)
    
    if analysis_res == -1:
        # Statistical Anomaly
        msg = f"ML Anomaly! Size {length} Port {dst_port}"
        print(f"[API ALERT] {msg}")
        await log_alert_internal("Machine Learning", src, msg)
        rep.update_score(src, 10) # -10 for suspicious pattern
    elif analysis_res == -2:
        # Timing Anomaly (Bot Hunter)
        msg = f"Timing Anomaly! Bot-like behavior detected (Beaconing)"
        print(f"[API ALERT] {msg}")
        await log_alert_internal("Cognitive Analytics", src, msg)
        rep.update_score(src, 25) # -25 for robot-like timing

    # 3. Port Scan Logic
    if dst_port:
        packet_history[src].append((current_time, dst, dst_port))
        packet_history[src] = [x for x in packet_history[src] if current_time - x[0] <= PORT_SCAN_WINDOW]
        ports = set(p for _, d, p in packet_history[src] if d == dst)
        if len(ports) > PORT_SCAN_THRESHOLD:
            msg = f"Port Scan! {len(ports)} ports on {dst}"
            await log_alert_internal("Port Scan", src, msg)
            rep.update_score(src, 30) # -30 for scanning

    # Final Check: Should we block based on aggregate score?
    if rep.is_blocked(src):
        block_res = firewall.block_ip(src)
        if block_res == "NEW":
            await log_alert_internal("FIREWALL_BLOCK", src, "Trust Score reaching zero")
        elif block_res == "FAILED":
            await log_alert_internal("FIREWALL_ERROR", src, "Failed to Block (No Admin Rights?)")

async def log_alert_internal(type_, src, msg):
    query = alerts.insert().values(
        time=time.time(),
        type=type_,
        src_ip=src,
        message=msg
    )
    await database.execute(query)

@app.post("/log/packet", dependencies=[Depends(verify_token)])
async def log_packet(packet: PacketLog, background_tasks: BackgroundTasks):
    # Log raw packet immediately & return 200
    query = packets.insert().values(
        time=time.time(),
        src_ip=packet.src,
        dst_ip=packet.dst,
        dst_port=packet.dst_port,
        protocol=packet.proto,
        flags=packet.flags,
        length=packet.len
    )
    await database.execute(query)
    background_tasks.add_task(analyze_packet, packet)
    return {"status": "ok"}

@app.get("/stats")
async def get_stats(limit: int = 100):
    # Fetch total counts
    total_packets = await database.fetch_val("SELECT COUNT(*) FROM packets")
    total_alerts = await database.fetch_val("SELECT COUNT(*) FROM alerts")
    total_blocked = await database.fetch_val("SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE type = 'FIREWALL_BLOCK'")

    query_packets = packets.select().order_by(packets.c.time.desc()).limit(limit)
    recent_packets = await database.fetch_all(query_packets)
    query_alerts = alerts.select().order_by(alerts.c.time.desc()).limit(limit)
    recent_alerts = await database.fetch_all(query_alerts)
    return {
        "packets": [dict(p) for p in recent_packets],
        "alerts": [dict(a) for a in recent_alerts],
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "total_blocked": total_blocked or 0,
        "reputation": {ip: rep.get_score(ip) for ip in list(rep.scores.keys())[-10:]} # Show top 10 most recent
    }

@app.delete("/logs", dependencies=[Depends(verify_token)])
async def clear_logs():
    await database.execute("DELETE FROM packets")
    await database.execute("DELETE FROM alerts")
    return {"status": "cleared"}

@app.post("/unblock", dependencies=[Depends(verify_token)])
async def unblock_ip_api(ip_data: dict):
    ip = ip_data.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="IP required")
    success = firewall.unblock_ip(ip)
    if success:
        # Reset reputation score to 100 so it doesn't re-block immediately
        rep.scores[ip] = 100
        # Also remove from alerts list to keep Dashboard clean
        await database.execute("DELETE FROM alerts WHERE src_ip = :ip AND type = 'FIREWALL_BLOCK'", {"ip": ip})
        return {"status": "unblocked"}
    else:
        return {"status": "failed"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, workers=1) # Single worker for SQLite simplicity
