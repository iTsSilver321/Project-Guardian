import sys
import json
import collections
import time
from datetime import datetime
from database import TrafficDB

# Configuration
PORT_SCAN_THRESHOLD = 5  # ports per second
PORT_SCAN_WINDOW = 5      # seconds
SYN_FLOOD_THRESHOLD = 100 # packets per second (for demo purposes)

PAYLOAD_SIGNATURES = [
    "UNION SELECT", 
    "eval(", 
    "/etc/passwd", 
    "<script>", 
    "User-Agent: python-requests",
    "Log4j",
    "cmd.exe",
    "/bin/sh"
]

from ml_engine import MLEngine
import firewall

# ... (rest of imports)

def main():
    # Force unbuffered output for prints and UTF-8 input
    sys.stdout.reconfigure(line_buffering=True)
    sys.stdin.reconfigure(encoding='utf-8')
    print("PYTHON ANALYZER STARTED - WAITING FOR INPUT...", file=sys.stderr)
    
    # Initialize Database
    db = TrafficDB()
    print("[INIT] Database initialized at traffic.db", file=sys.stderr)

    # Initialize ML Engine
    ml = MLEngine()
    print("[INIT] ML Engine initialized (IsolationForest)", file=sys.stderr)

    # Track statistics
    # src_ip -> {dst_ip -> set(ports), timestamp}
    # We will use a cleaner structure:
    # src_ip -> list of (timestamp, dst_ip, dst_port)
    packet_history = collections.defaultdict(list)
    packet_counts = collections.Counter()
    start_time = time.time()

    # Use a while loop with readline to avoid iterator buffering
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break # EOF
            
            line = line.strip()
            # Debug: print raw line to check if data reaches Python
            # print(f"PYTHON_DEBUG: Received: {line[:50]}...", file=sys.stderr) 
            if not line:
                continue
                
            data = json.loads(line)
            src = data.get('src')
            dst = data.get('dst')
            proto = str(data.get('proto'))
            src_port = data.get('src_port', 0)
            dst_port = data.get('dst_port', 0)
            length = data.get('len', 0)
            flags = data.get('flags', 0)
            payload = data.get('payload', "")
            
            # Map proto string to number if needed, but IsolationForest works better with numbers
            # Protocol is often "IpNextHeaderProtocol(6)" in our logs which is ugly
            # Let's try to extract number or hash it
            proto_num = 0
            if "TCP" in proto or "(6)" in proto: proto_num = 6
            elif "UDP" in proto or "(17)" in proto: proto_num = 17
            elif "ICMP" in proto or "(1)" in proto: proto_num = 1
            
            current_time = time.time()
            packet_counts['total'] += 1

            # Log to Database
            db.log_packet(src, dst, dst_port, proto, flags, length)

            # --- DPI: Signature Detection ---
            for sig in PAYLOAD_SIGNATURES:
                if sig in payload:
                    msg = f"DPI Alert! Malicious Signature detected: '{sig}'"
                    print(f"[ALERT] {msg}")
                    db.log_alert("Deep Packet Inspection", src, msg)
                    if firewall.block_ip(src):
                        db.log_alert("FIREWALL_BLOCK", src, f"Blocked due to DPI signature: {sig}")
                    break # Stop checking other signatures for this packet

            # --- ML Anomaly Detection ---
            # Feed packet features to ML engine
            ml_result = ml.add_packet(length, src_port, dst_port, proto_num)
            
            if ml_result == -1:
                # Anomaly Detected!
                msg = f"ML Anomaly! Unusual packet size {length} or port {dst_port}"
                print(f"[ALERT] {msg}")
                db.log_alert("Machine Learning", src, msg)
                if firewall.block_ip(src):
                    db.log_alert("FIREWALL_BLOCK", src, "Automatically blocked malicious IP")
            elif ml_result == 0:
                pass # Still training
            # ----------------------------

            # Log packet to history for analysis
            if dst_port is not None:
                packet_history[src].append((current_time, dst, dst_port))


            # Prune old history
            # In a real system we'd use a more efficient sliding window
            packet_history[src] = [
                (t, d, p) for (t, d, p) in packet_history[src] 
                if current_time - t <= PORT_SCAN_WINDOW
            ]

            # Port Scan Detection
            # Heuristic: One source connecting to many ports on the SAME destination
            # OR one source connecting to many destinations?
            # PRD says: "If one Source IP hits >10 unique ports on a Destination IP within 5 seconds"
            
            # Group by destination
            ports_per_dst = collections.defaultdict(set)
            for (t, d, p) in packet_history[src]:
                ports_per_dst[d].add(p)
            
            for d, ports in ports_per_dst.items():
                if len(ports) > PORT_SCAN_THRESHOLD:
                    msg = f"Port Scan Detected! {src} scanned {len(ports)} ports on {d}"
                    print(f"[ALERT] {msg}")
                    db.log_alert("Port Scan", src, msg)
                    if firewall.block_ip(src):
                        db.log_alert("FIREWALL_BLOCK", src, "Automatically blocked malicious IP")
                    
                    # Clear history to avoid spamming alerts? 
                    # For now, let's just let it spam or maybe debounce.
                    # A simple debounce: remove these entries so we don't alert again immediately?
                    # But then we miss ongoing attacks. 
                    # Let's just print.


            # SYN Flood Detection
            # SYN flag is 0x02 (2nd bit)
            if flags is not None and (flags & 0x02):
                # Detected a SYN packet
                packet_history[src].append((current_time, 'SYN', 0)) # Using 'SYN' as marker
            
            # Count SYNs in window
            syn_count = 0
            for (t, d, p) in packet_history[src]:
                if d == 'SYN':
                    syn_count += 1
            
            if syn_count > SYN_FLOOD_THRESHOLD:
                msg = f"SYN Flood Detected! {src} sent {syn_count} SYN packets"
                print(f"[ALERT] {msg}")
                db.log_alert("SYN Flood", src, msg)
                if firewall.block_ip(src):
                    db.log_alert("FIREWALL_BLOCK", src, "Automatically blocked malicious IP")

            # Info Log (Optional: Comment out to reduce noise if DB is primary)
            port_str = f":{dst_port}" if dst_port else ""
            flag_str = f" [Flags: {flags}]" if flags else ""
            print(f"[INFO] {src} -> {dst}{port_str} ({proto}){flag_str}")

            # Simple throughput calc
            elapsed = current_time - start_time
            if elapsed > 10:
                print(f"[STATS] {packet_counts['total']} packets in last {elapsed:.2f}s")
                packet_counts['total'] = 0
                start_time = current_time

        except json.JSONDecodeError:
            pass # Ignore partial lines
        except Exception as e:
            print(f"[ERROR] {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
