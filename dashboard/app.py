import streamlit as st
import pandas as pd
import sqlite3
import time
import os
import warnings
import requests
import json
import ipaddress
import subprocess
import sys

# Suppress Streamlit deprecation warnings
warnings.filterwarnings("ignore", category=UserWarning, module="streamlit")
warnings.filterwarnings("ignore", message=".*use_container_width.*")

# Project Root and Database setup
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_NAME = "guardian.db"

# Intelligence Layer - Mappings
PORT_MAP = {
    80: "Web (HTTP)",
    443: "Secure Web (HTTPS)",
    53: "Domain Search (DNS)",
    22: "Remote Login (SSH)",
    21: "File Transfer (FTP)",
    23: "Old Remote Login (Telnet)",
    25: "Email Sending (SMTP)",
    110: "Email Retrieval (POP3)",
    143: "Email Retrieval (IMAP)",
    3389: "Windows Remote Desktop",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis Cache",
    8080: "Dev Web Port",
    8000: "Guardian Brain API",
    27017: "MongoDB Database"
}

IDENTITIES = {
    "1.1.1.1": "Cloudflare DNS",
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "142.250.": "Google Services",
    "34.117.": "Google Cloud",
    "52.223.": "Twitch/Amazon Services",
    "157.240.": "Facebook Server",
    "31.13.": "Instagram Server"
}

def analyze_traffic_metadata(df):
    """Adds human-readable intelligence to the raw traffic data."""
    if df is None:
        return df

    # Ensure columns exist to avoid KeyErrors in UI
    if 'Service' not in df.columns:
        df['Service'] = "Other App"
    if 'Identity' not in df.columns:
        df['Identity'] = "Unknown External"

    if df.empty:
        return df
        
    # Analyze Ports
    if 'dst_port' in df.columns:
        df['Service'] = df['dst_port'].map(PORT_MAP).fillna("Other App")
        
    # Analyze Identities (Simple Prefix Matching)
    def identify_ip(ip):
        if is_private(ip):
            return "Home Device"
        for prefix, label in IDENTITIES.items():
            if str(ip).startswith(prefix):
                return label
        return "Unknown External"
        
    if 'src_ip' in df.columns:
        df['Identity'] = df['src_ip'].apply(identify_ip)
        
    return df

# Helper to check if IP is private
def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except:
        return True

# Set page config
st.set_page_config(
    page_title="Project Guardian Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# Title and Header
st.title("🛡️ Project Guardian - Network Sentinel")
st.markdown("---")

# Config
API_URL = "http://localhost:8080/stats"
USE_API = True
API_TOKEN = "SECRET_GUARDIAN_TOKEN"

# Data Loading Function
@st.cache_data(ttl=2)  # Cache for 2 seconds
def get_data():
    if USE_API:
        try:
            # Increased timeout to 5 seconds
            response = requests.get(API_URL, timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                # Packets DataFrame
                df_packets = pd.DataFrame(data.get('packets', []))
                if df_packets.empty:
                    df_packets = pd.DataFrame(columns=['id', 'time', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'flags', 'length', 'timestamp'])
                
                # Alerts DataFrame
                df_alerts = pd.DataFrame(data.get('alerts', []))
                if df_alerts.empty:
                    df_alerts = pd.DataFrame(columns=['id', 'time', 'type', 'src_ip', 'message', 'timestamp'])
                
                # Standardize alerts columns
                df_alerts = df_alerts.rename(columns={'message': 'details', 'type': 'attack_type'})
                # Calculate total count from API data
                count_val = data.get('total_packets', len(df_packets))
                total_alerts = data.get('total_alerts', len(df_alerts))
                total_blocked = data.get('total_blocked', 0)

                if not df_packets.empty and 'time' in df_packets.columns:
                    df_packets['timestamp'] = df_packets['time']
                    df_packets['time'] = pd.to_datetime(df_packets['timestamp'], unit='s').dt.strftime('%H:%M:%S')
                
                # Apply Intelligence (Always call to ensure columns exist)
                df_packets = analyze_traffic_metadata(df_packets)

                if not df_alerts.empty and 'time' in df_alerts.columns:
                    df_alerts['timestamp'] = df_alerts['time']
                    df_alerts['time'] = pd.to_datetime(df_alerts['timestamp'], unit='s').dt.strftime('%H:%M:%S')
                
                # Apply Intelligence (Always call to ensure columns exist)
                df_alerts = analyze_traffic_metadata(df_alerts)

                # Reputation Data
                reputation = data.get('reputation', {})

                return df_packets, df_alerts, count_val, total_alerts, total_blocked, reputation
            else:
                st.error(f"API returned status code {response.status_code}")
                # Return empty DFs with ALL necessary columns to prevent UI crashes
                empty_packets = pd.DataFrame(columns=['time', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'flags', 'length', 'Identity', 'Service'])
                empty_alerts = pd.DataFrame(columns=['time', 'attack_type', 'src_ip', 'details', 'Identity', 'Service'])
                return empty_packets, empty_alerts, 0, 0, 0, {}
        except Exception as e:
            st.error(f"API Connection Failed: {e}")
            empty_packets = pd.DataFrame(columns=['time', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'flags', 'length', 'Identity', 'Service'])
            empty_alerts = pd.DataFrame(columns=['time', 'attack_type', 'src_ip', 'details', 'Identity', 'Service'])
            return empty_packets, empty_alerts, 0, 0, 0, {}

    # Fallback to local DB (Legacy Mode)
    db_paths = ["guardian.db", "traffic.db", "sniffer/guardian.db", "../guardian.db"]
    db_path = None
    for path in db_paths:
        if os.path.exists(path):
            db_path = path
            break
    
    if not db_path:
        return None, None, None, None, None, {}

    try:
        conn = sqlite3.connect(db_path)
        
        # Get Packets
        packets_df = pd.read_sql_query(
            "SELECT id, timestamp, src_ip, dst_ip, dst_port, protocol, flags, length FROM packets ORDER BY id DESC LIMIT 100",
            conn
        )
        
        # Get Alerts
        alerts_df = pd.read_sql_query(
            "SELECT id, timestamp, attack_type, src_ip, details FROM alerts ORDER BY id DESC LIMIT 20",
            conn
        )
        
        # Get Stats (Total count)
        count_val = pd.read_sql_query("SELECT COUNT(*) as count FROM packets", conn).iloc[0]['count']
        
        conn.close()
        
        # Format timestamps
        if not packets_df.empty:
            packets_df['time'] = pd.to_datetime(packets_df['timestamp'], unit='s').dt.strftime('%H:%M:%S')
            packets_df = analyze_traffic_metadata(packets_df)
            
        if not alerts_df.empty:
            alerts_df['time'] = pd.to_datetime(alerts_df['timestamp'], unit='s').dt.strftime('%H:%M:%S')
            alerts_df = analyze_traffic_metadata(alerts_df)

        return packets_df, alerts_df, count_val, len(alerts_df), 0, {}

    except Exception as e:
        st.error(f"Error reading database: {e}")
        return None, None, None, None, None, {}

# Main Layout
col1, col2, col3 = st.columns(3)

# Auto-refresh logic (using a placeholder to avoid full reruns if possible, but st.rerun is standard)
if st.button("🔄 Refresh Data"):
    st.rerun()

# Fetch Data
packets, alerts, total_count, total_alerts, total_blocked, reputation = get_data()

API_TOKEN = "SECRET_GUARDIAN_TOKEN"

def clear_logs():
    if USE_API:
        try:
            requests.delete(f"http://localhost:8080/logs", headers={"Authorization": f"Bearer {API_TOKEN}"})
            st.success("Logs cleared!")
            time.sleep(1)
            st.rerun()
        except Exception as e:
            st.error(f"Failed to clear logs: {e}")

def unblock_ip_ui(ip):
    if USE_API:
        try:
            requests.post(f"http://localhost:8080/unblock", json={"ip": ip}, headers={"Authorization": f"Bearer {API_TOKEN}"})
            st.success(f"Unblocked {ip}!")
            time.sleep(1)
            st.rerun()
        except Exception as e:
            st.error(f"Failed to unblock {ip}: {e}")

if packets is None:
    st.warning("⚠️ Waiting for Traffic... (API or Database not found/empty)")
    st.info("Make sure the API server is running: `python -m server.api`")
    st.stop()

# --- Security Health Header ---
if total_blocked > 0:
    st.error(f"🚨 SECURITY STATUS: CRITICAL - {total_blocked} Attacks Blocked")
elif total_alerts > 0:
    st.warning(f"⚠️ SECURITY STATUS: ATTENTION - {total_alerts} Anomalies Detected")
else:
    st.success("✅ SECURITY STATUS: CLEAR - No threats detected")

# Metrics
with col1:
    st.metric(label="Total Packets Captured", value=total_count)
    if st.button("🗑️ Clear All Logs"):
        clear_logs()

with col2:
    if not packets.empty:
        # Calculate approximate packets/sec (simple heuristic)
        st.metric(label="Last Packet Seen", value=packets.iloc[0]['time'])

# Tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["🚦 Live Traffic", "🚨 Security Alerts", "🧠 ML Insights", "🌍 Threat Map", "🚫 Blocked IPs", "📚 Education", "⚙️ System Control"])

with tab1:
    st.subheader("Recent Packets")
    st.dataframe(
        packets[['time', 'Identity', 'src_ip', 'dst_ip', 'Service', 'dst_port', 'protocol', 'length']],
        hide_index=True,
        use_container_width=True
    )

with tab2:
    st.subheader("Detected Threats")
    if alerts.empty:
        st.success("✅ No threats detected recently.")
    else:
        # Display DataFrame
        st.dataframe(
            alerts[['time', 'attack_type', 'src_ip', 'details', 'Identity', 'Service']],
            use_container_width=True,
            hide_index=True
        )
        
        # Display distinct visual alerts
        for _, alert in alerts.iterrows():
            if alert['attack_type'] == "FIREWALL_BLOCK":
                st.error(f"🔴 **BLOCKED**: {alert['src_ip']} ({alert.get('Identity', 'Unknown')}) - {alert['details']}")
            elif alert['attack_type'] == "Machine Learning":
                st.warning(f"🟡 **FLAGGED (AI)**: {alert['src_ip']} ({alert.get('Identity', 'Unknown')}) - {alert['details']}")
            else:
                st.info(f"ℹ️ **DETECTED**: {alert['attack_type']} from {alert['src_ip']} - {alert['details']}")

with tab3:
    st.header("🧠 Machine Learning Insights")
    st.info("The Isolation Forest model is analyzing packets for anomalies and bot-like behavior.")
    
    # Trust Score Gauge (Average of last seen IPs)
    if reputation:
        avg_trust = sum(reputation.values()) / len(reputation)
        st.write(f"### Overall Network Trust: {avg_trust:.1f}%")
        st.progress(avg_trust / 100)
        if avg_trust < 50:
            st.warning("⚠️ Low network trust detected. Several IPs are behaving suspiciously.")
        else:
            st.success("🛡️ High network trust. Most traffic patterns are within normal bounds.")

    # Filter for ML / Timing alerts
    ml_alerts = alerts[alerts['attack_type'].isin(["Machine Learning", "Cognitive Analytics"])]
    if ml_alerts.empty:
        st.success("No ML anomalies detected yet. Traffic looks normal.")
    else:
        st.dataframe(ml_alerts[['time', 'src_ip', 'details', 'Identity', 'Service']], hide_index=True)
        
    st.subheader("Feature Distribution (Last 100 Packets)")
    if not packets.empty and 'length' in packets.columns and 'dst_port' in packets.columns:
        # Check if we have valid non-null data to plot
        if not packets[['length', 'dst_port']].isnull().all().all():
            st.scatter_chart(packets, x='length', y='dst_port', color='#FF4B4B')
        else:
            st.info("Gathering more data for the distribution chart...")
    else:
        st.info("Gathering more data for the distribution chart...")



# --- GEOIP LOGIC ---
# The `is_private` function above is now used for general IP classification.
# This `get_location` function still needs to handle its own "Local Network" logic
# because it's specifically about external API calls.
@st.cache_data(ttl=3600)  # Cache for 1 hour to respect API limits
def get_location(ip):
    # Skip private IPs
    if is_private(ip): # Using the new is_private here
        return None, None, "Local Network"
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data['lat'], data['lon'], data['country']
    except:
        pass
    return None, None, "Unknown"

# Resolve IPs efficiently
unique_src_ips = packets['src_ip'].unique() if not packets.empty else []
public_ips = [ip for ip in unique_src_ips if not is_private(ip)]

map_data = []

# Limit resolutions to avoid freezing (check top 20 PUBLIC IPs)
for ip in public_ips[:20]:
    lat, lon, country = get_location(ip)
    if lat and lon:
        map_data.append({'lat': lat, 'lon': lon, 'ip': ip, 'country': country})

map_df = pd.DataFrame(map_data)

with tab4:
    st.header("🌍 Global Threat Map")
    st.info("Visualizing source IP locations (ignoring local network). Data via ip-api.com.")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        if not map_df.empty:
            st.map(map_df)
        else:
            st.warning("No external traffic sources detected yet (or API limit reached).")
            
    with col2:
        st.metric("Total Public IPs", len(public_ips))
        if not map_df.empty:
            st.dataframe(map_df[['ip', 'country']], hide_index=True)

with tab5:
    st.subheader("🚫 Firewall Control & Reputation")
    
    # Show Reputation Scores
    if reputation:
        st.write("### 🏅 Recent IP Trust Scores")
        rep_df = pd.DataFrame([{"IP": k, "Trust Score": v} for k, v in reputation.items()])
        st.dataframe(rep_df, hide_index=True, use_container_width=True)

    st.write("### Currently Blocked IPs")
    
    # Security Status Header
    total_blocked_unique_ips = alerts[alerts['attack_type'] == "FIREWALL_BLOCK"]['src_ip'].nunique()
    firewall_errors = alerts[alerts['attack_type'] == "FIREWALL_ERROR"]
    
    if not firewall_errors.empty:
        st.error("⚠️ SYSTEM WARNING: Firewall blocks are failing! Please restart Project Guardian as Administrator.")
    
    # Filter for Block alerts
    blocked_alerts = alerts[alerts['attack_type'] == "FIREWALL_BLOCK"]
    
    if blocked_alerts.empty:
        st.success("✅ No IPs have been blocked yet. Traffic is safe.")
    else:
        st.error(f"🛑 Total IPs Blocked: {len(blocked_alerts)}")
        st.dataframe(blocked_alerts[['time', 'src_ip', 'details']], hide_index=True)
        
        # Unblock UI
        st.subheader("Manage Active Blocks")
        unique_blocked = blocked_alerts['src_ip'].unique()
        ip_to_unblock = st.selectbox("Select IP to Unblock:", unique_blocked)
        if st.button(f"🔓 Unblock {ip_to_unblock}"):
            unblock_ip_ui(ip_to_unblock)

with tab6:
    st.header("📚 Education & Live Analysis")
    
    # Live Analysis Section
    if not alerts.empty:
        st.subheader("🕵️ Live Incident Explanation")
        recent_attack = alerts.iloc[0]['attack_type']
        if recent_attack == "Deep Packet Inspection":
            st.info("💡 **DPI Alert**: Guardian read the content of a packet and found malicious code (like an SQL injection). This is the most accurate form of detection.")
        elif recent_attack == "Port Scan":
            st.info("💡 **Port Scan**: Someone is 'knocking on every door' of your computer to see what's open. Guardian has stopped them from looking further.")
        elif recent_attack == "Machine Learning":
            st.info("💡 **ML Anomaly**: This traffic doesn't follow normal patterns. It might be a new type of attack or an app behaving very strangely.")
        elif recent_attack == "FIREWALL_BLOCK":
            st.info("💡 **Firewall Block**: Guardian has officially disconnected a suspicious IP to keep your network safe.")

    st.subheader("Network Security Concepts")
    
    with st.expander("What is a SYN Flood?"):
        st.markdown("""
        **SYN Flood** is a type of Denial of Service (DoS) attack.
        
        1.  **Normal Handshake**: A computer sends a **SYN** (Synchronize) packet to connect. The server replies with **SYN-ACK**. The computer replies **ACK**. Connection established!
        2.  **The Attack**: The attacker sends thousands of **SYN** packets but NEVER sends the final **ACK**.
        3.  **The Result**: The server waits for the ACKs that never come, filling up its memory and crashing, blocking real users.
        
        *Project Guardian detects this by counting how many SYN packets a single IP sends per second.*
        """)

    with st.expander("What is a Port Scan?"):
        st.markdown("""
        **Port Scanning** is like a thief checking every door and window in a house to see which one is unlocked.
        
        *   **Hacker**: Connects to Port 21 (FTP)... Closed.
        *   **Hacker**: Connects to Port 80 (HTTP)... Open!
        *   **Hacker**: Connects to Port 22 (SSH)... Open!
        
        Once they know which "doors" (ports) are open, they know what weaknesses to exploit.
        
        *Project Guardian detects this when one IP accesses many different ports on the same destination quickly.*
        """)
        
    with st.expander("Understanding TCP Flags"):
        st.table(pd.DataFrame([
            {"Flag": "SYN (2)", "Meaning": "Start Connection"},
            {"Flag": "ACK (16)", "Meaning": "Acknowledge Data"},
            {"Flag": "FIN (1)", "Meaning": "End Connection"},
            {"Flag": "RST (4)", "Meaning": "Reset/Crash Connection"},
            {"Flag": "PSH (8)", "Meaning": "Push Data Immediately"},
        ]))

with tab7:
    st.header("⚙️ Background Service Manager")
    st.info("Guardian is designed to run 24/7. Use this tab to monitor the background processes.")
    
    # Read PIDs from guardian_pids.json (Absolute Path)
    pids = {}
    pid_path = os.path.join(ROOT_DIR, "guardian_pids.json")
    
    if os.path.exists(pid_path):
        try:
            with open(pid_path, "r") as f:
                pids = json.load(f)
        except:
            pass
            
    col1, col2, col3 = st.columns(3)
    with col1:
        st.write("**API Server**")
        st.code(f"PID: {pids.get('api', 'Offline')}")
    with col2:
        st.write("**Sniffer**")
        st.code(f"PID: {pids.get('sniffer', 'Offline')}")
    with col3:
        st.write("**Dashboard**")
        st.code(f"PID: {pids.get('dashboard', 'Offline')}")
        
    st.markdown("---")
    st.subheader("🧹 Maintenance")
    if st.button("🔥 Reset System Logs", type="primary"):
        try:
            headers = {"Authorization": f"Bearer {API_TOKEN}"}
            resp = requests.delete(f"http://localhost:8080/logs", headers=headers)
            if resp.status_code == 200:
                st.success("Clean Slate! All old logs and blocks cleared. Redirecting...")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Failed to clear logs.")
        except Exception as e:
            st.error(f"Error: {e}")
    st.caption("This will remove all packet history and alerts from the database for a fresh start.")

    st.divider()
    
    if st.button("🛑 Stop All Background Services"):
        if os.name == 'nt':
            # Use the manager script to stop
            subprocess.run([sys.executable, "guardian.py", "stop"])
            st.warning("Shutdown command sent. You will lose connection to this dashboard in 3 seconds.")
            time.sleep(3)
            st.rerun()
            
    st.markdown("""
    ### 🔋 How to Run 24/7 (Background Mode)
    1.  Close all your open terminals.
    2.  Open **one** terminal.
    3.  Type: `python guardian.py start [index]` (replace `[index]` with your interface number, e.g., `0`).
    4.  **Close the terminal.** Guardian will keep running in the background!
    """)

