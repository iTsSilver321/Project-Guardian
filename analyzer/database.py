import sqlite3
import time
from datetime import datetime

class TrafficDB:
    def __init__(self, db_path="guardian.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Table for raw packets
        c.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                flags INTEGER,
                length INTEGER
            )
        ''')
        
        # Table for alerts
        c.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                attack_type TEXT,
                src_ip TEXT,
                details TEXT
            )
        ''')
        
        # Indexes for performance
        c.execute('CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp)')
        
        conn.commit()
        conn.close()

    def log_packet(self, src_ip, dst_ip, dst_port, protocol, flags, length):
        """Log a single packet to the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, dst_port, protocol, flags, length)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (time.time(), src_ip, dst_ip, dst_port, protocol, flags, length))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB ERROR] Failed to log packet: {e}")

    def log_alert(self, attack_type, src_ip, details):
        """Log a security alert."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''
                INSERT INTO alerts (timestamp, attack_type, src_ip, details)
                VALUES (?, ?, ?, ?)
            ''', (time.time(), attack_type, src_ip, details))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB ERROR] Failed to log alert: {e}")

    def get_recent_packets(self, limit=100):
        """Get the most recent packets for the live feed."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            SELECT timestamp, src_ip, dst_ip, dst_port, protocol, flags, length
            FROM packets
            ORDER BY id DESC
            LIMIT ?
        ''', (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def get_alerts(self, limit=50):
        """Get recent alerts."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            SELECT timestamp, attack_type, src_ip, details
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        ''', (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def get_traffic_stats(self, seconds=60):
        """Get packet count in the last X seconds."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        cutoff = time.time() - seconds
        c.execute('SELECT COUNT(*) FROM packets WHERE timestamp > ?', (cutoff,))
        count = c.fetchone()[0]
        conn.close()
        return count
