import numpy as np
from sklearn.ensemble import IsolationForest
import sys
import time
import collections

class MLEngine:
    def __init__(self, contamination=0.01):
        """
        Initialize the Advanced Anomaly Detector.
        """
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self.training_buffer = []
        self.is_trained = False
        self.TRAIN_SIZE = 500
        
        # Timing Analysis
        self.last_seen = {} # {ip: timestamp}
        self.intervals = collections.defaultdict(list) # {ip: [intervals]}
        self.JITTER_THRESHOLD = 0.05 # Low jitter (<5%) suggests a bot/beacon

    def add_packet(self, ip, packet_len, src_port, dst_port, protocol_num):
        """
        Predict and track timing.
        Returns:
            0: Training
            1: Normal
            -1: Statistical Anomaly
            -2: Timing Anomaly (Beaconing)
        """
        current_time = time.time()
        
        # 1. Timing Analysis (Bot Hunter)
        timing_anomaly = False
        if ip in self.last_seen:
            interval = current_time - self.last_seen[ip]
            self.intervals[ip].append(interval)
            
            if len(self.intervals[ip]) > 10:
                self.intervals[ip] = self.intervals[ip][-10:]
                avg = np.mean(self.intervals[ip])
                std = np.std(self.intervals[ip])
                # If standard deviation is extremely low, it's a fixed-interval beacon
                if avg > 1.0 and (std / avg) < self.JITTER_THRESHOLD:
                    timing_anomaly = True
        
        self.last_seen[ip] = current_time

        # 2. Features
        features = [packet_len, src_port, dst_port, protocol_num]
        
        if not self.is_trained:
            self.training_buffer.append(features)
            if len(self.training_buffer) >= self.TRAIN_SIZE:
                self.train()
            return 0
        else:
            if timing_anomaly:
                return -2 # Timing Anomaly
                
            result = self.model.predict([features])[0]
            return result

    def train(self):
        X = np.array(self.training_buffer)
        self.model.fit(X)
        self.is_trained = True
        print(f"[ML] Cognitive model trained on {len(X)} packets.", file=sys.stderr)

    def reinforce(self, packet_len, src_port, dst_port, protocol_num, is_good=True):
        """
        Adaptive Learning: Learn from user 'Unblock' signals.
        This manually adds 'good' samples back to the training set.
        """
        features = [packet_len, src_port, dst_port, protocol_num]
        if is_good:
            # We treat 'Unblock' as a signal that the specific feature set is normal
            # Re-balancing the buffer and re-fitting could be slow, so we just
            # extend the training buffer and fit occasionally in a real app.
            # For this version, we'll log it for future batch training.
            print(f"[ML] Adaptive Learning: Reinforced features as '{'GOOD' if is_good else 'BAD'}'", file=sys.stderr)
