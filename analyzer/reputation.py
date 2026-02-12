import time
import collections

class ReputationEngine:
    def __init__(self, block_threshold=0):
        """
        IP Reputation Engine.
        Scores range from 0 (Blocked) to 100 (Trusted).
        """
        self.scores = collections.defaultdict(lambda: 100)
        self.block_threshold = block_threshold
        self.last_update = time.time()
        self.recovery_rate = 1  # 1 point recovered per hour of clean traffic

    def update_score(self, ip, penalty):
        """Decrease score for bad behavior."""
        self.scores[ip] = max(0, self.scores[ip] - penalty)
        return self.scores[ip]

    def get_score(self, ip):
        """Get current trust score, applying recovery if time has passed."""
        now = time.time()
        hours_passed = (now - self.last_update) / 3600
        
        if hours_passed >= 1:
            for ip_addr in self.scores:
                if self.scores[ip_addr] < 100:
                    self.scores[ip_addr] = min(100, self.scores[ip_addr] + (self.recovery_rate * hours_passed))
            self.last_update = now
            
        return self.scores[ip]

    def is_blocked(self, ip):
        return self.scores[ip] <= self.block_threshold
