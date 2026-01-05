"""
Real-time Threat Detection System
Monitors system logs, network connections, and processes for suspicious activity
"""

import os
import sys
import threading
import time
import json
import re
from datetime import datetime
from collections import defaultdict, deque

import psutil

# Configuration
CONFIG = {
    'signatures': {
        'malicious_patterns': [
            r'rm -rf /',
            r'chmod 777',
            r'wget.*http://',
            r'curl.*http://',
            r'base64.*decode',
            r'eval\(.*\)',
            r'exec\(.*\)',
            r'system\(.*\)',
            r'subprocess\.call',
            r'\/dev\/tcp\/',
            r'\/dev\/udp\/'
        ],
        'suspicious_processes': [
            'minerd', 'cpuminer', 'xmrig', 'ccminer',
            'nc', 'ncat', 'socat', 'netcat',
            'tcpdump', 'wireshark', 'tshark'
        ]
    }
}

class ThreatDetector:
    def __init__(self):
        self.suspicious_events = deque(maxlen=1000)
        self.known_malicious_hashes = set()
        self.detection_rules = self.load_rules()
        self.running = True

    def load_rules(self):
        """Load detection rules from file or default"""
        rules_file = 'detection_rules.json'
        if os.path.exists(rules_file):
            with open(rules_file, 'r') as f:                
                return json.load(f)
            
        return CONFIG['signatures']

    def monitor_system_logs(self):
        """Monitor system logs in real-time"""
        log_files = [
            '/var/log/syslog', 
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/messages'
        ]

        for log_file in log_files:
            if os.path.exists(log_file):
                threading.Thread(
                    target=self.tail_log, 
                    args=(log_file,), 
                    daemon=True
                ).start()

    def tail_log(self, log_file):
        """Tail a log file for real-time monitoring"""
        try:
            with open(log_file, 'r') as f:
                f.seek(0, 2)  # Go to end of file
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    self.analyze_log_entry(line, log_file)
        except Exception as e:
            logger.error(f"Error tailing {log_file}: {e}")
    
    def analyze_log_entry(self, entry, log_file):
        """Analyze log entry for suspicious patterns"""                
        suspicious_patterns = [
            (r'Failed password', 'Failed SSH login'),
            (r'authentication failure', 'Authentication failure'),
            (r'Invalid user', 'Invalid user attempt'),
            (r'POSSIBLE BREAK-IN ATTEMPT', 'Break-in attempt'),
            (r'port scan', 'Port scan detected'),
            (r'kernel:.*firewall.*DROP', 'Firewall block'),
            (r'root.*sudo.*ALL', 'Root privilege escalation')
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, entry, re.IGNORECASE):
                self.alert(f"{description}: {entry.strip()}", "LOG_ANALYSIS")
                break
        
        # Check for malicious patterns in commands
        for pattern in self.detection_rules['malicious_patterns']:
            if re.search(pattern, entry, re.IGNORECASE):
                self.alert(f"Malicious pattern in logs: {entry.strip()}", "MALICIOUS_COMMAND")

    def monitor_network_traffic(self):
        pass

    def monitor_processes(self):
        pass

    def scan_filesystem(self):
        pass
    
    def alert(self, message, alert_type):
        """Generate alert for suspicious activity"""
        
    def generate_report(self):
        """Generate threat detection report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_alerts': len(self.suspicious_events),
            'alerts_by_type': defaultdict(int),
            'recent_alerts': list(self.suspicious_events)[-10:],
            'system_info': {
                'hostname': os.uname().nodename,
                'uptime': psutil.boot_time(),
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent
            }
        }
        
        for alert in self.suspicious_events:
            report['alerts_by_type'][alert['type']] += 1

        report_file = f'threat_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Report generated: {report_file}")
        return report


    def start(self):
        """Start all monitoring threads"""
        logger.info("Starting threat detection system...")
        
        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_system_logs, daemon=True),
            threading.Thread(target=self.monitor_network_traffic, daemon=True),
            threading.Thread(target=self.monitor_processes, daemon=True),
            threading.Thread(target=self.scan_filesystem, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        logger.info("Threat detection system running. Press Ctrl+C to stop.")
        
        # Main loop
        try:
            while self.running:
                # Generate periodic report
                if int(time.time()) % 3600 == 0:  # Every hour
                    self.generate_report()
                
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down threat detection system...")
            self.running = False
            self.generate_report()
            sys.exit(0)

def main():
    """Main function"""
    # Check if running as root (required for some operations)
    if os.geteuid() != 0:
        logger.warning("Running without root privileges. Some features may be limited.")
    
    # Initialize and start detector
    detector = ThreatDetector()
    detector.start()

if __name__ == "__main__":
    main()