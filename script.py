#!/usr/bin/env python3
"""
Real-time Threat Detection System
Monitors system logs, network connections, and processes for suspicious activity
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import hashlib
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import psutil
import requests
from scapy.all import sniff, IP, TCP, UDP
import yara
import warnings
warnings.filterwarnings('ignore')

# Configuration
CONFIG = {
    'log_file': '/var/log/threat_detection.log',
    'alert_threshold': 5,  # Number of suspicious events before alert
    'scan_interval': 30,   # Seconds between scans
    'api_keys': {
        'virustotal': 'YOUR_VIRUSTOTAL_API_KEY',
        'abuseipdb': 'YOUR_ABUSEIPDB_API_KEY'
    },
    'monitor_paths': [
        '/bin', '/sbin', '/usr/bin', '/usr/sbin',
        '/etc', '/home', '/tmp', '/var/www'
    ],
    'suspicious_ports': [4444, 5555, 6666, 7777, 8888, 9999, 31337],
    'whitelist_ips': ['127.0.0.1', '192.168.1.0/24'],
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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['log_file']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
            '/var/log/auth.log',
            '/var/log/syslog',
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
    
    def analyze_log_entry(self, entry, log_source):
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
        """Monitor network traffic using scapy"""
        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check for suspicious ports
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    
                    if dport in CONFIG['suspicious_ports']:
                        self.alert(f"Suspicious port {dport} connection from {src_ip} to {dst_ip}", "SUSPICIOUS_PORT")
                    
                    # Detect port scanning patterns
                    self.detect_port_scan(src_ip, dport)
        
        # Start sniffing in background thread
        threading.Thread(
            target=lambda: sniff(prn=packet_callback, store=0),
            daemon=True
        ).start()
    
    def detect_port_scan(self, src_ip, port):
        """Detect port scanning activity"""
        scan_key = f"scan_{src_ip}"
        
        if not hasattr(self, 'port_scan_tracker'):
            self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'count': 0, 'first_seen': datetime.now()})
        
        tracker = self.port_scan_tracker[scan_key]
        tracker['ports'].add(port)
        tracker['count'] += 1
        
        # Alert if too many ports scanned in short time
        time_diff = (datetime.now() - tracker['first_seen']).seconds
        if len(tracker['ports']) > 10 and time_diff < 60:
            self.alert(f"Port scanning detected from {src_ip}: {len(tracker['ports'])} ports in {time_diff} seconds", "PORT_SCAN")
            del self.port_scan_tracker[scan_key]
    
    def monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'connections']):
                    try:
                        self.check_process(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(CONFIG['scan_interval'])
            except Exception as e:
                logger.error(f"Error monitoring processes: {e}")
    
    def check_process(self, proc_info):
        """Check a single process for suspicious activity"""
        # Check process name against suspicious list
        proc_name = proc_info.get('name', '').lower()
        for suspicious in self.detection_rules['suspicious_processes']:
            if suspicious in proc_name:
                self.alert(f"Suspicious process running: {proc_name} (PID: {proc_info['pid']})", "SUSPICIOUS_PROCESS")
        
        # Check for hidden processes (no executable path)
        if not proc_info.get('exe') and proc_info.get('name'):
            self.alert(f"Hidden process detected: {proc_info['name']} (PID: {proc_info['pid']})", "HIDDEN_PROCESS")
        
        # Check for cryptocurrency miners
        cmdline = ' '.join(proc_info.get('cmdline', []))
        miner_keywords = ['miner', 'pool', 'stratum', 'hashrate', '--algo']
        if any(keyword in cmdline.lower() for keyword in miner_keywords):
            self.alert(f"Cryptocurrency miner detected: {proc_name}", "CRYPTO_MINER")
    
    def scan_filesystem(self):
        """Scan filesystem for suspicious files and changes"""
        known_hashes = {}
        hash_file = 'known_hashes.json'
        
        if os.path.exists(hash_file):
            with open(hash_file, 'r') as f:
                known_hashes = json.load(f)
        
        while self.running:
            try:
                for path in CONFIG['monitor_paths']:
                    if os.path.exists(path):
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                filepath = os.path.join(root, file)
                                self.check_file(filepath, known_hashes)
                
                # Save known hashes
                with open(hash_file, 'w') as f:
                    json.dump(known_hashes, f)
                
                time.sleep(CONFIG['scan_interval'] * 2)
            except Exception as e:
                logger.error(f"Error scanning filesystem: {e}")
    
    def check_file(self, filepath, known_hashes):
        """Check a single file for suspicious characteristics"""
        try:
            # Calculate file hash
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Check if hash changed
            if filepath in known_hashes:
                if known_hashes[filepath] != file_hash:
                    self.alert(f"File modified: {filepath}", "FILE_MODIFIED")
            
            known_hashes[filepath] = file_hash
            
            # Check file permissions
            if os.access(filepath, os.X_OK):
                stat_info = os.stat(filepath)
                if stat_info.st_mode & 0o777 == 0o777:
                    self.alert(f"World-writable executable: {filepath}", "INSECURE_PERMISSIONS")
            
            # Check for suspicious file extensions
            suspicious_ext = ['.php', '.pl', '.py', '.sh', '.cgi']
            if any(filepath.endswith(ext) for ext in suspicious_ext):
                if '/tmp/' in filepath or '/dev/shm/' in filepath:
                    self.alert(f"Suspicious executable in temp directory: {filepath}", "TEMP_EXECUTABLE")
        
        except (PermissionError, FileNotFoundError, IsADirectoryError):
            pass
    
    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal (requires API key)"""
        api_key = CONFIG['api_keys'].get('virustotal')
        if not api_key or api_key == 'YOUR_VIRUSTOTAL_API_KEY':
            return None
        
        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                    return True
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
        
        return False
    
    def check_abuseipdb(self, ip_address):
        """Check IP against AbuseIPDB (requires API key)"""
        api_key = CONFIG['api_keys'].get('abuseipdb')
        if not api_key or api_key == 'YOUR_ABUSEIPDB_API_KEY':
            return None
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                result = response.json()
                abuse_score = result.get('data', {}).get('abuseConfidenceScore', 0)
                if abuse_score > 50:
                    return True
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
        
        return False
    
    def alert(self, message, alert_type):
        """Generate alert for suspicious activity"""
        timestamp = datetime.now().isoformat()
        alert_data = {
            'timestamp': timestamp,
            'type': alert_type,
            'message': message,
            'severity': self.calculate_severity(alert_type)
        }
        
        self.suspicious_events.append(alert_data)
        
        # Log alert
        logger.warning(f"[{alert_type}] {message}")
        
        # Check if we should send critical alert
        if self.should_escalate_alert(alert_type):
            self.send_critical_alert(alert_data)
    
    def calculate_severity(self, alert_type):
        """Calculate severity level for alert"""
        severity_map = {
            'PORT_SCAN': 'HIGH',
            'MALICIOUS_COMMAND': 'CRITICAL',
            'CRYPTO_MINER': 'HIGH',
            'HIDDEN_PROCESS': 'MEDIUM',
            'SUSPICIOUS_PROCESS': 'MEDIUM',
            'FILE_MODIFIED': 'MEDIUM',
            'INSECURE_PERMISSIONS': 'LOW',
            'TEMP_EXECUTABLE': 'HIGH',
            'LOG_ANALYSIS': 'MEDIUM'
        }
        return severity_map.get(alert_type, 'LOW')
    
    def should_escalate_alert(self, alert_type):
        """Determine if alert should be escalated"""
        recent_alerts = [a for a in self.suspicious_events 
                        if (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 300]
        
        if len(recent_alerts) > CONFIG['alert_threshold']:
            return True
        
        critical_types = ['CRYPTO_MINER', 'MALICIOUS_COMMAND', 'PORT_SCAN']
        return alert_type in critical_types
    
    def send_critical_alert(self, alert_data):
        """Send critical alert via available methods"""
        # Could be extended to send email, Slack message, etc.
        logger.critical(f"CRITICAL ALERT: {json.dumps(alert_data, indent=2)}")
        
        # Example: Send to syslog
        subprocess.run(['logger', '-t', 'THREAT_DETECTOR', '-p', 'alert', json.dumps(alert_data)])
    
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