#!/usr/bin/env python3
"""
Log File Analyzer for Intrusion Detection
Detects suspicious patterns in Apache and SSH logs
"""

import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json
import csv
import os
import argparse
from pathlib import Path
import requests
import warnings
warnings.filterwarnings('ignore')

class LogAnalyzer:
    def __init__(self, apache_log_path=None, ssh_log_path=None):
        """Initialize the log analyzer with log file paths"""
        self.apache_log_path = apache_log_path
        self.ssh_log_path = ssh_log_path
        self.apache_data = []
        self.ssh_data = []
        self.suspicious_ips = set()
        self.threat_alerts = []
        self.ip_blacklist = set()
        
        # Regular expressions for log parsing
        self.apache_pattern = re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] '
            r'"(?P<method>\S+) (?P<url>\S+) \S+" '
            r'(?P<status>\d{3}) (?P<size>\d+) '
            r'"(?P<referer>.*?)" "(?P<user_agent>.*?)"'
        )
        
        self.ssh_pattern = re.compile(
            r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
            r'(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)'
        )
        
        # Failed login patterns for SSH
        self.ssh_failed_patterns = [
            r'Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)',
            r'Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)',
            r'Authentication failure for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ]
        
        # Thresholds for detection
        self.thresholds = {
            'brute_force': 10,  # Failed attempts per minute
            'dos': 100,         # Requests per minute
            'scan': 20          # Unique URLs per IP
        }
        
    def load_ip_blacklist(self, blacklist_file=None):
        """Load IP blacklist from file or public source"""
        # Built-in suspicious IPs (example)
        default_blacklist = {
            '192.168.1.100', '10.0.0.50', '172.16.0.1'
        }
        self.ip_blacklist.update(default_blacklist)
        
        if blacklist_file and os.path.exists(blacklist_file):
            with open(blacklist_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self.ip_blacklist.add(ip)
        else:
            # Try to fetch from public blacklist (optional)
            try:
                print("Fetching IP blacklist from public source...")
                # Using a sample blacklist URL - replace with actual source
                response = requests.get('https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', 
                                      timeout=5)
                if response.status_code == 200:
                    for line in response.text.split('\n'):
                        if line and not line.startswith('#'):
                            self.ip_blacklist.add(line.strip())
                print(f"Loaded {len(self.ip_blacklist)} blacklisted IPs")
            except:
                print("Could not fetch public blacklist, using default only")
    
    def parse_apache_logs(self):
        """Parse Apache access logs"""
        if not self.apache_log_path or not os.path.exists(self.apache_log_path):
            print(f"Apache log file not found: {self.apache_log_path}")
            return
        
        print(f"Parsing Apache logs: {self.apache_log_path}")
        with open(self.apache_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.apache_pattern.search(line)
                if match:
                    data = match.groupdict()
                    # Convert time to datetime object
                    try:
                        data['time'] = datetime.strptime(data['time'], '%d/%b/%Y:%H:%M:%S %z')
                    except:
                        data['time'] = datetime.now()
                    data['size'] = int(data['size']) if data['size'].isdigit() else 0
                    self.apache_data.append(data)
        
        print(f"Parsed {len(self.apache_data)} Apache log entries")
        
    def parse_ssh_logs(self):
        """Parse SSH authentication logs"""
        if not self.ssh_log_path or not os.path.exists(self.ssh_log_path):
            print(f"SSH log file not found: {self.ssh_log_path}")
            return
        
        print(f"Parsing SSH logs: {self.ssh_log_path}")
        current_year = datetime.now().year
        
        with open(self.ssh_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = self.ssh_pattern.search(line)
                if match:
                    data = match.groupdict()
                    # Parse time
                    try:
                        time_str = f"{data['month']} {data['day']} {data['time']}"
                        data['datetime'] = datetime.strptime(time_str, '%b %d %H:%M:%S')
                        data['datetime'] = data['datetime'].replace(year=current_year)
                    except:
                        data['datetime'] = datetime.now()
                    
                    # Check for failed login attempts
                    for pattern in self.ssh_failed_patterns:
                        ip_match = re.search(pattern, data['message'])
                        if ip_match:
                            data['failed_ip'] = ip_match.group('ip')
                            data['failed'] = True
                            break
                    else:
                        data['failed'] = False
                    
                    self.ssh_data.append(data)
        
        print(f"Parsed {len(self.ssh_data)} SSH log entries")
    
    def detect_brute_force(self):
        """Detect brute force attacks from SSH logs"""
        failed_attempts = defaultdict(list)
        
        for entry in self.ssh_data:
            if entry.get('failed') and entry.get('failed_ip'):
                ip = entry['failed_ip']
                failed_attempts[ip].append(entry['datetime'])
        
        brute_force_ips = []
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= self.thresholds['brute_force']:
                # Check time window
                attempts.sort()
                for i in range(len(attempts) - self.thresholds['brute_force'] + 1):
                    time_diff = (attempts[i + self.thresholds['brute_force'] - 1] - attempts[i]).total_seconds() / 60
                    if time_diff <= 1:  # Within 1 minute
                        brute_force_ips.append(ip)
                        self.threat_alerts.append({
                            'type': 'Brute Force Attack',
                            'ip': ip,
                            'attempts': len(attempts),
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat(),
                            'details': f"{len(attempts)} failed login attempts from {ip}"
                        })
                        break
        
        self.suspicious_ips.update(brute_force_ips)
        print(f"Detected {len(brute_force_ips)} brute force attempts")
        
    def detect_dos_attacks(self):
        """Detect DoS attacks from Apache logs"""
        if not self.apache_data:
            return
            
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(self.apache_data)
        df['time'] = pd.to_datetime(df['time'])
        
        # Group by IP and minute
        df['minute'] = df['time'].dt.floor('min')
        requests_per_ip_min = df.groupby(['ip', 'minute']).size().reset_index(name='count')
        
        dos_ips = []
        for _, row in requests_per_ip_min.iterrows():
            if row['count'] >= self.thresholds['dos']:
                ip = row['ip']
                dos_ips.append(ip)
                self.threat_alerts.append({
                    'type': 'DoS Attack',
                    'ip': ip,
                    'requests_per_minute': row['count'],
                    'severity': 'CRITICAL',
                    'timestamp': row['minute'].isoformat(),
                    'details': f"{row['count']} requests in one minute from {ip}"
                })
        
        self.suspicious_ips.update(dos_ips)
        print(f"Detected {len(dos_ips)} potential DoS attacks")
    
    def detect_port_scanning(self):
        """Detect port scanning behavior from Apache logs"""
        if not self.apache_data:
            return
            
        df = pd.DataFrame(self.apache_data)
        unique_urls_per_ip = df.groupby('ip')['url'].nunique()
        
        scan_ips = []
        for ip, unique_urls in unique_urls_per_ip.items():
            if unique_urls >= self.thresholds['scan']:
                scan_ips.append(ip)
                self.threat_alerts.append({
                    'type': 'Port/URL Scanning',
                    'ip': ip,
                    'unique_urls': unique_urls,
                    'severity': 'MEDIUM',
                    'timestamp': datetime.now().isoformat(),
                    'details': f"{unique_urls} unique URLs accessed by {ip}"
                })
        
        self.suspicious_ips.update(scan_ips)
        print(f"Detected {len(scan_ips)} potential scanning activities")
    
    def cross_reference_blacklist(self):
        """Cross-reference detected suspicious IPs with blacklist"""
        blacklist_matches = []
        for ip in self.suspicious_ips:
            if ip in self.ip_blacklist:
                blacklist_matches.append(ip)
                self.threat_alerts.append({
                    'type': 'Blacklisted IP Detected',
                    'ip': ip,
                    'severity': 'HIGH',
                    'timestamp': datetime.now().isoformat(),
                    'details': f"IP {ip} found in blacklist"
                })
        
        print(f"Found {len(blacklist_matches)} suspicious IPs in blacklist")
    
    def visualize_patterns(self):
        """Create visualizations of access patterns"""
        if not self.apache_data:
            print("No Apache data to visualize")
            return
        
        # Create DataFrame
        df = pd.DataFrame(self.apache_data)
        df['time'] = pd.to_datetime(df['time'])
        
        # Set up the plot style
        plt.style.use('seaborn-v0_8-darkgrid')
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # 1. Top 10 suspicious IPs
        ip_counts = df['ip'].value_counts().head(10)
        axes[0, 0].bar(range(len(ip_counts)), ip_counts.values)
        axes[0, 0].set_xticks(range(len(ip_counts)))
        axes[0, 0].set_xticklabels(ip_counts.index, rotation=45, ha='right')
        axes[0, 0].set_title('Top 10 Most Active IPs')
        axes[0, 0].set_xlabel('IP Address')
        axes[0, 0].set_ylabel('Request Count')
        
        # 2. Time series of requests
        df.set_index('time', inplace=True)
        requests_per_hour = df.resample('H').size()
        axes[0, 1].plot(requests_per_hour.index, requests_per_hour.values, 
                        marker='o', linewidth=2, markersize=4)
        axes[0, 1].set_title('Requests Over Time')
        axes[0, 1].set_xlabel('Time')
        axes[0, 1].set_ylabel('Number of Requests')
        axes[0, 1].tick_params(axis='x', rotation=45)
        
        # 3. HTTP Status Code Distribution
        status_counts = df['status'].value_counts().sort_index()
        axes[1, 0].pie(status_counts.values, labels=status_counts.index, 
                       autopct='%1.1f%%', startangle=90)
        axes[1, 0].set_title('HTTP Status Code Distribution')
        
        # 4. Suspicious IPs vs Total
        total_ips = len(df['ip'].unique())
        suspicious_count = len(self.suspicious_ips)
        axes[1, 1].bar(['Total IPs', 'Suspicious IPs'], [total_ips, suspicious_count], 
                       color=['skyblue', 'red'])
        axes[1, 1].set_title('Suspicious vs Total IPs')
        axes[1, 1].set_ylabel('Number of IPs')
        
        plt.tight_layout()
        plt.savefig('threat_analysis_report.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("Visualization saved as 'threat_analysis_report.png'")
    
    def export_incident_report(self, output_format='json'):
        """Export incident report in specified format"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Prepare report data
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_alerts': len(self.threat_alerts),
            'suspicious_ips': list(self.suspicious_ips),
            'threat_alerts': self.threat_alerts,
            'statistics': {
                'total_apache_entries': len(self.apache_data),
                'total_ssh_entries': len(self.ssh_data),
                'blacklisted_ips': len(self.ip_blacklist)
            }
        }
        
        if output_format == 'json':
            filename = f'incident_report_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"JSON report saved as {filename}")
            
        elif output_format == 'csv':
            # Export alerts as CSV
            filename = f'incident_alerts_{timestamp}.csv'
            with open(filename, 'w', newline='') as f:
                if self.threat_alerts:
                    writer = csv.DictWriter(f, fieldnames=self.threat_alerts[0].keys())
                    writer.writeheader()
                    writer.writerows(self.threat_alerts)
            print(f"CSV report saved as {filename}")
            
        elif output_format == 'both':
            self.export_incident_report('json')
            self.export_incident_report('csv')
    
    def print_summary(self):
        """Print a summary of findings"""
        print("\n" + "="*60)
        print("THREAT ANALYSIS SUMMARY")
        print("="*60)
        print(f"Total Apache Log Entries: {len(self.apache_data)}")
        print(f"Total SSH Log Entries: {len(self.ssh_data)}")
        print(f"Suspicious IPs Found: {len(self.suspicious_ips)}")
        print(f"Total Threats Detected: {len(self.threat_alerts)}")
        print("\nThreat Breakdown:")
        
        threat_types = Counter([alert['type'] for alert in self.threat_alerts])
        for threat_type, count in threat_types.items():
            print(f"  - {threat_type}: {count}")
        
        if self.suspicious_ips:
            print(f"\nSuspicious IPs: {', '.join(list(self.suspicious_ips)[:10])}")
        
        print("="*60 + "\n")
    
    def run_full_analysis(self, blacklist_file=None):
        """Run the complete log analysis pipeline"""
        print("Starting Log Analysis...")
        print("-" * 40)
        
        # Parse logs
        self.parse_apache_logs()
        self.parse_ssh_logs()
        
        # Load blacklist
        self.load_ip_blacklist(blacklist_file)
        
        # Detect threats
        self.detect_brute_force()
        self.detect_dos_attacks()
        self.detect_port_scanning()
        
        # Cross-reference with blacklist
        self.cross_reference_blacklist()
        
        # Print summary
        self.print_summary()
        
        # Create visualizations
        if self.apache_data:
            self.visualize_patterns()
        
        # Export reports
        self.export_incident_report('both')
        
        print("Analysis Complete!")


def create_sample_logs():
    """Create sample log files for testing"""
    # Sample Apache log
    sample_apache = """
192.168.1.100 - - [01/Jan/2024:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [01/Jan/2024:12:00:02 +0000] "GET /login.php HTTP/1.1" 200 5678 "-" "Mozilla/5.0"
192.168.1.100 - - [01/Jan/2024:12:00:03 +0000] "POST /login.php HTTP/1.1" 401 123 "-" "Mozilla/5.0"
10.0.0.50 - - [01/Jan/2024:12:00:04 +0000] "GET /wp-admin HTTP/1.1" 404 456 "-" "python-requests"
10.0.0.50 - - [01/Jan/2024:12:00:05 +0000] "GET /phpmyadmin HTTP/1.1" 404 789 "-" "python-requests"
172.16.0.1 - - [01/Jan/2024:12:00:06 +0000] "GET / HTTP/1.1" 200 2345 "-" "Mozilla/5.0"
"""
    
    # Sample SSH log
    sample_ssh = """
Jan 1 12:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 12345 ssh2
Jan 1 12:00:02 server sshd[1235]: Failed password for root from 192.168.1.100 port 12346 ssh2
Jan 1 12:00:03 server sshd[1236]: Failed password for invalid user test from 10.0.0.50 port 54321 ssh2
Jan 1 12:00:04 server sshd[1237]: Accepted password for john from 172.16.0.1 port 12345 ssh2
"""
    
    # Write sample files
    with open('sample_apache.log', 'w') as f:
        f.write(sample_apache)
    
    with open('sample_ssh.log', 'w') as f:
        f.write(sample_ssh)
    
    print("Sample log files created: sample_apache.log, sample_ssh.log")


def main():
    """Main function to run the log analyzer"""
    parser = argparse.ArgumentParser(description='Log File Analyzer for Intrusion Detection')
    parser.add_argument('--apache', help='Path to Apache access log file')
    parser.add_argument('--ssh', help='Path to SSH auth log file')
    parser.add_argument('--blacklist', help='Path to IP blacklist file (optional)')
    parser.add_argument('--create-sample', action='store_true', help='Create sample log files for testing')
    
    args = parser.parse_args()
    
    if args.create_sample:
        create_sample_logs()
        return
    
    if not args.apache and not args.ssh:
        print("Please provide at least one log file path")
        print("Example: python log_analyzer.py --apache access.log --ssh auth.log")
        print("Or use --create-sample to create test files")
        return
    
    # Initialize and run analyzer
    analyzer = LogAnalyzer(apache_log_path=args.apache, ssh_log_path=args.ssh)
    analyzer.run_full_analysis(blacklist_file=args.blacklist)


if __name__ == "__main__":
    main()
