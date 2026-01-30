"""
Network Traffic Analyzer with Advanced Anomaly Detection
A comprehensive packet capture and analysis tool with security features
"""

import time
import sqlite3
import json
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, conf
import threading
import csv
import sys
import random

class NetworkAnalyzer:
    """Main class for network traffic analysis and anomaly detection"""
    
    def __init__(self, db_name="network_traffic.db", alert_threshold=50, time_window=10):
        """
        Initialize the Network Analyzer
        
        Args:
            db_name: SQLite database filename for logging
            alert_threshold: Number of packets from same IP to trigger alert
            time_window: Time window in seconds for anomaly detection
        """
        self.db_name = db_name
        self.alert_threshold = alert_threshold
        self.time_window = time_window
        
        # Statistics tracking
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.total_bytes = 0
        
        # Anomaly detection tracking
        self.ip_timestamps = defaultdict(lambda: deque())
        self.port_scan_attempts = defaultdict(set)
        self.suspicious_ips = set()
        self.alerts = []
        
        # Initialize database
        self.init_database()
        
        # Threading for real-time stats
        self.running = True
        self.stats_thread = None
        
    def init_database(self):
        """Initialize SQLite database for packet logging"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dest_port INTEGER,
                packet_size INTEGER,
                flags TEXT,
                is_suspicious INTEGER DEFAULT 0,
                alert_reason TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                source_ip TEXT,
                description TEXT,
                severity TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"[OK] Database initialized: {self.db_name}")
    
    def log_packet(self, packet_data, is_suspicious=False, alert_reason=""):
        """Log packet to database"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO packets (timestamp, source_ip, dest_ip, protocol, 
                                src_port, dest_port, packet_size, flags, 
                                is_suspicious, alert_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_data['timestamp'],
            packet_data['source_ip'],
            packet_data['dest_ip'],
            packet_data['protocol'],
            packet_data.get('src_port'),
            packet_data.get('dest_port'),
            packet_data['packet_size'],
            packet_data.get('flags', ''),
            int(is_suspicious),
            alert_reason
        ))
        
        conn.commit()
        conn.close()
    
    def log_alert(self, alert_type, source_ip, description, severity="MEDIUM"):
        """Log security alert to database"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, source_ip, description, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, alert_type, source_ip, description, severity))
        
        conn.commit()
        conn.close()
        
        # Store in memory for quick access
        self.alerts.append({
            'timestamp': timestamp,
            'type': alert_type,
            'source_ip': source_ip,
            'description': description,
            'severity': severity
        })
    
    def extract_packet_info(self, packet):
        """Extract relevant information from captured packet"""
        packet_info = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'source_ip': None,
            'dest_ip': None,
            'protocol': 'UNKNOWN',
            'packet_size': len(packet),
            'src_port': None,
            'dest_port': None,
            'flags': ''
        }
        
        # Extract IP layer information
        if IP in packet:
            packet_info['source_ip'] = packet[IP].src
            packet_info['dest_ip'] = packet[IP].dst
            
            # Extract protocol-specific information
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dest_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dest_port'] = packet[UDP].dport
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['flags'] = str(packet[ICMP].type)
                
        elif ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['source_ip'] = packet[ARP].psrc
            packet_info['dest_ip'] = packet[ARP].pdst
        
        return packet_info
    
    def detect_anomalies(self, packet_info):
        """Detect various types of network anomalies"""
        source_ip = packet_info.get('source_ip')
        if not source_ip:
            return False, ""
        
        current_time = time.time()
        is_suspicious = False
        alert_reason = ""
        
        # 1. Flooding Attack Detection
        self.ip_timestamps[source_ip].append(current_time)
        
        # Remove timestamps outside the time window
        while (self.ip_timestamps[source_ip] and 
               current_time - self.ip_timestamps[source_ip][0] > self.time_window):
            self.ip_timestamps[source_ip].popleft()
        
        packet_rate = len(self.ip_timestamps[source_ip])
        
        if packet_rate >= self.alert_threshold:
            is_suspicious = True
            alert_reason = f"FLOODING: {packet_rate} packets in {self.time_window}s"
            if source_ip not in self.suspicious_ips:
                self.suspicious_ips.add(source_ip)
                self.log_alert(
                    "FLOODING_ATTACK",
                    source_ip,
                    f"Detected {packet_rate} packets from {source_ip} in {self.time_window} seconds",
                    "HIGH"
                )
                print(f"\n[ALERT] Potential flooding attack from {source_ip}!")
                print(f"   Rate: {packet_rate} packets/{self.time_window}s")
        
        # 2. Port Scanning Detection
        if packet_info.get('dest_port'):
            dest_port = packet_info['dest_port']
            if source_ip not in self.port_scan_attempts:
                self.port_scan_attempts[source_ip] = set()
            
            self.port_scan_attempts[source_ip].add(dest_port)
            
            # Alert if scanning many ports
            if len(self.port_scan_attempts[source_ip]) >= 10:
                is_suspicious = True
                if not alert_reason:
                    alert_reason = f"PORT_SCAN: {len(self.port_scan_attempts[source_ip])} unique ports"
                self.log_alert(
                    "PORT_SCAN",
                    source_ip,
                    f"Possible port scan: {len(self.port_scan_attempts[source_ip])} unique ports accessed",
                    "MEDIUM"
                )
                print(f"\n[WARNING] ALERT: Possible port scan from {source_ip}!")
                print(f"   Ports accessed: {len(self.port_scan_attempts[source_ip])}")
        
        # 3. Suspicious Protocol Patterns
        if packet_info['protocol'] == 'ICMP' and packet_rate > 20:
            is_suspicious = True
            if not alert_reason:
                alert_reason = "ICMP_FLOOD"
            self.log_alert(
                "ICMP_FLOOD",
                source_ip,
                f"High ICMP traffic: {packet_rate} ICMP packets",
                "MEDIUM"
            )
        
        return is_suspicious, alert_reason
    
    def process_packet(self, packet):
        """Process each captured packet"""
        try:
            packet_info = self.extract_packet_info(packet)
            
            # Update statistics
            self.packet_count += 1
            self.protocol_stats[packet_info['protocol']] += 1
            self.total_bytes += packet_info['packet_size']
            
            if packet_info['source_ip']:
                self.ip_stats[packet_info['source_ip']] += 1
            
            if packet_info.get('dest_port'):
                self.port_stats[packet_info['dest_port']] += 1
            
            # Detect anomalies
            is_suspicious, alert_reason = self.detect_anomalies(packet_info)
            
            # Log packet
            self.log_packet(packet_info, is_suspicious, alert_reason)
            
            # Display packet info
            self.display_packet(packet_info, is_suspicious)
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def display_packet(self, packet_info, is_suspicious=False):
        """Display packet information in real-time"""
        status = "[SUSPICIOUS]" if is_suspicious else "[OK]"
        protocol = packet_info['protocol']
        src_ip = packet_info.get('source_ip', 'N/A')
        dst_ip = packet_info.get('dest_ip', 'N/A')
        size = packet_info['packet_size']
        
        port_info = ""
        if packet_info.get('src_port') and packet_info.get('dest_port'):
            port_info = f" {packet_info['src_port']} -> {packet_info['dest_port']}"
        
        print(f"{status} [{protocol:4}] {src_ip:15} -> {dst_ip:15}{port_info:20} Size: {size:5} bytes")
    
    def display_statistics(self):
        """Display real-time statistics"""
        while self.running:
            time.sleep(5)  # Update every 5 seconds
            if self.packet_count > 0:
                print("\n" + "="*70)
                print("[STATS] REAL-TIME STATISTICS")
                print("="*70)
                print(f"Total Packets Captured: {self.packet_count}")
                print(f"Total Data Transferred: {self.total_bytes:,} bytes ({self.total_bytes/1024:.2f} KB)")
                print(f"\nProtocol Distribution:")
                for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / self.packet_count) * 100
                    print(f"  {protocol:6}: {count:6} packets ({percentage:5.2f}%)")
                
                print(f"\nTop 5 Source IPs:")
                for ip, count in sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"  {ip:15}: {count:6} packets")
                
                print(f"\nTop 5 Destination Ports:")
                for port, count in sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"  Port {port:5}: {count:6} packets")
                
                if self.suspicious_ips:
                    print(f"\n[WARNING] Suspicious IPs Detected: {len(self.suspicious_ips)}")
                    for ip in list(self.suspicious_ips)[:5]:
                        print(f"  {ip}")
                
                print("="*70 + "\n")
    
    def generate_demo_packets(self, count=20):
        """Generate demo packets for testing when pcap is not available"""
        print("[INFO] DEMO MODE: Generating sample packets (pcap not available)")
        print("[INFO] Install Npcap for real packet capture on Windows")
        print("[INFO] Download from: https://nmap.org/npcap/\n")
        
        protocols = ['TCP', 'UDP', 'ICMP', 'TCP', 'UDP', 'TCP']
        sample_ips = [
            '192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.1',
            '192.168.1.50', '10.0.0.10', '192.168.1.200'
        ]
        ports = [80, 443, 22, 53, 3389, 8080, 21, 25, 110, 143]
        
        for i in range(count):
            # Create a demo packet structure
            protocol = random.choice(protocols)
            src_ip = random.choice(sample_ips)
            dst_ip = random.choice([ip for ip in sample_ips if ip != src_ip])
            
            # Create packet using Scapy
            if protocol == 'TCP':
                packet = IP(src=src_ip, dst=dst_ip) / TCP(
                    sport=random.choice(ports),
                    dport=random.choice(ports),
                    flags=random.choice(['S', 'A', 'PA'])
                )
            elif protocol == 'UDP':
                packet = IP(src=src_ip, dst=dst_ip) / UDP(
                    sport=random.choice(ports),
                    dport=random.choice(ports)
                )
            elif protocol == 'ICMP':
                packet = IP(src=src_ip, dst=dst_ip) / ICMP(type=8)
            else:
                packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=80, dport=443)
            
            # Process the demo packet
            self.process_packet(packet)
            
            # Small delay to simulate real capture
            time.sleep(0.1)
            
            # Simulate flooding attack for demo
            if i == count - 5:
                print("\n[INFO] Simulating flooding attack for demo...")
                for j in range(55):  # Trigger alert
                    flood_packet = IP(src='192.168.1.99', dst='10.0.0.1') / TCP(sport=50000+j, dport=80)
                    self.process_packet(flood_packet)
                    time.sleep(0.05)
    
    def start_capture(self, interface=None, count=0, timeout=None, demo_mode=False):
        """
        Start capturing network packets
        
        Args:
            interface: Network interface to capture on (None = default)
            count: Number of packets to capture (0 = infinite)
            timeout: Capture timeout in seconds (None = infinite)
            demo_mode: Use demo mode if pcap not available
        """
        print("\n" + "="*70)
        print("[SHIELD] NETWORK TRAFFIC ANALYZER - Starting Capture")
        print("="*70)
        print(f"Interface: {interface or 'Default'}")
        print(f"Alert Threshold: {self.alert_threshold} packets/{self.time_window}s")
        print(f"Database: {self.db_name}")
        print("="*70 + "\n")
        
        # Start statistics display thread
        self.stats_thread = threading.Thread(target=self.display_statistics, daemon=True)
        self.stats_thread.start()
        
        try:
            # Try real packet capture first
            sniff(
                iface=interface,
                prn=self.process_packet,
                count=count,
                timeout=timeout,
                store=False
            )
        except (RuntimeError, OSError) as e:
            if "winpcap" in str(e).lower() or "pcap" in str(e).lower() or demo_mode:
                # Fall back to demo mode
                if count == 0:
                    count = 50  # Default demo count
                self.generate_demo_packets(count)
            else:
                raise
        except KeyboardInterrupt:
            print("\n\n[STOP] Capture stopped by user")
        finally:
            self.running = False
            self.generate_summary()
    
    def generate_summary(self):
        """Generate final summary report"""
        print("\n" + "="*70)
        print("[REPORT] FINAL SUMMARY REPORT")
        print("="*70)
        print(f"Total Packets Analyzed: {self.packet_count}")
        print(f"Total Alerts Generated: {len(self.alerts)}")
        print(f"Suspicious IPs Identified: {len(self.suspicious_ips)}")
        print(f"Data Logged to: {self.db_name}")
        print("="*70)
    
    def export_to_csv(self, filename="network_traffic_export.csv"):
        """Export packet data to CSV file"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM packets')
        rows = cursor.fetchall()
        
        # Get column names
        column_names = [description[0] for description in cursor.description]
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(column_names)
            writer.writerows(rows)
        
        conn.close()
        print(f"[OK] Data exported to {filename}")
    
    def export_alerts_to_json(self, filename="alerts_export.json"):
        """Export alerts to JSON file"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM alerts')
        rows = cursor.fetchall()
        column_names = [description[0] for description in cursor.description]
        
        alerts_data = [dict(zip(column_names, row)) for row in rows]
        
        with open(filename, 'w') as jsonfile:
            json.dump(alerts_data, jsonfile, indent=2)
        
        conn.close()
        print(f"[OK] Alerts exported to {filename}")


def main():
    """Main function to run the network analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer with Anomaly Detection')
    parser.add_argument('-i', '--interface', type=str, default=None,
                       help='Network interface to capture on (default: auto-detect)')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 = infinite)')
    parser.add_argument('-t', '--timeout', type=int, default=None,
                       help='Capture timeout in seconds')
    parser.add_argument('--threshold', type=int, default=50,
                       help='Alert threshold for flooding detection (default: 50)')
    parser.add_argument('--window', type=int, default=10,
                       help='Time window in seconds for anomaly detection (default: 10)')
    parser.add_argument('--export-csv', action='store_true',
                       help='Export captured data to CSV after capture')
    parser.add_argument('--export-alerts', action='store_true',
                       help='Export alerts to JSON after capture')
    parser.add_argument('--demo', action='store_true',
                       help='Use demo mode (generate sample packets)')
    
    args = parser.parse_args()
    
    # Create analyzer instance
    analyzer = NetworkAnalyzer(
        alert_threshold=args.threshold,
        time_window=args.window
    )
    
    try:
        # Start capture
        analyzer.start_capture(
            interface=args.interface,
            count=args.count,
            timeout=args.timeout,
            demo_mode=args.demo
        )
    finally:
        # Export data if requested
        if args.export_csv:
            analyzer.export_to_csv()
        if args.export_alerts:
            analyzer.export_alerts_to_json()


if __name__ == "__main__":
    main()
