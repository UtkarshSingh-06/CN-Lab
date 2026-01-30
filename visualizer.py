"""
Real-time Network Traffic Visualization Dashboard
Creates interactive charts and graphs for network analysis
"""

import sqlite3
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from collections import defaultdict
from datetime import datetime
import time

class NetworkVisualizer:
    """Create visualizations from network traffic data"""
    
    def __init__(self, db_name="network_traffic.db"):
        self.db_name = db_name
        self.fig = None
        self.axes = None
        
    def get_statistics(self):
        """Fetch statistics from database"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Protocol distribution
        cursor.execute('''
            SELECT protocol, COUNT(*) as count 
            FROM packets 
            GROUP BY protocol
        ''')
        protocol_data = dict(cursor.fetchall())
        
        # Top source IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM packets 
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_ips = cursor.fetchall()
        
        # Top destination ports
        cursor.execute('''
            SELECT dest_port, COUNT(*) as count 
            FROM packets 
            WHERE dest_port IS NOT NULL
            GROUP BY dest_port 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_ports = cursor.fetchall()
        
        # Suspicious packets
        cursor.execute('SELECT COUNT(*) FROM packets WHERE is_suspicious = 1')
        suspicious_count = cursor.fetchone()[0]
        
        # Total packets
        cursor.execute('SELECT COUNT(*) FROM packets')
        total_packets = cursor.fetchone()[0]
        
        # Traffic over time (last 20 timestamps)
        cursor.execute('''
            SELECT timestamp, COUNT(*) as count 
            FROM packets 
            GROUP BY timestamp 
            ORDER BY timestamp DESC 
            LIMIT 20
        ''')
        time_data = cursor.fetchall()
        
        conn.close()
        
        return {
            'protocols': protocol_data,
            'top_ips': top_ips,
            'top_ports': top_ports,
            'suspicious': suspicious_count,
            'total': total_packets,
            'time_data': time_data
        }
    
    def create_dashboard(self):
        """Create a comprehensive dashboard with multiple charts"""
        stats = self.get_statistics()
        
        if stats['total'] == 0:
            print("No data found in database. Please capture some packets first.")
            return
        
        # Create figure with subplots
        self.fig, self.axes = plt.subplots(2, 2, figsize=(15, 10))
        self.fig.suptitle('Network Traffic Analysis Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Protocol Distribution (Pie Chart)
        ax1 = self.axes[0, 0]
        if stats['protocols']:
            protocols = list(stats['protocols'].keys())
            counts = list(stats['protocols'].values())
            colors = plt.cm.Set3(range(len(protocols)))
            ax1.pie(counts, labels=protocols, autopct='%1.1f%%', colors=colors, startangle=90)
            ax1.set_title('Protocol Distribution', fontweight='bold')
        
        # 2. Top Source IPs (Bar Chart)
        ax2 = self.axes[0, 1]
        if stats['top_ips']:
            ips = [ip[:15] + '...' if len(ip) > 15 else ip for ip, _ in stats['top_ips']]
            counts = [count for _, count in stats['top_ips']]
            ax2.barh(ips, counts, color='steelblue')
            ax2.set_xlabel('Packet Count')
            ax2.set_title('Top 10 Source IPs', fontweight='bold')
            ax2.invert_yaxis()
        
        # 3. Top Destination Ports (Bar Chart)
        ax3 = self.axes[1, 0]
        if stats['top_ports']:
            ports = [str(port) for port, _ in stats['top_ports']]
            counts = [count for _, count in stats['top_ports']]
            ax3.bar(ports, counts, color='coral')
            ax3.set_xlabel('Port Number')
            ax3.set_ylabel('Packet Count')
            ax3.set_title('Top 10 Destination Ports', fontweight='bold')
            ax3.tick_params(axis='x', rotation=45)
        
        # 4. Security Overview (Text + Stats)
        ax4 = self.axes[1, 1]
        ax4.axis('off')
        security_text = f"""
        🔒 SECURITY OVERVIEW
        
        Total Packets: {stats['total']:,}
        Suspicious Packets: {stats['suspicious']:,}
        Threat Level: {'HIGH' if stats['suspicious'] > stats['total'] * 0.1 else 'LOW'}
        
        Protocols Detected: {len(stats['protocols'])}
        Unique Source IPs: {len(stats['top_ips'])}
        Active Ports: {len(stats['top_ports'])}
        """
        ax4.text(0.1, 0.5, security_text, fontsize=12, 
                verticalalignment='center', family='monospace',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        plt.show()
    
    def create_protocol_chart(self):
        """Create a simple protocol distribution chart"""
        stats = self.get_statistics()
        
        if not stats['protocols']:
            print("No data available")
            return
        
        plt.figure(figsize=(10, 6))
        protocols = list(stats['protocols'].keys())
        counts = list(stats['protocols'].values())
        
        plt.bar(protocols, counts, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8'])
        plt.xlabel('Protocol')
        plt.ylabel('Packet Count')
        plt.title('Network Protocol Distribution', fontweight='bold')
        plt.grid(axis='y', alpha=0.3)
        
        # Add value labels on bars
        for i, v in enumerate(counts):
            plt.text(i, v + max(counts)*0.01, str(v), ha='center', va='bottom')
        
        plt.tight_layout()
        plt.show()
    
    def create_traffic_timeline(self):
        """Create a timeline chart of packet traffic"""
        stats = self.get_statistics()
        
        if not stats['time_data']:
            print("No time-series data available")
            return
        
        # Process time data
        timestamps = [row[0] for row in reversed(stats['time_data'])]
        counts = [row[1] for row in reversed(stats['time_data'])]
        
        plt.figure(figsize=(12, 6))
        plt.plot(range(len(timestamps)), counts, marker='o', linewidth=2, markersize=6)
        plt.xlabel('Time Index')
        plt.ylabel('Packet Count')
        plt.title('Packet Traffic Over Time', fontweight='bold')
        plt.grid(True, alpha=0.3)
        plt.fill_between(range(len(timestamps)), counts, alpha=0.3)
        
        plt.tight_layout()
        plt.show()
    
    def export_chart(self, filename="network_analysis.png"):
        """Export the dashboard as an image"""
        if self.fig:
            self.fig.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"✓ Chart exported to {filename}")


def main():
    """Main function for visualization"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Network Traffic Visualizer')
    parser.add_argument('--db', type=str, default='network_traffic.db',
                       help='Database file to visualize')
    parser.add_argument('--type', type=str, choices=['dashboard', 'protocol', 'timeline'],
                       default='dashboard', help='Type of visualization')
    parser.add_argument('--export', type=str, default=None,
                       help='Export chart to file (e.g., chart.png)')
    
    args = parser.parse_args()
    
    visualizer = NetworkVisualizer(db_name=args.db)
    
    if args.type == 'dashboard':
        visualizer.create_dashboard()
    elif args.type == 'protocol':
        visualizer.create_protocol_chart()
    elif args.type == 'timeline':
        visualizer.create_traffic_timeline()
    
    if args.export:
        visualizer.export_chart(args.export)


if __name__ == "__main__":
    main()
