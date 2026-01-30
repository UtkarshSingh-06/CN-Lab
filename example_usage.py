"""
Example usage script demonstrating various features of the Network Analyzer
This file shows how to use the analyzer programmatically
"""

from network_analyzer import NetworkAnalyzer
import time

def example_basic_capture():
    """Example: Basic packet capture"""
    print("Example 1: Basic Packet Capture")
    print("-" * 50)
    
    analyzer = NetworkAnalyzer(
        db_name="example_traffic.db",
        alert_threshold=30,
        time_window=5
    )
    
    # Capture 50 packets
    analyzer.start_capture(count=50)
    
    print("\n✓ Basic capture completed!")


def example_custom_thresholds():
    """Example: Custom anomaly detection thresholds"""
    print("\nExample 2: Custom Detection Thresholds")
    print("-" * 50)
    
    # More sensitive detection
    analyzer = NetworkAnalyzer(
        alert_threshold=20,  # Lower threshold = more alerts
        time_window=5        # 5 second window
    )
    
    print("Starting capture with sensitive thresholds...")
    print("Press Ctrl+C after a few seconds to stop")
    
    try:
        analyzer.start_capture(timeout=30)
    except KeyboardInterrupt:
        pass
    
    print("\n✓ Custom threshold capture completed!")


def example_data_export():
    """Example: Capture and export data"""
    print("\nExample 3: Data Export")
    print("-" * 50)
    
    analyzer = NetworkAnalyzer(db_name="export_example.db")
    
    print("Capturing packets for export...")
    print("Press Ctrl+C after capturing some packets")
    
    try:
        analyzer.start_capture(timeout=20)
    except KeyboardInterrupt:
        pass
    
    # Export data
    analyzer.export_to_csv("exported_packets.csv")
    analyzer.export_alerts_to_json("exported_alerts.json")
    
    print("\n✓ Data exported successfully!")


def example_statistics_analysis():
    """Example: Analyze captured statistics"""
    print("\nExample 4: Statistics Analysis")
    print("-" * 50)
    
    analyzer = NetworkAnalyzer()
    
    # Capture some packets
    print("Capturing 100 packets for analysis...")
    analyzer.start_capture(count=100)
    
    # Display statistics
    print("\n" + "="*50)
    print("CAPTURED STATISTICS")
    print("="*50)
    print(f"Total Packets: {analyzer.packet_count}")
    print(f"Total Bytes: {analyzer.total_bytes:,}")
    print(f"\nProtocol Distribution:")
    for protocol, count in analyzer.protocol_stats.items():
        print(f"  {protocol}: {count}")
    print(f"\nTop Source IPs:")
    for ip, count in sorted(analyzer.ip_stats.items(), 
                           key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip}: {count}")
    print("="*50)


if __name__ == "__main__":
    print("="*70)
    print("NETWORK ANALYZER - EXAMPLE USAGE")
    print("="*70)
    print("\nThis script demonstrates various usage patterns.")
    print("Note: You need administrator/root privileges to capture packets.")
    print("\nChoose an example to run:")
    print("1. Basic Capture (50 packets)")
    print("2. Custom Thresholds (30 seconds)")
    print("3. Data Export (20 seconds)")
    print("4. Statistics Analysis (100 packets)")
    print("\nOr run the examples individually by uncommenting them.")
    
    # Uncomment the example you want to run:
    # example_basic_capture()
    # example_custom_thresholds()
    # example_data_export()
    # example_statistics_analysis()
    
    print("\n" + "="*70)
    print("To run examples, uncomment them in the script!")
    print("="*70)
