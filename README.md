# 🛡️ Network Traffic Analyzer with Advanced Anomaly Detection

A comprehensive Python-based network traffic analysis tool that captures, analyzes, and visualizes network packets with built-in security anomaly detection. Think of it as a mini Wireshark with a security lens!

## ✨ Features

### Core Features
- ✅ **Live Packet Capture** - Real-time network packet sniffing using Scapy
- ✅ **Protocol Analysis** - Extract and analyze TCP, UDP, ICMP, ARP protocols
- ✅ **Real-time Statistics** - Protocol distribution, top IPs, port analysis
- ✅ **Database Logging** - SQLite database for forensic packet storage
- ✅ **Anomaly Detection** - Multiple security threat detection algorithms

### Advanced Security Features
- 🚨 **Flooding Attack Detection** - Detects DDoS/flooding patterns from single IPs
- 🔍 **Port Scanning Detection** - Identifies potential port scanning attempts
- ⚠️ **ICMP Flood Detection** - Monitors suspicious ICMP traffic patterns
- 📊 **Real-time Alerts** - Console alerts with severity levels
- 🔒 **Forensic Logging** - All suspicious activities logged to database

### Professional Features
- 📈 **Data Visualization** - Interactive matplotlib dashboards
- 💾 **Data Export** - CSV and JSON export capabilities
- 📋 **Comprehensive Reports** - Detailed statistics and summaries
- 🎯 **Modular Architecture** - Clean, maintainable code structure
- 📝 **Command-line Interface** - Flexible CLI with multiple options

## 🚀 Quick Start

### Installation

1. **Clone or download this repository**

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

**Note:** On Linux, you may need to install additional dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libpcap-dev

# For Windows, Scapy should work out of the box
```

### Basic Usage

**Start capturing packets (default interface, infinite capture):**
```bash
python network_analyzer.py
```

**Capture with specific options:**
```bash
# Capture 100 packets
python network_analyzer.py -c 100

# Capture for 60 seconds
python network_analyzer.py -t 60

# Specify network interface
python network_analyzer.py -i eth0

# Custom alert threshold (default: 50 packets/10 seconds)
python network_analyzer.py --threshold 30 --window 5
```

**Export captured data:**
```bash
# Export to CSV
python network_analyzer.py --export-csv

# Export alerts to JSON
python network_analyzer.py --export-alerts

# Both exports
python network_analyzer.py --export-csv --export-alerts
```

### Visualization

**View comprehensive dashboard:**
```bash
python visualizer.py --type dashboard
```

**View protocol distribution:**
```bash
python visualizer.py --type protocol
```

**View traffic timeline:**
```bash
python visualizer.py --type timeline
```

**Export chart:**
```bash
python visualizer.py --type dashboard --export chart.png
```

## 📖 Detailed Usage

### Command-Line Arguments

#### Network Analyzer (`network_analyzer.py`)

| Argument | Description | Default |
|----------|-------------|---------|
| `-i, --interface` | Network interface to capture on | Auto-detect |
| `-c, --count` | Number of packets to capture (0 = infinite) | 0 |
| `-t, --timeout` | Capture timeout in seconds | None |
| `--threshold` | Alert threshold for flooding detection | 50 |
| `--window` | Time window in seconds for anomaly detection | 10 |
| `--export-csv` | Export captured data to CSV | False |
| `--export-alerts` | Export alerts to JSON | False |

#### Visualizer (`visualizer.py`)

| Argument | Description | Default |
|----------|-------------|---------|
| `--db` | Database file to visualize | network_traffic.db |
| `--type` | Type of visualization (dashboard/protocol/timeline) | dashboard |
| `--export` | Export chart to file | None |

## 🔍 Anomaly Detection

The analyzer detects several types of network anomalies:

### 1. Flooding Attack Detection
- Monitors packet rate from each source IP
- Alerts when threshold exceeded (default: 50 packets in 10 seconds)
- Severity: **HIGH**

### 2. Port Scanning Detection
- Tracks unique destination ports accessed by each IP
- Alerts when 10+ unique ports accessed from same IP
- Severity: **MEDIUM**

### 3. ICMP Flood Detection
- Monitors ICMP packet frequency
- Alerts on high ICMP traffic patterns
- Severity: **MEDIUM**

## 📊 Database Schema

### Packets Table
Stores all captured packet information:
- `id` - Primary key
- `timestamp` - Packet capture time
- `source_ip` - Source IP address
- `dest_ip` - Destination IP address
- `protocol` - Protocol type (TCP/UDP/ICMP/ARP)
- `src_port` - Source port
- `dest_port` - Destination port
- `packet_size` - Packet size in bytes
- `flags` - Protocol-specific flags
- `is_suspicious` - Boolean flag for suspicious packets
- `alert_reason` - Reason for marking as suspicious

### Alerts Table
Stores security alerts:
- `id` - Primary key
- `timestamp` - Alert time
- `alert_type` - Type of alert (FLOODING_ATTACK/PORT_SCAN/ICMP_FLOOD)
- `source_ip` - Source IP that triggered alert
- `description` - Detailed alert description
- `severity` - Alert severity (HIGH/MEDIUM/LOW)

## 🎯 Project Structure

```
.
├── network_analyzer.py    # Main analyzer script
├── visualizer.py          # Visualization dashboard
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── network_traffic.db    # SQLite database (created on first run)
```

## 💡 Use Cases

1. **Network Monitoring** - Monitor network traffic in real-time
2. **Security Analysis** - Detect potential attacks and anomalies
3. **Forensic Investigation** - Log and analyze network events
4. **Educational Purpose** - Learn about network protocols and security
5. **Lab Projects** - Perfect for Computer Networks lab assignments

## 🔧 Advanced Customization

### Modify Alert Thresholds
Edit the `NetworkAnalyzer` initialization:
```python
analyzer = NetworkAnalyzer(
    alert_threshold=30,  # Lower threshold = more sensitive
    time_window=5        # Shorter window = faster detection
)
```

### Add Custom Anomaly Detection
Extend the `detect_anomalies()` method in `NetworkAnalyzer` class to add your own detection logic.

### Customize Visualization
Modify `visualizer.py` to add new chart types or customize existing ones.

## ⚠️ Important Notes

1. **Administrator/Root Access Required**: Packet capture requires elevated privileges
   - Linux/Mac: Run with `sudo`
   - Windows: Run as Administrator

2. **Network Interface Selection**: 
   - Use `ifconfig` (Linux/Mac) or `ipconfig` (Windows) to list interfaces
   - Common interfaces: `eth0`, `wlan0`, `en0`, etc.

3. **Performance**: 
   - Large packet volumes may impact performance
   - Consider using packet count/timeout limits for testing

4. **Legal Considerations**: 
   - Only capture traffic on networks you own or have permission to monitor
   - Respect privacy and legal regulations

## 🎓 Viva/Interview Points

### Technical Concepts to Explain:
1. **Packet Capture**: How Scapy captures packets at the network layer
2. **Protocol Analysis**: TCP/UDP/ICMP header parsing
3. **Anomaly Detection**: Statistical analysis and pattern recognition
4. **Database Design**: Normalized schema for forensic logging
5. **Real-time Processing**: Threading for concurrent capture and display

### Security Concepts:
1. **DDoS Detection**: Rate limiting and threshold-based detection
2. **Port Scanning**: Behavioral analysis of network reconnaissance
3. **Traffic Analysis**: Protocol distribution and pattern analysis
4. **Forensic Logging**: Evidence preservation and audit trails

## 📈 Resume-Worthy Features

This project demonstrates:
- ✅ Network programming and packet analysis
- ✅ Security threat detection algorithms
- ✅ Database design and SQL operations
- ✅ Data visualization and analytics
- ✅ Real-time system design
- ✅ Python programming best practices
- ✅ Command-line interface development
- ✅ Forensic analysis capabilities

## 🤝 Contributing

Feel free to extend this project with:
- Machine learning-based anomaly detection
- Web-based dashboard (Flask/Dash)
- More protocol support (IPv6, etc.)
- Performance optimizations
- Additional visualization types

## 📝 License

This project is for educational purposes. Use responsibly and ethically.

## 🐛 Troubleshooting

**Issue: "Permission denied" or "No such device"**
- Solution: Run with sudo/Administrator privileges

**Issue: "No packets captured"**
- Solution: Check network interface name, ensure network activity

**Issue: "ModuleNotFoundError: scapy"**
- Solution: Install dependencies: `pip install -r requirements.txt`

**Issue: Database locked errors**
- Solution: Ensure only one instance is accessing the database at a time

---
