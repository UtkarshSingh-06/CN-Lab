# 🚀 Quick Start Guide

## Installation (One-Time Setup)

```bash
# Install Python dependencies
pip install -r requirements.txt
```

**On Linux/Mac, you may also need:**
```bash
sudo apt-get install python3-dev libpcap-dev  # Ubuntu/Debian
```

## Basic Commands

### 1. Start Capturing Packets
```bash
# Windows (Run PowerShell/CMD as Administrator)
python network_analyzer.py

# Linux/Mac (Run with sudo)
sudo python network_analyzer.py
```

### 2. Capture Limited Packets
```bash
# Capture 100 packets and stop
python network_analyzer.py -c 100

# Capture for 60 seconds
python network_analyzer.py -t 60
```

### 3. View Visualizations
```bash
# After capturing some packets, view dashboard
python visualizer.py --type dashboard

# View protocol distribution
python visualizer.py --type protocol
```

### 4. Export Data
```bash
# Export all captured packets to CSV
python network_analyzer.py --export-csv

# Export security alerts to JSON
python network_analyzer.py --export-alerts
```

## Common Use Cases

### For Lab/Demo
```bash
# Capture 50 packets, show stats, export data
python network_analyzer.py -c 50 --export-csv --export-alerts
python visualizer.py --type dashboard
```

### For Security Testing
```bash
# More sensitive detection (lower threshold)
python network_analyzer.py --threshold 20 --window 5
```

### For Analysis
```bash
# Capture for 2 minutes, then analyze
python network_analyzer.py -t 120
python visualizer.py --type dashboard --export analysis.png
```

## Troubleshooting

**"Permission denied" error:**
- Windows: Run as Administrator
- Linux/Mac: Use `sudo`

**"No packets captured":**
- Check if you're on the correct network interface
- Ensure there's network activity
- Try: `python network_analyzer.py -i <interface_name>`

**"Module not found":**
- Run: `pip install -r requirements.txt`

## Tips

1. **First Run**: Start with `-c 50` to test everything works
2. **Interface Selection**: Use `ipconfig` (Windows) or `ifconfig` (Linux/Mac) to find interface names
3. **Database**: All data is stored in `network_traffic.db` - you can query it with any SQLite tool
4. **Alerts**: Watch the console for real-time security alerts

## Example Workflow

```bash
# Step 1: Capture packets
sudo python network_analyzer.py -c 200

# Step 2: View dashboard
python visualizer.py --type dashboard

# Step 3: Export for report
python network_analyzer.py --export-csv --export-alerts
```

That's it! You're ready to analyze network traffic! 🎉
