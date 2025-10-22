# 🌐 Real-Time Network Packet Analyzer

A powerful CLI-based tool for real-time network packet capture, protocol analysis, and threat detection with comprehensive traffic monitoring capabilities. **Windows-only version**.

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20Only-lightgrey.svg)
![Security](https://img.shields.io/badge/Security-Network%20Analysis-green.svg)
![Real-Time](https://img.shields.io/badge/Monitoring-Real--Time-orange.svg)

## 🚀 Quick Start

```bash
# Windows - Run as Administrator
python pherion.py
```

## 📋 Prerequisites

- **Windows** 7/10/11
- Python 3.6+
- **Administrator privileges**
- Network interface access

## 🛠️ Installation

```bash
# Install dependencies automatically (run normally first)
python pherion.py

# Or manually install dependencies
pip install rich numpy scikit-learn scapy
```

## 🎯 Usage

```bash
# Analyze default interface (Run as Administrator)
python pherion.py

# Specific interface
python pherion.py --interface "Ethernet"

# Wireless monitoring
python pherion.py --interface "Wi-Fi"

# All available interfaces
python pherion.py --interface "any"
```

## ✨ Features

### 📊 Real-Time Dashboard
- Live traffic statistics and metrics
- Packets per second monitoring  
- Bandwidth utilization tracking
- Active connection counter
- Running time display

### 📡 Protocol Analysis
- **TCP**: Full flag analysis (SYN, ACK, FIN, RST), sequence/ack tracking, window size
- **UDP**: Length analysis, port monitoring
- **DNS**: Query/response monitoring with domain tracking
- **HTTP/HTTPS**: Request pattern detection on ports 80/443/8080
- **ICMP**: Type/code analysis
- **DHCP**: Client/server IP tracking, lease monitoring
- **ARP**: Request/reply analysis with MAC address tracking
- **IPv4/IPv6**: Dual stack support

### 🔍 Traffic Intelligence
- **Top Talkers**: Most active IP addresses with percentage breakdown
- **Service Port Mapping**: Automatic service identification (HTTP, SSH, DNS, etc.)
- **Protocol Distribution**: Real-time protocol usage statistics
- **Connection Duration**: Active connection timing
- **Conversation Analysis**: Source-destination pair tracking

### 🎨 Rich Visualization
- Real-time updating dashboard with 2 FPS refresh
- Color-coded protocol display
- Structured table layouts with borders
- Comprehensive final reports
- Windows-optimized interface

## 🏗️ Architecture

```
Windows Network Interface → Packet Capture → Protocol Analysis → Real-Time Display
           ↓                      ↓                 ↓                 ↓
      Raw Packets        EnhancedPacket       NetworkStatistics   Rich Dashboard
                          Capture Class          Class            with Live Updates
```

## 🔧 Technical Details

### Core Components
- **EnhancedPacketCapture**: Raw packet processing and protocol decoding using Scapy
- **NetworkStatistics**: Real-time metrics and traffic analysis with counters
- **RealTimeAnalyzer**: Visualization and dashboard management with Rich
- **NetworkPacket**: Structured packet representation with threat scoring

### Supported Protocols
- **Layer 2**: Ethernet
- **Layer 3**: IP, IPv6, ICMP, IGMP, OSPF
- **Layer 4**: TCP, UDP, SCTP  
- **Layer 7**: DNS, DHCP, ARP, HTTP/HTTPS (port-based)

### Dashboard Sections
1. **Traffic Statistics**: Volume, rates, connection counts, unique IPs
2. **Protocol Distribution**: Breakdown by protocol type with percentages
3. **Active Connections**: Real-time connection tracking with durations
4. **Top Talkers**: Most active IP addresses with packet counts
5. **Port Analysis**: Service identification and mapping for top ports
6. **Recent Activity**: Live packet stream with protocol-specific info

## 🛡️ Security Features

- **Windows Admin Privilege Verification**: Ensures proper permissions
- **Malformed Packet Handling**: Graceful error handling for corrupt packets
- **Connection State Tracking**: Active connection monitoring
- **Forensic Data Preservation**: Comprehensive final reporting
- **Queue-based Processing**: Non-blocking packet handling

## 📝 Example Output

```
📊 Traffic Statistics:
  Total Packets: 15,247
  Total Bytes: 45.2 MB  
  Packets/Sec: 128.5
  Active Connections: 23
  Unique IPs: 156
  Running Time: 142s

📡 Protocol Distribution:
  TCP: 8,452 (55.4%)
  UDP: 4,123 (27.0%)
  DNS: 1,845 (12.1%)
  HTTP: 827 (5.4%)

🔗 Active Connections:
  192.168.1.102 → 8.8.8.8 :53 UDP 45s
  192.168.1.104 → 151.101.1.609 :443 TCP 12s

🏆 Top Talkers:
  192.168.1.102: 4,128 packets (27.1%)
  8.8.8.8: 1,845 packets (12.1%) 
  192.168.1.1: 892 packets (5.8%)

🔌 Top Destination Ports:
  Port 53 (DNS): 1,845 packets
  Port 443 (HTTPS): 1,234 packets
  Port 80 (HTTP): 827 packets
```

## 🐛 Troubleshooting

### Common Issues

**Permission Denied Error:**
```bash
# Windows - Run Command Prompt as Administrator
# Right-click Command Prompt → "Run as administrator"
python pherion.py
```

**Scapy Installation Issues:**
```bash
# Try alternative installation methods
pip install --upgrade scapy
python -m pip install scapy --user

# If using Anaconda
conda install -c conda-forge scapy
```

**Interface Not Found:**
```bash
# Check available interfaces in Windows
# Control Panel → Network and Sharing Center → Change adapter settings
python pherion.py --interface "Ethernet"
python pherion.py --interface "Wi-Fi" 
python pherion.py --interface "Local Area Connection"
```

**Dependency Installation Failed:**
```bash
# Install individually
pip install rich
pip install numpy
pip install scikit-learn
pip install scapy
```
## 📄 License

This tool is for educational and legitimate network monitoring purposes only. Users are responsible for complying with local laws and regulations.

## ⚠️ Disclaimer

Use responsibly and only on networks you own or have explicit permission to monitor. The authors are not responsible for misuse. Always ensure proper authorization before monitoring any network traffic.

---

<div align="center">

**🚀 Ready to monitor your network? Run as Administrator and execute `python pherion.py` to begin!**

*For Windows systems only - Administrator privileges required*

</div>
