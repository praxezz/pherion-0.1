# 🌐 Real-Time Network Packet Analyzer

A powerful CLI-based tool for real-time network packet capture, protocol analysis, and threat detection with comprehensive traffic monitoring capabilities.

![Network Analyzer](https://img.shields.io/badge/Python-3.6+-blue.svg)
![Security](https://img.shields.io/badge/Security-Network%20Analysis-green.svg)
![Real-Time](https://img.shields.io/badge/Monitoring-Real--Time-orange.svg)

## 🚀 Quick Start

```bash
# Clone and run (Linux/macOS)
sudo python pherion 0.1.py

# Windows (Run as Administrator)
python pherion 0.1.py
```

## 📋 Prerequisites

- Python 3.6+
- Administrator/root privileges
- Network interface access

## 🛠️ Installation

```bash
# Install dependencies automatically
pip install rich numpy scikit-learn scapy

# Or run the script - it auto-installs dependencies
sudo python pherion 0.1.py --interface eth0
```

## 🎯 Usage

```bash
# Analyze default interface
sudo python npherion 0.1.py

# Specific interface
sudo python pherion 0.1.py --interface eth0

# Wireless monitoring
sudo python pherion 0.1.py --interface wlan0

# All interfaces
sudo python pherion 0.1.py --interface any
```

## ✨ Features

### 📊 Real-Time Dashboard
- Live traffic statistics and metrics
- Packets per second monitoring
- Bandwidth utilization tracking
- Active connection counter

### 📡 Protocol Analysis
- **TCP/UDP**: Flag analysis, sequence tracking
- **DNS**: Query/response monitoring
- **HTTP/HTTPS**: Request pattern detection
- **ICMP**: Type/code analysis
- **DHCP/ARP**: Network discovery tracking
- **IPv4/IPv6**: Dual stack support

### 🔍 Traffic Intelligence
- Top talkers identification
- Service port mapping
- Protocol distribution
- Connection duration tracking
- Conversation analysis

### 🎨 Rich Visualization
- Real-time updating dashboard
- Color-coded protocol display
- Interactive progress tracking
- Comprehensive final reports

## 🏗️ Architecture

```
Network Interface → Packet Capture → Protocol Analysis → Real-Time Display
       ↓                  ↓                 ↓                 ↓
   Raw Packets    EnhancedPacket   NetworkStatistics   Rich Dashboard
                   Capture Class      Class            with Live Updates
```

## 🔧 Technical Details

### Core Components
- **EnhancedPacketCapture**: Raw packet processing and protocol decoding
- **NetworkStatistics**: Real-time metrics and traffic analysis
- **RealTimeAnalyzer**: Visualization and dashboard management
- **NetworkPacket**: Structured packet representation

### Supported Protocols
- Ethernet, IP, IPv6
- TCP, UDP, ICMP
- DNS, DHCP, ARP
- HTTP, HTTPS (port-based detection)
- Custom protocol extensibility

## 📊 Output Sections

1. **Traffic Statistics**: Volume, rates, connection counts
2. **Protocol Distribution**: Breakdown by protocol type
3. **Active Connections**: Real-time connection tracking
4. **Top Talkers**: Most active IP addresses
5. **Port Analysis**: Service identification and mapping
6. **Recent Activity**: Live packet stream with alerts

## 🛡️ Security Features

- Administrator privilege verification
- Malformed packet handling
- Connection state tracking
- Anomaly detection ready
- Forensic data preservation

## 📝 Example Output

```
📊 Traffic Statistics:
  Total Packets: 15,247
  Total Bytes: 45.2 MB
  Packets/Sec: 128.5
  Active Connections: 23

📡 Protocol Distribution:
  TCP: 8,452 (55.4%)
  UDP: 4,123 (27.0%)
  DNS: 1,845 (12.1%)
  HTTP: 827 (5.4%)

🏆 Top Talkers:
  1. 192.168.1.000: 4,128 packets
  2. 8.8.8.8: 1,845 packets
  3. 192.168.0.0: 892 packets
```

## 🐛 Troubleshooting

### Common Issues

**Permission Denied:**
```bash
# Linux/macOS
sudo python pherion 0.1.py

# Windows - Run as Administrator
```

**Scapy Installation Issues:**
```bash
pip install --upgrade scapy
# or
python -m pip install scapy
```

**Interface Not Found:**
```bash
# List available interfaces
scapy.ifaces
# Use correct interface name
python pherion 0.1.py --interface "Ethernet 2"
```

## 🔮 Future Enhancements

- [ ] Threat intelligence integration
- [ ] Machine learning anomaly detection
- [ ] Packet capture to PCAP files
- [ ] Custom filter expressions
- [ ] Historical data analysis
- [ ] Web-based dashboard
- [ ] Alert system with notifications

## 📄 License

This tool is for educational and legitimate network monitoring purposes only. Users are responsible for complying with local laws and regulations.

## ⚠️ Disclaimer

Use responsibly and only on networks you own or have explicit permission to monitor. The authors are not responsible for misuse.

---

<div align="center">

**🚀 Ready to monitor your network? Run `sudo python pherion 0.1.py` to begin!**

</div>
