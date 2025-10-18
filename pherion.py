#!/usr/bin/env python3
"""
Real-Time Network Packet Analyzer with Threat Detection
A CLI-based tool for real packet capture, protocol analysis, and threat detection
"""

import time
import random
import threading
import queue
import json
import sqlite3
import pickle
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
import subprocess
import sys
import os
import argparse
import ipaddress
import platform

# Install dependencies if needed
def install_dependencies():
    required = {
        'rich': 'rich',
        'numpy': 'numpy',
        'sklearn': 'scikit-learn',
        'scapy': 'scapy'
    }
    
    missing = []
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Installing required packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "-q"])

install_dependencies()

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree
from rich import box
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Scapy imports
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DHCP, Raw, Ether
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNSQR, DNSRR
    from scapy.layers.dhcp import BOOTP, DHCPOptions
    SCAPY_AVAILABLE = True
except (ImportError, OSError):
    SCAPY_AVAILABLE = False

console = Console()

class NetworkPacket:
    """Enhanced network packet representation"""
    
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, payload_size, flags=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.payload_size = payload_size
        self.timestamp = time.time()
        self.flags = flags or []
        self.additional_info = {}
        self.threat_score = 0
        self.threat_type = None

class NetworkStatistics:
    """Real-time network statistics and activity tracking"""
    
    def __init__(self):
        self.reset_stats()
        
    def reset_stats(self):
        """Reset all statistics"""
        self.start_time = time.time()
        
        # Protocol counters
        self.protocols = Counter()
        self.ports = Counter()
        self.ip_addresses = Counter()
        self.conversations = Counter()  # src_ip:dst_ip pairs
        
        # Traffic analysis
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_sizes = []
        
        # Time-based tracking
        self.packets_per_second = deque(maxlen=60)
        self.current_second_count = 0
        self.last_second_check = time.time()
        
        # Top talkers
        self.top_talkers = Counter()
        self.top_ports = Counter()
        self.top_protocols = Counter()
        
        # Active connections
        self.active_connections = set()  # (src_ip, dst_ip, src_port, dst_port, protocol)
        self.connection_start_times = {}
        
    def update_stats(self, packet):
        """Update statistics with new packet"""
        self.total_packets += 1
        self.total_bytes += packet.payload_size
        self.packet_sizes.append(packet.payload_size)
        
        # Protocol statistics
        self.protocols[packet.protocol] += 1
        self.top_protocols[packet.protocol] += 1
        
        # Port statistics
        if packet.dst_port > 0:
            self.ports[packet.dst_port] += 1
            self.top_ports[packet.dst_port] += 1
        
        # IP statistics
        self.ip_addresses[packet.src_ip] += 1
        self.ip_addresses[packet.dst_ip] += 1
        self.top_talkers[packet.src_ip] += 1
        
        # Conversation tracking
        conversation = f"{packet.src_ip} → {packet.dst_ip}"
        self.conversations[conversation] += 1
        
        # Connection tracking
        conn_key = (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        if conn_key not in self.connection_start_times:
            self.connection_start_times[conn_key] = packet.timestamp
        self.active_connections.add(conn_key)
        
        # Packets per second calculation
        current_time = time.time()
        if current_time - self.last_second_check >= 1.0:
            self.packets_per_second.append(self.current_second_count)
            self.current_second_count = 0
            self.last_second_check = current_time
        else:
            self.current_second_count += 1
            
        # Clean old connections (older than 5 minutes)
        current_time = time.time()
        self.active_connections = {
            conn for conn in self.active_connections 
            if current_time - self.connection_start_times.get(conn, current_time) < 300
        }
    
    def get_packets_per_second(self):
        """Get current packets per second"""
        if self.packets_per_second:
            return sum(self.packets_per_second) / len(self.packets_per_second)
        return self.current_second_count
    
    def get_top_talkers(self, n=10):
        """Get top n talking IP addresses"""
        return self.top_talkers.most_common(n)
    
    def get_top_ports(self, n=10):
        """Get top n destination ports"""
        return self.top_ports.most_common(n)
    
    def get_top_protocols(self, n=5):
        """Get top n protocols"""
        return self.top_protocols.most_common(n)
    
    def get_connection_duration(self, connection):
        """Get duration of a connection"""
        start_time = self.connection_start_times.get(connection)
        if start_time:
            return time.time() - start_time
        return 0

class EnhancedPacketCapture:
    """Enhanced real packet capture with detailed protocol analysis"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_queue = queue.Queue(maxsize=2000)
        self.running = False
        self.statistics = NetworkStatistics()
        
    def packet_callback(self, pkt):
        """Enhanced packet callback with detailed protocol analysis"""
        try:
            packet_info = self._analyze_packet(pkt)
            if packet_info and not self.packet_queue.full():
                self.packet_queue.put(packet_info)
                self.statistics.update_stats(packet_info)
        except Exception as e:
            pass  # Silently handle malformed packets
    
    def _analyze_packet(self, pkt):
        """Deep packet analysis with protocol detection"""
        if not pkt:
            return None
            
        # Check for Ethernet and IP layers
        has_ether = Ether in pkt
        has_ip = IP in pkt
        has_ipv6 = IPv6 in pkt
        
        if not (has_ether and (has_ip or has_ipv6)):
            return None
        
        # Basic packet information
        src_ip = pkt[IP].src if has_ip else (pkt[IPv6].src if has_ipv6 else "Unknown")
        dst_ip = pkt[IP].dst if has_ip else (pkt[IPv6].dst if has_ipv6 else "Unknown")
        
        if src_ip == "Unknown" or dst_ip == "Unknown":
            return None
            
        protocol = "IPv6" if has_ipv6 else "IP"
        payload_size = len(pkt)
        
        # Initialize ports and flags
        src_port = 0
        dst_port = 0
        flags = []
        protocol_name = "Unknown"
        additional_info = {}
        
        # Layer 3 protocol analysis
        if has_ip:
            ip_layer = pkt[IP]
            protocol_num = ip_layer.proto
            
            # Protocol mapping
            protocol_map = {
                1: "ICMP", 6: "TCP", 17: "UDP", 
                2: "IGMP", 89: "OSPF", 132: "SCTP"
            }
            protocol_name = protocol_map.get(protocol_num, f"IP-{protocol_num}")
            
        # Transport layer analysis
        if TCP in pkt:
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            protocol_name = "TCP"
            
            # TCP flags analysis
            tcp_flags = []
            if hasattr(tcp, 'flags'):
                if tcp.flags & 0x01: tcp_flags.append("FIN")
                if tcp.flags & 0x02: tcp_flags.append("SYN")
                if tcp.flags & 0x04: tcp_flags.append("RST")
                if tcp.flags & 0x08: tcp_flags.append("PSH")
                if tcp.flags & 0x10: tcp_flags.append("ACK")
                if tcp.flags & 0x20: tcp_flags.append("URG")
                if tcp.flags & 0x40: tcp_flags.append("ECE")
                if tcp.flags & 0x80: tcp_flags.append("CWR")
            flags = tcp_flags
            
            # TCP-specific analysis
            additional_info['window_size'] = getattr(tcp, 'window', 0)
            additional_info['seq_num'] = getattr(tcp, 'seq', 0)
            additional_info['ack_num'] = getattr(tcp, 'ack', 0)
            
        elif UDP in pkt:
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            protocol_name = "UDP"
            additional_info['length'] = getattr(udp, 'len', 0)
            
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            protocol_name = "ICMP"
            additional_info['type'] = getattr(icmp, 'type', 0)
            additional_info['code'] = getattr(icmp, 'code', 0)
            
        # Application layer protocol detection
        if DNS in pkt:
            protocol_name = "DNS"
            dns = pkt[DNS]
            if hasattr(dns, 'qr') and dns.qr == 0:  # Query
                if hasattr(dns, 'qd') and dns.qd:
                    qname = getattr(dns.qd, 'qname', b'')
                    if qname:
                        try:
                            additional_info['dns_query'] = qname.decode('utf-8', errors='ignore')
                        except:
                            additional_info['dns_query'] = str(qname)
            else:  # Response
                if hasattr(dns, 'an') and dns.an:
                    rdata = getattr(dns.an, 'rdata', '')
                    additional_info['dns_answer'] = str(rdata)
                    
        elif DHCP in pkt or (UDP in pkt and (pkt[UDP].sport == 67 or pkt[UDP].dport == 67)):
            protocol_name = "DHCP"
            if BOOTP in pkt:
                bootp = pkt[BOOTP]
                additional_info['client_ip'] = getattr(bootp, 'ciaddr', '0.0.0.0')
                additional_info['your_ip'] = getattr(bootp, 'yiaddr', '0.0.0.0')
                additional_info['server_ip'] = getattr(bootp, 'siaddr', '0.0.0.0')
                
        elif ARP in pkt:
            arp = pkt[ARP]
            protocol_name = "ARP"
            operation = "Request" if getattr(arp, 'op', 0) == 1 else "Reply"
            additional_info['operation'] = operation
            additional_info['sender_mac'] = getattr(arp, 'hwsrc', '')
            additional_info['target_mac'] = getattr(arp, 'hwdst', '')
            
        # HTTP detection (common ports)
        if TCP in pkt and (dst_port in [80, 443, 8080] or src_port in [80, 443, 8080]):
            if dst_port in [80, 8080]:
                protocol_name = "HTTP"
            elif dst_port == 443:
                protocol_name = "HTTPS"
                
            # Basic HTTP analysis
            if Raw in pkt:
                try:
                    payload = pkt[Raw].load
                    if isinstance(payload, bytes):
                        payload = payload.decode('utf-8', errors='ignore')
                    if 'HTTP' in payload or 'GET' in payload or 'POST' in payload:
                        lines = payload.split('\r\n')
                        if lines:
                            additional_info['http_method'] = lines[0][:50]  # Limit length
                except:
                    pass
        
        # Create enhanced packet object
        packet = NetworkPacket(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_name,
            payload_size=payload_size,
            flags=flags
        )
        
        # Add additional information
        packet.additional_info = additional_info
        packet.timestamp = time.time()
        
        return packet
    
    def start_capture(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            console.print("[red]Error: Scapy not available for packet capture[/red]")
            return
            
        self.running = True
        console.print(f"[green]Starting packet capture on interface: {self.interface or 'default'}[/green]")
        
        def capture():
            try:
                sniff(
                    prn=self.packet_callback, 
                    store=False, 
                    iface=self.interface,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                console.print(f"[red]Capture Error: {e}[/red]")
                self.running = False
        
        capture_thread = threading.Thread(target=capture, daemon=True)
        capture_thread.start()
    
    def get_packet(self):
        """Get captured packet"""
        try:
            return self.packet_queue.get(timeout=0.1)
        except queue.Empty:
            return None
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False

class RealTimeAnalyzer:
    """Real-time network analysis and visualization"""
    
    def __init__(self, packet_capture):
        self.packet_capture = packet_capture
        self.running = False
        
    def generate_detailed_dashboard(self):
        """Generate comprehensive real-time dashboard"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", size=20),
            Layout(name="footer", size=4)
        )
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="center"),
            Layout(name="right")
        )
        
        layout["left"].split_column(
            Layout(name="traffic_stats"),
            Layout(name="protocols")
        )
        
        layout["center"].split_column(
            Layout(name="connections"),
            Layout(name="top_talkers")
        )
        
        layout["right"].split_column(
            Layout(name="ports"),
            Layout(name="alerts")
        )
        
        # Header
        layout["header"].update(
            Panel(
                "[bold cyan]🌐 REAL-TIME NETWORK PACKET ANALYZER - LIVE TRAFFIC MONITOR[/bold cyan]",
                style="bold white on blue"
            )
        )
        
        # Traffic Statistics
        stats = self.packet_capture.statistics
        stats_table = Table(title="📊 Traffic Statistics", box=box.ROUNDED)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="green", justify="right")
        
        stats_table.add_row("Total Packets", f"{stats.total_packets:,}")
        stats_table.add_row("Total Bytes", f"{stats.total_bytes:,}")
        stats_table.add_row("Packets/Sec", f"{stats.get_packets_per_second():.1f}")
        stats_table.add_row("Active Connections", f"{len(stats.active_connections)}")
        stats_table.add_row("Unique IPs", f"{len(stats.ip_addresses)}")
        stats_table.add_row("Running Time", f"{time.time() - stats.start_time:.0f}s")
        
        layout["traffic_stats"].update(Panel(stats_table))
        
        # Protocol Distribution
        proto_table = Table(title="📡 Protocol Distribution", box=box.SIMPLE)
        proto_table.add_column("Protocol", style="yellow")
        proto_table.add_column("Count", style="green", justify="right")
        proto_table.add_column("%", justify="right")
        
        total = max(stats.total_packets, 1)
        for proto, count in stats.get_top_protocols(8):
            percentage = (count / total) * 100
            proto_table.add_row(proto, f"{count:,}", f"{percentage:.1f}%")
        
        layout["protocols"].update(Panel(proto_table))
        
        # Active Connections
        conn_table = Table(title="🔗 Active Connections", box=box.SIMPLE)
        conn_table.add_column("Source", style="cyan", width=15)
        conn_table.add_column("→", width=3)
        conn_table.add_column("Destination", style="magenta", width=15)
        conn_table.add_column("Port", justify="right")
        conn_table.add_column("Proto", width=6)
        conn_table.add_column("Duration", justify="right")
        
        # Show recent connections (last 10)
        recent_connections = list(stats.active_connections)[-10:]
        for conn in recent_connections:
            src_ip, dst_ip, src_port, dst_port, proto = conn
            duration = stats.get_connection_duration(conn)
            
            # Shorten IPs for display
            src_display = src_ip[:15] + "..." if len(src_ip) > 15 else src_ip
            dst_display = dst_ip[:15] + "..." if len(dst_ip) > 15 else dst_ip
            
            conn_table.add_row(
                src_display, "→", dst_display,
                str(dst_port), proto, f"{duration:.0f}s"
            )
        
        layout["connections"].update(Panel(conn_table))
        
        # Top Talkers
        talker_table = Table(title="🏆 Top Talkers", box=box.SIMPLE)
        talker_table.add_column("IP Address", style="cyan")
        talker_table.add_column("Packets", style="green", justify="right")
        talker_table.add_column("%", justify="right")
        
        for ip, count in stats.get_top_talkers(8):
            percentage = (count / total) * 100
            talker_table.add_row(ip, f"{count:,}", f"{percentage:.1f}%")
        
        layout["top_talkers"].update(Panel(talker_table))
        
        # Top Ports
        port_table = Table(title="🔌 Top Destination Ports", box=box.SIMPLE)
        port_table.add_column("Port", style="yellow", justify="right")
        port_table.add_column("Service", style="cyan")
        port_table.add_column("Count", style="green", justify="right")
        
        common_ports = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS",
            25: "SMTP", 110: "POP3", 143: "IMAP", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5900: "VNC", 21: "FTP",
            23: "Telnet", 69: "TFTP", 161: "SNMP", 389: "LDAP"
        }
        
        for port, count in stats.get_top_ports(8):
            service = common_ports.get(port, "Unknown")
            port_table.add_row(str(port), service, f"{count:,}")
        
        layout["ports"].update(Panel(port_table))
        
        # Recent Activity Alerts
        alert_table = Table(title="🚨 Recent Activity", box=box.SIMPLE)
        alert_table.add_column("Time", style="yellow", width=8)
        alert_table.add_column("Source", style="cyan", width=15)
        alert_table.add_column("Protocol", width=8)
        alert_table.add_column("Info", style="white")
        
        # Get recent packets for activity display
        recent_packets = []
        # Create a temporary queue to process packets without blocking
        temp_queue = queue.Queue()
        while not self.packet_capture.packet_queue.empty():
            try:
                packet = self.packet_capture.packet_queue.get_nowait()
                temp_queue.put(packet)
                recent_packets.append(packet)
            except queue.Empty:
                break
        
        # Put packets back in the original queue
        while not temp_queue.empty():
            try:
                self.packet_capture.packet_queue.put(temp_queue.get_nowait())
            except queue.Empty:
                break
        
        for packet in recent_packets[-5:]:
            timestamp = datetime.fromtimestamp(packet.timestamp).strftime('%H:%M:%S')
            src_display = packet.src_ip[:12] + "..." if len(packet.src_ip) > 12 else packet.src_ip
            
            # Create info string
            info_parts = []
            if packet.dst_port > 0:
                info_parts.append(f"Port {packet.dst_port}")
            if packet.flags:
                info_parts.append(f"Flags: {','.join(packet.flags)}")
            if packet.additional_info.get('dns_query'):
                info_parts.append(f"DNS: {packet.additional_info['dns_query'][:20]}")
            if packet.additional_info.get('http_method'):
                info_parts.append(f"HTTP: {packet.additional_info['http_method'][:15]}")
                
            info = " | ".join(info_parts) if info_parts else f"{packet.payload_size} bytes"
            
            alert_table.add_row(
                timestamp,
                src_display,
                packet.protocol,
                info
            )
        
        layout["alerts"].update(Panel(alert_table))
        
        # Footer
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        layout["footer"].update(
            Panel(
                f"🕒 {current_time} | "
                f"📡 Interface: {self.packet_capture.interface or 'default'} | "
                f"⚡ Live Analysis Active | "
                f"Press [bold red]Ctrl+C[/bold red] to stop",
                style="white on dark_blue"
            )
        )
        
        return layout
    
    def run_analysis(self):
        """Start real-time analysis"""
        self.running = True
        
        console.print("\n[bold green]Starting Real-Time Network Analysis...[/bold green]")
        console.print("[yellow]Capturing and analyzing live network traffic...[/yellow]\n")
        
        try:
            with Live(self.generate_detailed_dashboard(), refresh_per_second=2, console=console) as live:
                while self.running:
                    live.update(self.generate_detailed_dashboard())
                    time.sleep(0.5)
        except KeyboardInterrupt:
            self.running = False
            self.packet_capture.stop_capture()
            console.print("\n[yellow]Stopping network analysis...[/yellow]")
            
            # Print final statistics
            self._print_final_report()
    
    def _print_final_report(self):
        """Print comprehensive final report"""
        stats = self.packet_capture.statistics
        console.print("\n[bold cyan]════════════════════ FINAL ANALYSIS REPORT ════════════════════[/bold cyan]")
        
        # Summary
        console.print("\n[bold]📈 Summary:[/bold]")
        console.print(f"  Total Packets Analyzed: {stats.total_packets:,}")
        console.print(f"  Total Data: {stats.total_bytes:,} bytes")
        console.print(f"  Average PPS: {stats.get_packets_per_second():.1f}")
        console.print(f"  Unique IP Addresses: {len(stats.ip_addresses)}")
        console.print(f"  Analysis Duration: {time.time() - stats.start_time:.1f} seconds")
        
        # Protocol Breakdown
        console.print("\n[bold]📡 Protocol Breakdown:[/bold]")
        for proto, count in stats.get_top_protocols():
            percentage = (count / max(stats.total_packets, 1)) * 100
            console.print(f"  {proto}: {count:,} packets ({percentage:.1f}%)")
        
        # Top Talkers
        console.print("\n[bold]🏆 Top 10 Talkers:[/bold]")
        for i, (ip, count) in enumerate(stats.get_top_talkers(10), 1):
            console.print(f"  {i:2d}. {ip}: {count:,} packets")
        
        # Top Ports
        console.print("\n[bold]🔌 Top 10 Destination Ports:[/bold]")
        common_ports = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS", 25: "SMTP"}
        for i, (port, count) in enumerate(stats.get_top_ports(10), 1):
            service = common_ports.get(port, "Unknown")
            console.print(f"  {i:2d}. Port {port} ({service}): {count:,} packets")
        
        console.print("\n[green]Analysis complete. Data captured for forensic review.[/green]")

def check_admin_privileges():
    """Check if the script has administrator privileges"""
    try:
        # For Windows
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        # For Unix/Linux
        else:
            return os.geteuid() == 0
    except:
        return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Real-Time Network Packet Analyzer with Live Traffic Monitoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze on default interface
  python network_analyzer.py
  
  # Analyze on specific interface
  python network_analyzer.py --interface eth0
  
  # Analyze on wireless interface
  python network_analyzer.py --interface wlan0
  
  # Monitor with high detail
  python network_analyzer.py --interface any

Note: On Windows, run as Administrator. On Linux/macOS, use sudo.
        """
    )
    
    parser.add_argument('--interface', type=str, default=None,
                       help='Network interface to capture from (e.g., eth0, wlan0, any)')
    
    args = parser.parse_args()
    
    # Check for admin privileges for packet capture
    if not check_admin_privileges():
        console.print("[red]Error: Administrator privileges required for packet capture[/red]")
        if platform.system() == "Windows":
            console.print("[yellow]Run as Administrator[/yellow]")
        else:
            console.print("[yellow]Run with: sudo python network_analyzer.py[/yellow]")
        sys.exit(1)
    
    if not SCAPY_AVAILABLE:
        console.print("[red]Error: Scapy is required but not available[/red]")
        console.print("[yellow]Try installing with: pip install scapy[/yellow]")
        sys.exit(1)
    
    # Welcome banner
    console.print("""
[bold cyan]╔════════════════════════════════════════════════════════════════╗
          
     ██████╗ ██╗  ██╗███████╗██████╗ ██╗ ██████╗ ███╗   ██╗    
     ██╔══██╗██║  ██║██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║    
     ██████╔╝███████║█████╗  ██████╔╝██║██║   ██║██╔██╗ ██║    
     ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║██║   ██║██║╚██╗██║    
     ██║     ██║  ██║███████╗██║  ██║██║╚██████╔╝██║ ╚████║    
     ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝    
                                                          
╚════════════════════════════════════════════════════════════════╝[/bold cyan]

[green]🎯 Features:[/green]
  • 📊 Real-time traffic statistics and metrics
  • 📡 Detailed protocol analysis (TCP, UDP, ICMP, DNS, HTTP, etc.)
  • 🔗 Active connection tracking and monitoring
  • 🏆 Top talkers and service identification
  • 🔌 Port usage analysis and service mapping
  • 🚨 Live activity alerts and packet inspection
  • 💾 Comprehensive logging and reporting

[yellow]📡 Monitoring:[/yellow]
  • All IP traffic (IPv4 and IPv6)
  • TCP/UDP connections with flag analysis
  • DNS queries and responses
  • HTTP/HTTPS traffic patterns
  • DHCP and ARP communications
  • Custom protocol detection
""")
    
    # Platform-specific information
    system = platform.system()
    console.print(f"[blue]🖥️  Platform:[/blue] {system}")
    
    # Interface information
    if args.interface:
        console.print(f"[blue]🎯 Target Interface:[/blue] {args.interface}")
    else:
        console.print("[blue]🎯 Target Interface:[/blue] Default system interface")
    
    console.print("\n[green]🚀 Starting capture in 3 seconds...[/green]")
    time.sleep(3)
    
    # Initialize and start analysis
    capture = EnhancedPacketCapture(interface=args.interface)
    analyzer = RealTimeAnalyzer(capture)
    
    # Start capture
    capture.start_capture()
    
    # Start analysis
    analyzer.run_analysis()

if __name__ == "__main__":
    main()