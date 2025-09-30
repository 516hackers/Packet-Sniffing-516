

# 🔍 Basic Packet Sniffing Guide - 516 Hackers

## 🎯 Overview
This guide walks you through the fundamentals of packet sniffing using various tools and techniques.
```
## 📋 Prerequisites
- Linux system (Kali Linux recommended)
- Root/administrator privileges
- Basic understanding of networking
- Ethical mindset and proper authorization

## 🛠️ Required Tools Installation

### Kali Linux (Pre-installed):
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install additional tools
sudo apt install -y tcpdump tshark dsniff
```

### Other Linux Distributions:
```bash
# Install essential tools
sudo apt install tcpdump wireshark bettercap python3-pip

# Install Python requirements
pip3 install scapy
```

## 📡 Step 1: Network Interface Configuration

### List Available Interfaces:
```bash
# Method 1: Using ip command
ip link show

# Method 2: Using ifconfig
ifconfig

# Method 3: Using bettercap
sudo bettercap -iface any --check
```

### Enable Monitor Mode (Wireless):
```bash
# Put interface in monitor mode
sudo airmon-ng start wlan0

# Check mode
iwconfig
```

## 🎪 Step 2: Basic TCPDump Usage

### Simple Capture:
```bash
# Capture on specific interface
sudo tcpdump -i eth0

# Capture with verbose output
sudo tcpdump -i eth0 -v

# Capture specific number of packets
sudo tcpdump -i eth0 -c 100
```

### Advanced TCPDump Filters:
```bash
# Capture only HTTP traffic
sudo tcpdump -i eth0 -A 'tcp port 80'

# Capture traffic to/from specific IP
sudo tcpdump -i eth0 host 192.168.1.100

# Capture DNS queries
sudo tcpdump -i eth0 -A 'port 53'

# Save capture to file
sudo tcpdump -i eth0 -w capture.pcap
```

## 🐍 Step 3: Python Scapy Sniffer

### Basic Sniffer Script:
```python
#!/usr/bin/env python3
from scapy.all import *
import argparse

def simple_sniffer():
    """Basic packet sniffer using Scapy"""
    print("[*] Starting basic packet sniffer...")
    print("[*] Press Ctrl+C to stop\n")
    
    # Capture packets with callback
    sniff(prn=process_packet, count=0)

def process_packet(packet):
    """Process each captured packet"""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"IP: {ip_src:15} -> {ip_dst:15} | Proto: {protocol}")
        
        # Show TCP information
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"    TCP: {sport} -> {dport}")
            
        # Show UDP information  
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"    UDP: {sport} -> {dport}")

if __name__ == "__main__":
    simple_sniffer()
```

## 🎭 Step 4: Bettercap Practical Session

### Starting Bettercap:
```bash
# Start bettercap on specific interface
sudo bettercap -iface eth0

# Or start and execute commands
sudo bettercap -iface eth0 -eval "net.probe on; net.recon on"
```

### Complete Bettercap Sniffing Session:
```bash
# Start bettercap
sudo bettercap -iface eth0

# In bettercap console:

# 1. Network discovery
net.probe on
net.recon on

# 2. View discovered hosts
net.show

# 3. Set ARP spoofing target
set arp.spoof.targets 192.168.1.100
set arp.spoof.fullduplex true

# 4. Start ARP spoofing
arp.spoof on

# 5. Start packet sniffing
net.sniff on

# 6. Monitor events
events.stream
```

### Bettercap Module Configuration:
```bash
# Configure sniffing parameters
set net.sniff.local true
set net.sniff.output capture.pcap
set net.sniff.filter tcp port 80

# Start with custom filter
net.sniff on
```

## 🔍 Step 5: Traffic Analysis

### HTTP Traffic Analysis:
```bash
# Capture HTTP traffic specifically
sudo tcpdump -i eth0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Or using bettercap
set net.sniff.filter tcp port 80
net.sniff on
```

### DNS Query Monitoring:
```bash
# Capture DNS queries and responses
sudo tcpdump -i eth0 -n 'port 53'

# More detailed DNS analysis
sudo tcpdump -i eth0 -n -v 'port 53'
```

## 📊 Step 6: Saving and Analyzing Captures

### Save Captures:
```bash
# TCPDump to file
sudo tcpdump -i eth0 -w network_capture.pcap

# Bettercap to file
set net.sniff.output capture.pcap
net.sniff on
```

### Analyze with Wireshark:
```bash
# Open capture in Wireshark
wireshark network_capture.pcap

# Or use tshark for command line
tshark -r network_capture.pcap
```

## 🛡️ Step 7: Cleanup and Stealth

### Stop ARP Spoofing:
```bash
# In bettercap
arp.spoof off
net.sniff off

# Clear ARP cache on target (if authorized)
sudo arp -d 192.168.1.100
```

### Restore Network:
```bash
# Disable monitor mode (if used)
sudo airmon-ng stop wlan0mon

# Restart network manager
sudo systemctl restart NetworkManager
```

## 🎯 Pro Tips

### Filtering Techniques:
```bash
# Capture only specific protocols
tcpdump 'icmp'
tcpdump 'udp port 53'
tcpdump 'tcp port 443'

# Capture traffic between specific hosts
tcpdump 'host 192.168.1.100 and host 8.8.8.8'

# Capture large packets
tcpdump 'greater 1000'
```

### Performance Optimization:
```bash
# Limit packet size
tcpdump -s 96

# Buffer size optimization
tcpdump -B 4096

# Ring buffer for large captures
tcpdump -w capture_%H%M%S.pcap -G 3600 -W 24
```

## ⚠️ Important Notes

1. **Always get proper authorization**
2. **Test only on networks you own or have explicit permission**
3. **Be aware of legal implications**
4. **Clean up after your testing**
5. **Document your findings ethically**

## 🚀 Next Steps

After mastering basic sniffing, move to:
- Advanced protocol analysis
- Encrypted traffic inspection
- Network forensics
- Intrusion detection

---
*516 Hackers - Knowledge is Power, Responsibility is Key*
```

