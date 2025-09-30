

## Repository Structure:

```
Packet-Sniffing-516/
│
├── README.md
├── guides/
│   ├── basic-sniffing.md
│   ├── bettercap-setup.md
│   └── wireshark-guide.md
├── scripts/
│   ├── basic-sniffer.py
│   ├── http-traffic-analyzer.py
│   └── arp-spoof-detector.py
├── captures/
│   ├── example-http.pcap
│   └── sample-dns.pcap
└── resources/
    ├── tools-list.md
    └── learning-resources.md
```

---
## README.md Content:

# 🕵️ Packet Sniffing 516 | Capture & Analyze Network Traffic

> **"See the Unseen, Hear the Digital Whisper"** | *516 Hackers Collective*

![Packet Sniffing Banner](https://via.placeholder.com/800x200/000000/FFFFFF?text=Packet+Sniffing+516+-+Capture+The+Digital+Whisper)


 A comprehensive guide to network packet sniffing - from basic concepts to advanced traffic analysis techniques. Built for security researchers, network administrators, and ethical hackers.



## 🚀 Quick Start
```
Basic Bettercap Sniffing
```
bash
# Start bettercap
```
sudo bettercap
```
# Discover hosts
```
net.probe on
```
# Start ARP spoofing (replace with target IP)
```
set arp.spoof.targets 192.168.1.100

arp.spoof on

# Begin packet sniffing

net.sniff on

```
### Python Sniffer Example
```python
from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        print(f"[+] Data: {packet[Raw].load}")

sniff(prn=packet_handler, filter="tcp", count=50)
```

---

## 📚 Table of Contents

1. [What is Packet Sniffing?](#-what-is-packet-sniffing)
2. [Legal & Ethical Framework](#️-legal--ethical-framework)
3. [Tools of the Trade](#-tools-of-the-trade)
4. [Practical Guides](#-practical-guides)
5. [Detection & Prevention](#-detection--prevention)
6. [516 Hackers Methodology](#-516-hackers-methodology)
7. [Contributing](#-contributing)

---

## 🔍 What is Packet Sniffing?

Packet sniffing is the practice of capturing and analyzing data packets as they travel across a network. Think of it as **"eavesdropping on digital conversations"**.

### How It Works:
- **Promiscuous Mode**: Network card captures ALL packets, not just those addressed to it
- **MITM Positioning**: Placing yourself between communication points
- **Protocol Analysis**: Decoding various network protocols

### What You Can Capture:
| Traffic Type | Visibility | Example Data |
|-------------|------------|--------------|
| **HTTP** | 🔓 Full Content | Passwords, cookies, images |
| **HTTPS** | 🔒 Encrypted | Only metadata visible |
| **DNS** | 🔓 Queries | Websites being visited |
| **FTP** | 🔓 Full Content | Files, credentials |

---

## ⚖️ Legal & Ethical Framework

### 🚫 Strictly For:
- Security research on YOUR OWN networks
- Penetration testing with EXPLICIT permission
- Network troubleshooting and education

### 🚨 Absolutely NOT For:
- Unauthorized network monitoring
- Credential theft
- Corporate espionage
- Any illegal activities

> **516 Ethics Code**: "With great power comes great responsibility. Knowledge is a tool - use it to protect, not to harm."

---

## 🛠️ Tools of the Trade

### Primary Tools:
- **Bettercap** - Swiss army knife for network attacks
- **Wireshark** - Deep packet analysis
- **tcpdump** - Command-line packet capture
- **Scapy** - Python packet manipulation

### 516 Recommended Stack:
```yaml
Reconnaissance:
  - bettercap
  - nmap
  
Capture:
  - wireshark
  - tcpdump
  
Analysis:
  - scapy (python)
  - custom scripts
```

---

## 📖 Practical Guides

### [Basic Bettercap Sniffing](guides/basic-sniffing.md)
```bash
# Full bettercap session example
sudo bettercap -iface eth0
# > net.probe on
# > set arp.spoof.targets 192.168.1.100
# > arp.spoof on
# > net.sniff on
```

### [Wireshark Analysis](guides/wireshark-guide.md)
- Filtering techniques
- Following TCP streams
- Exporting objects

### Advanced Techniques:
- SSL/TLS decryption (when possible)
- VoIP call reconstruction
- Network forensics

---

## 🛡️ Detection & Prevention

### How to Detect Sniffing:
```python
# ARP spoofing detection script
from scapy.all import *

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        real_mac = getmacbyip(packet[ARP].psrc)
        response_mac = packet[ARP].hwsrc
        if real_mac != response_mac:
            print(f"[!] ARP Spoof detected: {packet[ARP].psrc}")

sniff(prn=detect_arp_spoof, filter="arp", store=0)
```

### Prevention Measures:
- **Encryption**: Use HTTPS, SSH, VPNs
- **Network Segmentation**: Isolate sensitive traffic
- **ARP Monitoring**: Detect spoofing attempts
- **Switch Security**: Port security, DHCP snooping

---

## 🎯 516 Hackers Methodology

### Our Approach:
1. **Reconnaissance** - Map the network landscape
2. **Positioning** - Strategic placement for capture
3. **Capture** - Selective packet acquisition
4. **Analysis** - Extract meaningful intelligence
5. **Reporting** - Document findings ethically

### 516 Principles:
- **Knowledge First**: Understand before you act
- **Stealth with Purpose**: Be invisible, but for the right reasons
- **Leave No Trace**: Clean up after testing
- **Share Wisdom**: Contribute to the security community

---

## 🤝 Contributing

We welcome contributions from ethical security researchers!

### How to Contribute:
1. Fork the repository
2. Add your techniques or scripts
3. Follow our ethical guidelines
4. Submit a pull request

### Areas Needing Contributions:
- New detection scripts
- Advanced analysis techniques
- Defensive strategies
- Educational content

---

## ⚠️ Disclaimer

> This repository is for educational and authorized security testing purposes only. The 516 Hackers Collective does not condone illegal activities. Always obtain proper authorization before testing on any network. Users are solely responsible for complying with applicable laws.

---

## 📞 Contact & Resources

- **Instagram**: [https://www.instagram.com/516_hackers/]

---

**"In the silence of packets, truth travels."** - *516 Hackers*

---
```

## Additional Files You Should Create:

### 1. `guides/basic-sniffing.md`
```markdown
# Basic Packet Sniffing Guide

## Prerequisites
- Linux system (Kali Linux recommended)
- Root/administrator privileges
- Basic networking knowledge

## Step-by-Step Process

### 1. Network Reconnaissance
```bash
# Discover active hosts
sudo netdiscover -i eth0 -r 192.168.1.0/24

# Or using bettercap
sudo bettercap -iface eth0
net.probe on
```

### 2. ARP Spoofing Setup
[... continue with detailed steps ...]
```

### 2. `scripts/basic-sniffer.py`
```python
#!/usr/bin/env python3
"""
516 Hackers - Basic Packet Sniffer
Educational purposes only
"""

from scapy.all import *
import argparse

def packet_callback(packet):
    """Process each captured packet"""
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"[+] {ip_src} -> {ip_dst} | Protocol: {proto}")
        
        # Check for raw data (unencrypted)
        if packet.haslayer(Raw):
            load = packet[Raw].load
            try:
                decoded_load = load.decode('utf-8', errors='ignore')
                if any(keyword in decoded_load.lower() for keyword in ['pass', 'user', 'login']):
                    print(f"[!] Possible credentials: {decoded_load[:100]}")
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description='516 Basic Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface', required=True)
    parser.add_argument('-c', '--count', help='Packet count', type=int, default=0)
    
    args = parser.parse_args()
    
    print(f"[*] 516 Packet Sniffer starting on {args.interface}")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        sniff(iface=args.interface, prn=packet_callback, count=args.count)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user")
    except PermissionError:
        print("[!] Need root privileges!")

if __name__ == "__main__":
    main()
```
