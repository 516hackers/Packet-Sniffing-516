
# 📊 Wireshark Mastery Guide - 516 Hackers

## 🎯 Introduction to Wireshark
Wireshark is the world's foremost network protocol analyzer. It lets you see what's happening on your network at a microscopic level and is the standard across many commercial and non-profit enterprises.

> **516 Note**: Wireshark is like a microscope for your network - use it to understand, diagnose, and secure network communications.

---

## 📦 Installation Guide

### Kali Linux (Pre-installed):
```bash
# Update to latest version
sudo apt update && sudo apt install wireshark -y

# Configure to run without root (recommended)
sudo dpkg-reconfigure wireshark-common
sudo usermod -a -G wireshark $USER

# Log out and back in for group changes to take effect
```

### Ubuntu/Debian:
```bash
# Install Wireshark
sudo apt install wireshark

# Or install from official PPA for latest version
sudo add-apt-repository ppa:wireshark-dev/stable
sudo apt update
sudo apt install wireshark
```

### Windows:
1. Download from: https://www.wireshark.org/download.html
2. Install with WinPcap/Npcap support
3. Run as administrator for live capture

### macOS:
```bash
# Using Homebrew
brew install wireshark

# Or download DMG from official website
```

### Verify Installation:
```bash
# Check version
wireshark -v
tshark -v

# Test capture (may require root)
sudo wireshark
```

---

## 🏁 Getting Started

### First Launch:
1. **Launch Wireshark** from applications menu or terminal
2. **Select network interface** (eth0, wlan0, etc.)
3. **Click the shark fin icon** or press `Ctrl+E` to start capture
4. **Stop capture** with red square button or `Ctrl+E`

### Interface Overview:

#### Main Components:
- **🛠️ Menu Bar**: File, Edit, View, Go, Capture, Analyze, Statistics, Telephony, Wireless, Tools, Help
- **⚡ Toolbar**: Quick actions (start, stop, restart capture, open, save)
- **🔍 Filter Toolbar**: Display filters and expression buttons
- **📋 Packet List Pane**: Overview of captured packets with basic info
- **📖 Packet Details Pane**: Hierarchical view of packet protocols
- **🔢 Packet Bytes Pane**: Raw hexadecimal and ASCII representation

#### Color Coding:
- **Light Purple**: TCP packets
- **Light Blue**: UDP packets  
- **Black**: Packets with errors
- **Red**: TCP RST packets
- **Light Green**: HTTP packets
- **Light Yellow**: DNS packets

### Command Line Capture:
```bash
# Basic capture to file
wireshark -i eth0 -k -w capture.pcap

# Capture with filter
wireshark -i eth0 -f "tcp port 80" -w http_capture.pcap

# Capture specific number of packets
wireshark -i eth0 -c 100 -w limited_capture.pcap
```

---

## 🎛️ Essential Display Filters

### Basic Protocol Filters:
```bash
# Common protocol filters
http          # HTTP traffic
tcp           # TCP packets
udp           # UDP packets  
dns           # DNS queries and responses
icmp          # ICMP (ping) packets
arp           # ARP requests and replies
ssh           # SSH connections
ftp           # FTP file transfers
```

### IP Address Filters:
```bash
# Specific IP addresses
ip.addr == 192.168.1.100          # Traffic to/from IP
ip.src == 192.168.1.100           # Traffic from IP
ip.dst == 192.168.1.1             # Traffic to IP

# IP ranges
ip.addr >= 192.168.1.1 and ip.addr <= 192.168.1.100
```

### Port Filters:
```bash
# Specific ports
tcp.port == 80                    # TCP port 80 (HTTP)
tcp.port == 443                   # TCP port 443 (HTTPS)
udp.port == 53                    # UDP port 53 (DNS)
tcp.dstport == 22                 # TCP destination port 22 (SSH)
tcp.srcport == 8080               # TCP source port 8080
```

### Advanced Filter Combinations:
```bash
# Multiple conditions
http and ip.addr == 192.168.1.100
tcp.port == 80 and frame.time >= "2024-01-01 10:00:00"

# Exclusion filters
not arp                          # Exclude ARP packets
not dns                          # Exclude DNS packets
http and not ip.addr == 192.168.1.1

# Pattern matching
http.request.uri contains "login"
dns.qry.name contains "google"
http.user_agent contains "Mozilla"

# Size-based filters
frame.len > 1000                 # Packets larger than 1000 bytes
tcp.len > 500                    # TCP payload larger than 500 bytes
```

### Common Practical Filters:
```bash
# HTTP analysis
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.response.code == 404

# DNS analysis
dns.flags.response == 0          # DNS queries only
dns.flags.response == 1          # DNS responses only
dns.qry.type == 1                # A record queries

# TCP analysis
tcp.flags.syn == 1               # SYN packets (connection start)
tcp.flags.fin == 1               # FIN packets (connection end)
tcp.analysis.retransmission      # Retransmitted packets
tcp.analysis.duplicate_ack       # Duplicate ACKs

# Error detection
tcp.analysis.lost_segment        # Lost segments
tcp.analysis.ack_lost_segment    # ACK for lost segment
icmp.type == 3                   # Destination unreachable
```

---

## 📊 Packet Analysis Techniques

### Following TCP Streams:
1. **Right-click** on any TCP packet
2. Select **"Follow" → "TCP Stream"**
3. **Analyze complete conversation** between client and server
4. **Save conversation** or export data
5. **Change stream** to see different conversations

### HTTP Stream Analysis:
```bash
# Filter for HTTP conversations
http

# Follow TCP stream to see complete HTTP session
# Look for:
# - Request headers
# - Response headers  
# - Status codes
# - Cookies and sessions
# - Form data and parameters
```

### Exporting Objects:
1. **File → Export Objects → HTTP**
2. **Browse available files** (images, documents, etc.)
3. **Select and save** specific files
4. **Analyze downloaded content**

### Conversation Analysis:
1. **Statistics → Conversations**
2. **View TCP, UDP, IP conversations**
3. **Identify top talkers** and bandwidth usage
4. **Filter conversations** by protocol or address

### Endpoint Analysis:
1. **Statistics → Endpoints**
2. **View all communicating endpoints**
3. **Analyze traffic distribution**
4. **Identify suspicious hosts**

---

## 🎨 Color Coding Rules

### Default Color Scheme:
- **Light Green**: HTTP traffic
- **Light Blue**: UDP traffic
- **Light Purple**: TCP traffic
- **Pink**: TCP errors or unusual packets
- **Black**: Packets with errors
- **Red**: TCP RST packets

### Custom Color Rules:
1. **View → Coloring Rules**
2. **Create new rules** or modify existing
3. **Apply colors based on filters**

### Useful Custom Color Rules:
```bash
# Suspicious traffic - Red
tcp.flags.reset == 1
tcp.analysis.retransmission

# Important traffic - Yellow
dns
http.request.method == "POST"

# Normal traffic - Green  
http.request.method == "GET"
tcp.port == 443

# Administrative traffic - Blue
tcp.port == 22
tcp.port == 23
```

### Saving Color Profiles:
1. Create your color rules
2. **View → Coloring Rules → Export**
3. Save as **colorprofile.xml**
4. Import on other installations

---

## 🔍 Forensic Analysis

### HTTP Traffic Analysis:
```bash
# Find all HTTP requests
http.request

# Find POST requests with data
http.request.method == "POST"

# Find specific user agents
http.user_agent contains "Mozilla"
http.user_agent contains "curl"
http.user_agent contains "python"

# Find cookies
http.cookie
http.set_cookie

# Find authentication
http.authorization
http.request.uri contains "login"
```

### DNS Traffic Analysis:
```bash
# All DNS queries
dns.qry.name

# Failed DNS queries
dns.flags.rcode != 0

# Specific domain queries
dns.qry.name contains "facebook"
dns.qry.name contains "google"

# DNS query types
dns.qry.type == 1    # A records
dns.qry.type == 28   # AAAA records (IPv6)
dns.qry.type == 5    # CNAME records
dns.qry.type == 15   # MX records
```

### SSL/TLS Analysis:
```bash
# SSL handshakes
ssl.handshake

# Certificate information
ssl.handshake.certificate

# Encrypted alerts
ssl.record.content_type == 21

# Specific TLS versions
ssl.record.version == 0x0301    # TLS 1.0
ssl.record.version == 0x0302    # TLS 1.1
ssl.record.version == 0x0303    # TLS 1.2
ssl.record.version == 0x0304    # TLS 1.3
```

### Malware Traffic Indicators:
```bash
# Suspicious patterns
dns.qry.name.len > 50                   # Long domain names (DGA)
tcp.payload contains "cmd.exe"          # Windows commands
http.request.uri contains ".exe"        # Executable downloads
http.request.uri contains ".php?"       # PHP with parameters

# Beaconing detection
frame.time_delta > 60 && tcp           # Regular intervals
dns.qry.name contains "update"         # Update domains
```

---

## 📈 Statistics and Reporting

### Protocol Hierarchy:
1. **Statistics → Protocol Hierarchy**
2. **View protocol distribution** by bytes and packets
3. **Identify unusual protocols**
4. **Export statistics** for reporting

### IO Graphs:
1. **Statistics → IO Graphs**
2. **Create custom graphs** with filters
3. **Measure network performance**
4. **Identify traffic patterns and anomalies**

### Flow Graphs:
1. **Statistics → Flow Graph**
2. **Visualize conversations** between hosts
3. **Identify connection patterns**
4. **Detect scanning activities**

### HTTP Statistics:
1. **Statistics → HTTP → Packet Counter**
2. **Analyze request/response distribution**
3. **Identify error rates**
4. **View server statistics**

### DNS Statistics:
1. **Statistics → DNS**
2. **Analyze query/response timing**
3. **View response code distribution**
4. **Identify DNS performance issues**

---

## 🎪 Practical Labs

### Lab 1: Basic HTTP Capture and Analysis
```bash
# Capture filter
tcp port 80

# Steps:
1. Start capture with filter "tcp port 80"
2. Browse to a HTTP website (not HTTPS)
3. Stop capture after loading page
4. Analyze HTTP requests/responses
5. Follow TCP streams
6. Export HTTP objects
7. Look for cookies and sessions
```

### Lab 2: DNS Query Analysis
```bash
# Capture filter
udp port 53

# Steps:
1. Capture DNS traffic
2. Perform nslookup commands
3. Analyze query/response patterns
4. Identify recursive vs iterative queries
5. Look for DNS errors
6. Export DNS statistics
```

### Lab 3: Network Scanning Detection
```bash
# Display filters for common scans
tcp.flags.syn==1 and tcp.flags.ack==0  # SYN scan
tcp.flags==0x0000                       # NULL scan
tcp.flags.fin==1                        # FIN scan
tcp.flags.syn==1 and tcp.flags.fin==1   # XMAS scan

# Steps:
1. Capture network traffic
2. Run nmap scan against target
3. Analyze scan patterns in Wireshark
4. Identify scan type from flags
5. Create detection filters
```

### Lab 4: TLS/SSL Handshake Analysis
```bash
# Display filter
ssl.handshake

# Steps:
1. Capture HTTPS traffic
2. Browse to HTTPS website
3. Analyze TLS handshake process
4. Examine certificate exchange
5. Identify cipher suites
6. Check for weak encryption
```

---

## 🔧 Command Line Tools

### TShark (Command-line Wireshark):
```bash
# Basic capture
tshark -i eth0

# Capture with filter
tshark -i eth0 -f "tcp port 80"

# Capture to file
tshark -i eth0 -w capture.pcap

# Read from file with filter
tshark -r capture.pcap -Y "http"

# Output specific fields
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri

# Statistics mode
tshark -r capture.pcap -z http,stat
tshark -r capture.pcap -z conv,tcp

# Follow TCP stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

### Dumpcap (Lightweight Capture):
```bash
# Basic capture
dumpcap -i eth0 -w capture.pcap

# Ring buffer capture
dumpcap -i eth0 -w capture -b filesize:100000 -b files:10

# Capture with buffer size
dumpcap -i eth0 -B 100 -w capture.pcap

# Capture specific duration
dumpcap -i eth0 -a duration:300 -w capture.pcap
```

### Capinfos (Capture File Information):
```bash
# Get capture file statistics
capinfos capture.pcap

# Detailed information
capinfos -T -H -E -c -d -u -x -y -z capture.pcap

# Multiple files
capinfos *.pcap
```

### Editcap (Capture File Editing):
```bash
# Convert file format
editcap -F pcapng input.pcap output.pcapng

# Extract specific packets
editcap -r input.pcap output.pcap 1-100

# Remove duplicate packets
editcap -d input.pcap output.pcap

# Split large files
editcap -c 10000 large.pcap split.pcap
```

### Mergecap (Combine Capture Files):
```bash
# Merge multiple files
mergecap -w merged.pcap file1.pcap file2.pcap file3.pcap

# Merge with timestamps
mergecap -a -w merged.pcap *.pcap
```

---

## 📋 Profile Management

### Creating Custom Profiles:
1. **Edit → Configuration Profiles**
2. **Click "+" to create new profile**
3. **Customize settings** for specific scenarios
4. **Switch between profiles** as needed

### Useful Profile Configurations:

#### HTTP Analysis Profile:
- **Columns**: Add URI, Host, User-Agent
- **Filters**: HTTP filter buttons
- **Colors**: Highlight POST requests, errors
- **Preferences**: Enable HTTP object export

#### Security Monitoring Profile:
- **Columns**: Add alert flags, severity
- **Filters**: Suspicious traffic filters
- **Colors**: Red for attacks, yellow for scans
- **Preferences**: Enable expert info

#### Performance Analysis Profile:
- **Columns**: Add delta time, throughput
- **Filters**: TCP analysis filters
- **Colors**: Highlight retransmissions, duplicates
- **Preferences**: Enable TCP sequence numbers

### Exporting/Importing Profiles:
```bash
# Profiles are stored in:
~/.config/wireshark/profiles/          # Linux
%APPDATA%\Wireshark\profiles\          # Windows
~/Library/Application Support/Wireshark/profiles/  # macOS
```

---

## 🔧 Performance Optimization

### Capture Performance:
```bash
# Use capture filters instead of display filters
tshark -f "tcp port 80" -w http.pcap

# Limit packet size
tshark -s 96 -i eth0

# Use ring buffers for long captures
dumpcap -i eth0 -b filesize:100000 -b files:10 -w capture

# Increase buffer size
tshark -B 1024 -i eth0
```

### Display Performance:
- Use simple display filters
- Limit number of packets in memory
- Close unused capture files
- Use "Decode As" for custom protocols
- Disable unnecessary protocol dissectors

### Memory Management:
1. **Edit → Preferences → Appearance**
2. **Set "Max recent files"** to reasonable number
3. **Edit → Preferences → Advanced**
4. **Adjust memory allocation** as needed

### Keyboard Shortcuts for Efficiency:
```bash
Ctrl+E      # Start/stop capture
Ctrl+K      # Clear capture
Ctrl+F      # Find packets
Ctrl+Shift+F # Find next
Ctrl+N      # New capture
Ctrl+O      # Open file
Ctrl+S      # Save file
Ctrl+Q      # Quit
```

---

## 🎯 Pro Tips

### Time Display Formats:
- **Seconds since previous packet**: Best for timing analysis
- **Seconds since beginning**: Good for overall timeline
- **Absolute date and time**: Useful for correlation with logs
- **UTC time**: Essential for multi-timezone analysis

### Expert Information:
1. **Analyze → Expert Information**
2. **Review warnings, notes, and errors**
3. **Identify network problems quickly**
4. **Use as starting point for investigation**

### Custom Columns:
```bash
# Add useful columns:
- http.request.uri
- dns.qry.name
- ssl.handshake.type
- tcp.analysis.ack_rtt
- frame.time_delta
```

### Exporting Data:
```bash
# Export packets to CSV
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e protocol -E header=y -E separator=, > output.csv

# Export HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.request.method -e http.request.uri -e http.host > http_requests.csv

# Export to JSON
tshark -r capture.pcap -T json > output.json
```

### Remote Capture:
```bash
# Capture from remote machine via SSH
ssh user@remote-host "tcpdump -i eth0 -w -" | wireshark -k -i -

# Or save to file first
ssh user@remote-host "tcpdump -i eth0 -w /tmp/capture.pcap"
scp user@remote-host:/tmp/capture.pcap ./
```

---

## ⚠️ Common Issues & Solutions

### "No Interfaces Listed":
```bash
# Fix permissions (Linux)
sudo chmod +x /usr/bin/dumpcap
sudo usermod -a -G wireshark $USER
# Log out and back in

# Windows: Run as Administrator
# macOS: Install from official package
```

### "Capture Filters Invalid":
- Use BPF syntax: `tcp port 80`
- Test filters with tcpdump first: `tcpdump -i eth0 'tcp port 80'`
- Check syntax: no quotes in capture filters

### Performance Issues:
- Use capture filters to reduce load
- Limit packet size with `-s` option
- Increase buffer size
- Use ring buffers for long captures

### "File Could Not Be Opened":
- Check file permissions
- Verify file isn't corrupted
- Try opening with `tshark -r file.pcap`

### Decryption Issues:
- Import SSL keys: **Edit → Preferences → Protocols → TLS**
- Use RSA keys for decryption
- Check if encryption is supported

---

## 🚀 Advanced Features

### Custom Protocol Dissectors:
1. **Write Lua scripts** for custom protocols
2. **Place in plugins directory**
3. **Reload Wireshark** to activate
4. **Test with sample captures**

### Lua Scripting Example:
```lua
-- simple_protocol.lua
local simple_protocol = Proto("simple", "Simple Protocol")

local f_field = ProtoField.uint32("simple.field", "Simple Field", base.DEC)

simple_protocol.fields = {f_field}

function simple_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "SIMPLE"
    local subtree = tree:add(simple_protocol, buffer(), "Simple Protocol Data")
    subtree:add(f_field, buffer(0,4))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9999, simple_protocol)
```

### Automated Analysis Scripts:
```bash
#!/bin/bash
# analyze_capture.sh

CAPTURE=$1

echo "=== Capture Analysis Report ==="
echo "File: $CAPTURE"
echo "Generated: $(date)"
echo ""

# Basic statistics
echo "## Basic Statistics"
capinfos $CAPTURE | grep -E "(File type|Packet size|Number of packets)"

# Top talkers
echo ""
echo "## Top Talkers"
tshark -r $CAPTURE -q -z endpoints,ip | head -20

# Protocol hierarchy
echo ""
echo "## Protocol Hierarchy"
tshark -r $CAPTURE -q -z io,phs | head -30
```

### Integration with Other Tools:
```bash
# Extract IOCs with Wireshark and grep
tshark -r capture.pcap -T fields -e http.host | sort | uniq > domains.txt

# Create firewall rules
tshark -r capture.pcap -Y "tcp.flags.syn==1" -T fields -e ip.dst | sort | uniq | \
xargs -I {} echo "iptables -A INPUT -s {} -j DROP"

# Generate threat intelligence
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | \
grep -v -E "(google|microsoft|apple)" | sort | uniq > suspicious_domains.txt
```

---

## 📚 Learning Resources

### Official Resources:
- **Wireshark Official Documentation**: https://www.wireshark.org/docs/
- **Wireshark University**: https://www.wireshark-training.com/
- **Sample Captures**: https://wiki.wireshark.org/SampleCaptures

### Practice Websites:
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/
- **Packet Total**: https://packettotal.com/
- **NetResec**: https://www.netresec.com/?page=PCAP

### Books:
- **"Wireshark Network Analysis"** by Laura Chappell
- **"Practical Packet Analysis"** by Chris Sanders
- **"Network Forensics"** by Sherri Davidoff

### Communities:
- **Wireshark Q&A**: https://ask.wireshark.org/
- **Reddit r/wireshark**
- **Stack Overflow** (wireshark tag)

---

*"In the world of networks, packets don't lie. Wireshark helps us listen to their stories." - 516 Hackers*

---
*516 Hackers - See the Unseen, Understand the Unknown*
