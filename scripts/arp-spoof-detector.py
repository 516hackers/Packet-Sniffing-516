import argparse
import time
from collections import defaultdict, deque
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import json
import smtplib
from email.mime.text import MimeText

class ARPSpoofDetector:
    def __init__(self, interface, alert_threshold=3, monitoring_period=60, output_file=None):
        self.interface = interface
        self.alert_threshold = alert_threshold
        self.monitoring_period = monitoring_period
        self.output_file = output_file
        
        # Data structures for detection
        self.arp_table = {}  # IP -> MAC mapping
        self.suspicious_activity = defaultdict(lambda: deque(maxlen=100))
        self.alerts_triggered = set()
        
        # Colors for output
        self.colors = {
            'reset': '\033[0m',
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m'
        }
        
        self.start_time = time.time()
    
    def print_banner(self):
        banner = f"""
{self.colors['cyan']}
╔══════════════════════════════════════════════════════════════╗
║              516 HACKERS - ARP SPOOF DETECTOR               ║
║               Educational Use Only                          ║
╚══════════════════════════════════════════════════════════════╗
        {self.colors['reset']}
"""
        print(banner)
    
    def get_vendor_from_mac(self, mac_address):
        """Get vendor information from MAC address (basic implementation)"""
        # This is a simplified version - in practice, you'd use a full OUI database
        oui = mac_address[:8].upper()
        
        common_ouis = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:1D:0F': 'VirtualBox',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU',
            '00:1A:11': 'Google',
            '3C:CE:73': 'Cisco',
            '00:1B:21': 'Cisco',
            '00:24:81': 'Cisco',
            '00:26:0B': 'Cisco',
        }
        
        return common_ouis.get(oui, 'Unknown')
    
    def log_alert(self, alert_type, details):
        """Log security alerts"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        alert_message = f"[{timestamp}] {alert_type}: {details}"
        
        print(f"{self.colors['red']}{alert_message}{self.colors['reset']}")
        
        # Save to file if specified
        if self.output_file:
            with open(self.output_file, 'a') as f:
                f.write(alert_message + '\n')
    
    def detect_arp_spoofing(self, packet):
        """Main ARP spoofing detection logic"""
        if packet.haslayer(ARP):
            arp = packet[ARP]
            
            # Only process ARP replies (op=2)
            if arp.op == 2:  # is-at (reply)
                ip_src = arp.psrc
                mac_src = arp.hwsrc
                
                # Check if we've seen this IP before
                if ip_src in self.arp_table:
                    previous_mac = self.arp_table[ip_src]
                    
                    # MAC address changed for the same IP
                    if previous_mac != mac_src:
                        self.handle_mac_change(ip_src, previous_mac, mac_src, packet)
                else:
                    # New IP-MAC mapping
                    self.arp_table[ip_src] = mac_src
                    vendor = self.get_vendor_from_mac(mac_src)
                    print(f"{self.colors['green']}[+] New ARP mapping: {ip_src} -> {mac_src} ({vendor}){self.colors['reset']}")
    
    def handle_mac_change(self, ip_src, previous_mac, new_mac, packet):
        """Handle cases where MAC address changes for an IP"""
        timestamp = time.time()
        
        # Record this suspicious activity
        key = f"{ip_src}_{new_mac}"
        self.suspicious_activity[key].append(timestamp)
        
        # Check if this exceeds our threshold
        recent_events = [ts for ts in self.suspicious_activity[key] 
                        if timestamp - ts < self.monitoring_period]
        
        if len(recent_events) >= self.alert_threshold and key not in self.alerts_triggered:
            self.trigger_alert(ip_src, previous_mac, new_mac, len(recent_events))
            self.alerts_triggered.add(key)
    
    def trigger_alert(self, ip_src, previous_mac, new_mac, event_count):
        """Trigger an ARP spoofing alert"""
        previous_vendor = self.get_vendor_from_mac(previous_mac)
        new_vendor = self.get_vendor_from_mac(new_mac)
        
        alert_details = (
            f"IP: {ip_src} | "
            f"Previous MAC: {previous_mac} ({previous_vendor}) | "
            f"New MAC: {new_mac} ({new_vendor}) | "
            f"Events: {event_count}"
        )
        
        self.log_alert("ARP_SPOOF_DETECTED", alert_details)
        
        # Additional detection heuristics
        self.run_additional_checks(ip_src, new_mac)
    
    def run_additional_checks(self, suspicious_ip, suspicious_mac):
        """Run additional verification checks"""
        
        # Check for VMware/VirtualBox MACs (common in spoofing)
        vendor = self.get_vendor_from_mac(suspicious_mac)
        if vendor in ['VMware', 'VirtualBox', 'QEMU', 'Parallels']:
            self.log_alert("SUSPICIOUS_VENDOR", 
                          f"Virtualization MAC detected: {suspicious_mac} ({vendor}) for IP {suspicious_ip}")
        
        # Check for unicast MAC address format
        if int(suspicious_mac[:2], 16) & 0x01:
            self.log_alert("SUSPICIOUS_MAC_FORMAT", 
                          f"Multicast MAC address used: {suspicious_mac}")
    
    def detect_gratuitous_arp(self, packet):
        """Detect gratuitous ARP packets (common in attacks)"""
        if packet.haslayer(ARP):
            arp = packet[ARP]
            
            # Gratuitous ARP: op=2, psrc=pdst, hwsrc != hwdst
            if (arp.op == 2 and 
                arp.psrc == arp.pdst and 
                arp.hwsrc != arp.hwdst):
                
                self.log_alert("GRATUITOUS_ARP", 
                              f"IP: {arp.psrc} | MAC: {arp.hwsrc}")
    
    def detect_arp_flood(self, packet):
        """Detect ARP flood attacks"""
        timestamp = time.time()
        
        # Track ARP packet rate
        self.suspicious_activity['arp_flood'].append(timestamp)
        
        # Check flood rate (more than 10 ARP packets per second)
        recent_arp = [ts for ts in self.suspicious_activity['arp_flood'] 
                     if timestamp - ts < 1]
        
        if len(recent_arp) > 10:
            self.log_alert("ARP_FLOOD", 
                          f"High ARP rate detected: {len(recent_arp)} packets/second")
    
    def passive_analysis(self):
        """Passive network analysis"""
        print(f"{self.colors['yellow']}[*] Starting passive network analysis...{self.colors['reset']}")
        print(f"{self.colors['yellow']}[*] Monitoring interface: {self.interface}{self.colors['reset']}")
        print(f"{self.colors['yellow']}[*] Alert threshold: {self.alert_threshold} changes per {self.monitoring_period} seconds{self.colors['reset']}")
        print(f"{self.colors['yellow']}[*] Press Ctrl+C to stop monitoring\n{self.colors['reset']}")
        
        try:
            sniff(iface=self.interface, prn=self.analyze_packet, store=0)
        except KeyboardInterrupt:
            print(f"\n{self.colors['red']}[!] Monitoring stopped by user{self.colors['reset']}")
        except Exception as e:
            print(f"{self.colors['red']}[!] Error: {e}{self.colors['reset']}")
    
    def analyze_packet(self, packet):
        """Comprehensive packet analysis"""
        # ARP spoofing detection
        self.detect_arp_spoofing(packet)
        
        # Gratuitous ARP detection
        self.detect_gratuitous_arp(packet)
        
        # ARP flood detection
        self.detect_arp_flood(packet)
    
    def print_statistics(self):
        """Print monitoring statistics"""
        duration = time.time() - self.start_time
        print(f"\n{self.colors['cyan']}=== MONITORING STATISTICS ==={self.colors['reset']}")
        print(f"{self.colors['yellow']}Duration: {duration:.2f} seconds{self.colors['reset']}")
        print(f"{self.colors['green']}Hosts monitored: {len(self.arp_table)}{self.colors['reset']}")
        print(f"{self.colors['red']}Alerts triggered: {len(self.alerts_triggered)}{self.colors['reset']}")
    
    def generate_report(self):
        """Generate security report"""
        report = {
            'monitoring_duration': time.time() - self.start_time,
            'hosts_monitored': len(self.arp_table),
            'alerts_triggered': list(self.alerts_triggered),
            'arp_table': self.arp_table,
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(
        description='516 Hackers - ARP Spoofing Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-i', '--interface', required=True, 
                       help='Network interface to monitor')
    parser.add_argument('-t', '--threshold', type=int, default=3,
                       help='Alert threshold (changes per monitoring period)')
    parser.add_argument('-p', '--period', type=int, default=60,
                       help='Monitoring period in seconds')
    parser.add_argument('-o', '--output', 
                       help='Output file for alerts')
    
    args = parser.parse_args()
    
    detector = ARPSpoofDetector(
        interface=args.interface,
        alert_threshold=args.threshold,
        monitoring_period=args.period,
        output_file=args.output
    )
    
    detector.print_banner()
    detector.passive_analysis()
    detector.print_statistics()
    
    # Save final report
    if args.output:
        report = detector.generate_report()
        with open(f"{args.output}.report.json", 'w') as f:
            json.dump(report, f, indent=2)
        print(f"{detector.colors['green']}[+] Report saved to {args.output}.report.json{detector.colors['reset']}")

if __name__ == "__main__":
    main()
