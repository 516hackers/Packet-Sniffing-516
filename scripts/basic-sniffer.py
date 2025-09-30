
import argparse
import socket
import struct
import textwrap
from datetime import datetime
import sys
from scapy.all import *
from scapy.layers import http
import json

class BasicSniffer:
    def __init__(self, interface=None, count=0, output_file=None, verbose=False):
        self.interface = interface
        self.count = count
        self.output_file = output_file
        self.verbose = verbose
        self.packet_count = 0
        
        # Colors for terminal output
        self.colors = {
            'reset': '\033[0m',
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m'
        }
        
    def print_banner(self):
        """Display 516 Hackers banner"""
        banner = f"""
{self.colors['cyan']}
╔══════════════════════════════════════════════════════════════╗
║                  516 HACKERS - PACKET SNIFFER               ║
║                 Educational Use Only                        ║
╚══════════════════════════════════════════════════════════════╗
        {self.colors['reset']}
"""
        print(banner)
        
    def print_packet_info(self, packet):
        """Extract and print packet information"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            
            # Protocol mapping
            proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            proto_name = proto_map.get(protocol, f"Proto-{protocol}")
            
            print(f"{self.colors['green']}[{timestamp}] {self.colors['blue']}{ip_src:15} → {ip_dst:15} {self.colors['yellow']}{proto_name:8}{self.colors['reset']}", end="")
            
            # TCP specific info
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags
                print(f" {self.colors['magenta']}TCP:{sport}→{dport} Flags:{flags}{self.colors['reset']}")
                
                # Check for HTTP
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.process_http(packet)
                    
            # UDP specific info
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                print(f" {self.colors['cyan']}UDP:{sport}→{dport}{self.colors['reset']}")
                
                # Check for DNS
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    self.process_dns(packet)
                    
            # ICMP specific info
            elif ICMP in packet:
                print(f" {self.colors['red']}ICMP Type:{packet[ICMP].type}{self.colors['reset']}")
                
        elif ARP in packet:
            print(f"{self.colors['green']}[{timestamp}] {self.colors['red']}ARP: {packet[ARP].psrc} → {packet[ARP].pdst}{self.colors['reset']}")
            
    def process_http(self, packet):
        """Process HTTP packets for interesting data"""
        try:
            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                
                # Look for interesting keywords
                interesting_keywords = [
                    'password', 'user', 'login', 'username', 'passwd',
                    'email', 'auth', 'cookie', 'session', 'token'
                ]
                
                for keyword in interesting_keywords:
                    if keyword in load:
                        print(f"{self.colors['red']}    [!] Potential {keyword.upper()} found in HTTP traffic{self.colors['reset']}")
                        if self.verbose:
                            # Show context (be careful with sensitive data)
                            lines = load.split('\n')
                            for line in lines:
                                if keyword in line:
                                    print(f"{self.colors['yellow']}        {line.strip()}{self.colors['reset']}")
                        break
                        
        except Exception as e:
            if self.verbose:
                print(f"{self.colors['red']}    [Error processing HTTP: {e}]{self.colors['reset']}")
    
    def process_dns(self, packet):
        """Process DNS packets"""
        try:
            if DNS in packet:
                if packet[DNS].qr == 0:  # DNS query
                    if packet[DNS].qd:
                        qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                        print(f"{self.colors['cyan']}    [DNS Query] {qname}{self.colors['reset']}")
                else:  # DNS response
                    if packet[DNS].an and packet[DNS].an.type == 1:  # A record
                        for i in range(packet[DNS].ancount):
                            if packet[DNS].an[i].type == 1:
                                print(f"{self.colors['green']}    [DNS Response] {packet[DNS].an[i].rdata}{self.colors['reset']}")
        except Exception as e:
            if self.verbose:
                print(f"{self.colors['red']}    [Error processing DNS: {e}]{self.colors['reset']}")
    
    def packet_handler(self, packet):
        """Main packet processing function"""
        self.packet_count += 1
        
        # Print basic packet info
        self.print_packet_info(packet)
        
        # Save to file if specified
        if self.output_file:
            self.save_packet(packet)
        
        # Check if we've reached the packet count limit
        if self.count > 0 and self.packet_count >= self.count:
            print(f"\n{self.colors['yellow']}[*] Captured {self.packet_count} packets. Stopping.{self.colors['reset']}")
            return False
            
        return True
    
    def save_packet(self, packet):
        """Save packet to file in JSON format"""
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'summary': packet.summary()
            }
            
            if IP in packet:
                packet_info.update({
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto
                })
            
            with open(self.output_file, 'a') as f:
                f.write(json.dumps(packet_info) + '\n')
                
        except Exception as e:
            if self.verbose:
                print(f"{self.colors['red']}    [Error saving packet: {e}]{self.colors['reset']}")
    
    def start_sniffing(self):
        """Start the packet sniffing process"""
        self.print_banner()
        
        print(f"{self.colors['yellow']}[*] Starting packet sniffer on interface: {self.interface}{self.colors['reset']}")
        print(f"{self.colors['yellow']}[*] Packet count: {self.count if self.count > 0 else 'Unlimited'}{self.colors['reset']}")
        if self.output_file:
            print(f"{self.colors['yellow']}[*] Output file: {self.output_file}{self.colors['reset']}")
        print(f"{self.colors['yellow']}[*] Press Ctrl+C to stop\n{self.colors['reset']}")
        
        try:
            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=0 if self.count == 0 else self.count,
                store=0
            )
            
        except KeyboardInterrupt:
            print(f"\n{self.colors['red']}[!] Sniffer stopped by user{self.colors['reset']}")
        except PermissionError:
            print(f"{self.colors['red']}[!] Need root privileges to capture packets{self.colors['reset']}")
            sys.exit(1)
        except Exception as e:
            print(f"{self.colors['red']}[!] Error: {e}{self.colors['reset']}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='516 Hackers - Basic Packet Sniffer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  {sys.argv[0]} -i eth0                          # Sniff on eth0 indefinitely
  {sys.argv[0]} -i wlan0 -c 100                  # Capture 100 packets
  {sys.argv[0]} -i eth0 -o capture.json -v       # Save to file with verbose output
  {sys.argv[0]} -i eth0 --filter "tcp port 80"   # HTTP traffic only

Ethical Notice:
  This tool is for educational purposes and authorized testing only.
  Always obtain proper authorization before use.
        '''
    )
    
    parser.add_argument('-i', '--interface', required=True, help='Network interface to sniff on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-o', '--output', help='Output file to save packet info')
    parser.add_argument('-f', '--filter', help='BPF filter string')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Create sniffer instance
    sniffer = BasicSniffer(
        interface=args.interface,
        count=args.count,
        output_file=args.output,
        verbose=args.verbose
    )
    
    # Start sniffing
    sniffer.start_sniffing()
    
    print(f"\n{sniffer.colors['green']}[+] Sniffing completed. Total packets: {sniffer.packet_count}{sniffer.colors['reset']}")

if __name__ == "__main__":
    main()
