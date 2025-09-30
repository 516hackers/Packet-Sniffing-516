#!/usr/bin/env python3
"""
516 Hackers - HTTP Traffic Analyzer
Specialized tool for analyzing HTTP traffic and extracting useful information
"""

import argparse
import re
from datetime import datetime
from scapy.all import *
from scapy.layers import http
import json
import hashlib

class HTTPTrafficAnalyzer:
    def __init__(self, interface=None, pcap_file=None, output_file=None):
        self.interface = interface
        self.pcap_file = pcap_file
        self.output_file = output_file
        self.sessions = {}
        self.credentials_found = []
        self.cookies_found = []
        self.files_detected = []
        
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
        
    def print_banner(self):
        banner = f"""
{self.colors['cyan']}
╔══════════════════════════════════════════════════════════════╗
║              516 HACKERS - HTTP TRAFFIC ANALYZER            ║
║               Educational Use Only                          ║
╚══════════════════════════════════════════════════════════════╗
        {self.colors['reset']}
"""
        print(banner)
    
    def extract_credentials(self, http_layer):
        """Extract potential credentials from HTTP traffic"""
        credentials = []
        
        if hasattr(http_layer, 'Authorization'):
            auth_header = http_layer.Authorization
            if auth_header:
                credentials.append({
                    'type': 'HTTP_Auth',
                    'value': auth_header.decode('utf-8', errors='ignore'),
                    'source': 'Authorization_Header'
                })
        
        return credentials
    
    def extract_cookies(self, http_layer):
        """Extract cookies from HTTP headers"""
        cookies = []
        
        if hasattr(http_layer, 'Cookie'):
            cookie_header = http_layer.Cookie
            if cookie_header:
                cookies.append({
                    'header': 'Cookie',
                    'value': cookie_header.decode('utf-8', errors='ignore')
                })
        
        if hasattr(http_layer, 'Set-Cookie'):
            set_cookie_header = http_layer['Set-Cookie']
            if set_cookie_header:
                cookies.append({
                    'header': 'Set-Cookie',
                    'value': set_cookie_header.decode('utf-8', errors='ignore')
                })
        
        return cookies
    
    def extract_post_data(self, payload):
        """Extract POST data and look for credentials"""
        findings = []
        
        try:
            post_data = payload.decode('utf-8', errors='ignore')
            
            # Look for common credential patterns
            credential_patterns = {
                'username': r'(?i)(username|user|email|login)=([^&]+)',
                'password': r'(?i)(password|pass|pwd)=([^&]+)',
                'session': r'(?i)(session|sessid|token)=([^&]+)'
            }
            
            for field_type, pattern in credential_patterns.items():
                matches = re.findall(pattern, post_data)
                for match in matches:
                    findings.append({
                        'type': field_type.upper(),
                        'field': match[0],
                        'value': match[1],
                        'source': 'POST_Data'
                    })
            
            # Look for file uploads
            if 'filename=' in post_data and 'Content-Type' in post_data:
                file_match = re.search(r'filename="([^"]+)"', post_data)
                if file_match:
                    findings.append({
                        'type': 'FILE_UPLOAD',
                        'filename': file_match.group(1),
                        'source': 'POST_Data'
                    })
                    
        except Exception as e:
            pass
            
        return findings
    
    def analyze_http_request(self, packet):
        """Analyze HTTP request packets"""
        findings = []
        
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet[http.HTTPRequest]
            
            # Extract basic request info
            host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else "Unknown"
            path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else "/"
            method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else "GET"
            
            print(f"{self.colors['blue']}[HTTP Request] {method} http://{host}{path}{self.colors['reset']}")
            
            # Extract credentials from headers
            credentials = self.extract_credentials(http_layer)
            if credentials:
                findings.extend(credentials)
                for cred in credentials:
                    print(f"{self.colors['red']}    [!] Authentication: {cred['value'][:50]}...{self.colors['reset']}")
            
            # Extract cookies
            cookies = self.extract_cookies(http_layer)
            if cookies:
                findings.extend([{'type': 'COOKIE', **cookie} for cookie in cookies])
                for cookie in cookies:
                    print(f"{self.colors['yellow']}    [Cookie] {cookie['header']}: {cookie['value'][:50]}...{self.colors['reset']}")
            
            # Analyze POST data
            if packet.haslayer(Raw) and method == "POST":
                post_findings = self.extract_post_data(packet[Raw].load)
                if post_findings:
                    findings.extend(post_findings)
                    for finding in post_findings:
                        if finding['type'] in ['USERNAME', 'PASSWORD']:
                            print(f"{self.colors['red']}    [!] {finding['type']}: {finding['field']}={finding['value']}{self.colors['reset']}")
                        elif finding['type'] == 'FILE_UPLOAD':
                            print(f"{self.colors['magenta']}    [File Upload] {finding['filename']}{self.colors['reset']}")
        
        return findings
    
    def analyze_http_response(self, packet):
        """Analyze HTTP response packets"""
        findings = []
        
        if packet.haslayer(http.HTTPResponse):
            http_layer = packet[http.HTTPResponse]
            
            print(f"{self.colors['green']}[HTTP Response] Status Code: {http_layer.Status_Code}{self.colors['reset']}")
            
            # Extract cookies from response
            cookies = self.extract_cookies(http_layer)
            if cookies:
                findings.extend([{'type': 'COOKIE', **cookie} for cookie in cookies])
                for cookie in cookies:
                    print(f"{self.colors['yellow']}    [Set-Cookie] {cookie['value'][:50]}...{self.colors['reset']}")
            
            # Check for interesting response data
            if packet.haslayer(Raw):
                try:
                    response_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Look for error messages
                    if 'error' in response_data.lower():
                        error_match = re.search(r'(?i)error[^<]{0,100}', response_data)
                        if error_match:
                            print(f"{self.colors['red']}    [Error] {error_match.group(0)[:100]}...{self.colors['reset']}")
                    
                    # Look for sensitive information patterns
                    sensitive_patterns = [
                        r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b',  # SSN
                        r'\b\d{16}\b',  # Credit card
                        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email
                    ]
                    
                    for pattern in sensitive_patterns:
                        matches = re.findall(pattern, response_data)
                        for match in matches:
                            print(f"{self.colors['red']}    [!] Sensitive data found: {match}{self.colors['reset']}")
                            
                except Exception:
                    pass
        
        return findings
    
    def process_packet(self, packet):
        """Main packet processing function"""
        findings = []
        
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
            
            # Analyze HTTP requests
            if packet.haslayer(http.HTTPRequest):
                findings.extend(self.analyze_http_request(packet))
            
            # Analyze HTTP responses
            elif packet.haslayer(http.HTTPResponse):
                findings.extend(self.analyze_http_response(packet))
            
            # Save findings
            if findings:
                session_key = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
                if session_key not in self.sessions:
                    self.sessions[session_key] = []
                self.sessions[session_key].extend(findings)
    
    def generate_report(self):
        """Generate a comprehensive report"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_sessions': len(self.sessions),
            'credentials_found': [],
            'cookies_found': [],
            'sessions': self.sessions
        }
        
        # Extract all credentials
        for session, findings in self.sessions.items():
            for finding in findings:
                if finding['type'] in ['USERNAME', 'PASSWORD', 'HTTP_Auth']:
                    report['credentials_found'].append(finding)
                elif finding['type'] == 'COOKIE':
                    report['cookies_found'].append(finding)
        
        return report
    
    def start_live_analysis(self):
        """Start live HTTP traffic analysis"""
        self.print_banner()
        print(f"{self.colors['yellow']}[*] Starting live HTTP traffic analysis on {self.interface}{self.colors['reset']}")
        print(f"{self.colors['yellow']}[*] Press Ctrl+C to stop analysis\n{self.colors['reset']}")
        
        try:
            # Filter for HTTP traffic only
            sniff(iface=self.interface, prn=self.process_packet, filter="tcp port 80", store=0)
        except KeyboardInterrupt:
            print(f"\n{self.colors['red']}[!] Analysis stopped by user{self.colors['reset']}")
        except Exception as e:
            print(f"{self.colors['red']}[!] Error: {e}{self.colors['reset']}")
    
    def analyze_pcap(self):
        """Analyze HTTP traffic from PCAP file"""
        self.print_banner()
        print(f"{self.colors['yellow']}[*] Analyzing HTTP traffic from {self.pcap_file}{self.colors['reset']}")
        
        try:
            packets = rdpcap(self.pcap_file)
            for packet in packets:
                self.process_packet(packet)
        except Exception as e:
            print(f"{self.colors['red']}[!] Error reading PCAP file: {e}{self.colors['reset']}")
    
    def save_results(self):
        """Save analysis results to file"""
        if self.output_file:
            report = self.generate_report()
            with open(self.output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"{self.colors['green']}[+] Results saved to {self.output_file}{self.colors['reset']}")
    
    def print_summary(self):
        """Print analysis summary"""
        print(f"\n{self.colors['cyan']}=== ANALYSIS SUMMARY ==={self.colors['reset']}")
        print(f"{self.colors['yellow']}Total HTTP sessions analyzed: {len(self.sessions)}{self.colors['reset']}")
        
        credential_count = sum(1 for session in self.sessions.values() 
                             for finding in session if finding['type'] in ['USERNAME', 'PASSWORD', 'HTTP_Auth'])
        cookie_count = sum(1 for session in self.sessions.values() 
                          for finding in session if finding['type'] == 'COOKIE')
        
        print(f"{self.colors['red']}Credentials found: {credential_count}{self.colors['reset']}")
        print(f"{self.colors['yellow']}Cookies extracted: {cookie_count}{self.colors['reset']}")

def main():
    parser = argparse.ArgumentParser(
        description='516 Hackers - HTTP Traffic Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interface', help='Network interface for live analysis')
    group.add_argument('-p', '--pcap', help='PCAP file to analyze')
    
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    analyzer = HTTPTrafficAnalyzer(
        interface=args.interface,
        pcap_file=args.pcap,
        output_file=args.output
    )
    
    if args.interface:
        analyzer.start_live_analysis()
    elif args.pcap:
        analyzer.analyze_pcap()
    
    analyzer.print_summary()
    
    if args.output:
        analyzer.save_results()

if __name__ == "__main__":
    main()
