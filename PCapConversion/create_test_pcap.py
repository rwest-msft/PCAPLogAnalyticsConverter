#!/usr/bin/env python3
"""
Script to create a test PCAP file for testing the Azure Function
"""

import os
from scapy.all import *
from datetime import datetime

def create_test_pcap():
    """Create a simple test PCAP file with some sample network traffic"""
    
    # Create a list to store packets
    packets = []
    
    # Create a few test packets
    # HTTP request packet
    http_request = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
                   IP(src="192.168.1.10", dst="192.168.1.1") / \
                   TCP(sport=12345, dport=80) / \
                   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packets.append(http_request)
    
    # HTTP response packet
    http_response = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
                    IP(src="192.168.1.1", dst="192.168.1.10") / \
                    TCP(sport=80, dport=12345) / \
                    "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"
    packets.append(http_response)
    
    # DNS query packet
    dns_query = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
                IP(src="192.168.1.10", dst="8.8.8.8") / \
                UDP(sport=54321, dport=53) / \
                DNS(rd=1, qd=DNSQR(qname="example.com"))
    packets.append(dns_query)
    
    # DNS response packet
    dns_response = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
                   IP(src="8.8.8.8", dst="192.168.1.10") / \
                   UDP(sport=53, dport=54321) / \
                   DNS(id=dns_query[DNS].id, qr=1, aa=0, rcode=0,
                       qd=DNSQR(qname="example.com"),
                       an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    packets.append(dns_response)
    
    # ICMP ping packet
    icmp_ping = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff") / \
                IP(src="192.168.1.10", dst="8.8.8.8") / \
                ICMP()
    packets.append(icmp_ping)
    
    # ICMP pong packet
    icmp_pong = Ether(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") / \
                IP(src="8.8.8.8", dst="192.168.1.10") / \
                ICMP(type=0)
    packets.append(icmp_pong)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"test_traffic_{timestamp}.pcap"
    
    # Write packets to PCAP file
    wrpcap(filename, packets)
    
    print(f"Test PCAP file created: {filename}")
    print(f"Number of packets: {len(packets)}")
    print(f"File size: {os.path.getsize(filename)} bytes")
    
    return filename

if __name__ == "__main__":
    try:
        filename = create_test_pcap()
        print(f"\nYou can now upload '{filename}' to test the Azure Function!")
    except ImportError:
        print("Error: scapy library not found. Please install it with: pip install scapy")
    except Exception as e:
        print(f"Error creating test PCAP file: {e}")
