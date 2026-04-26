from scapy.all import sniff, IP, TCP
from collections import defaultdict
import ipaddress
import socket

MY_IP = socket.gethostbyname(socket.gethostname())
NETWORK = ipaddress.ip_network(MY_IP + "/24", strict=False)
packet_count = defaultdict(int)
port_hit = defaultdict(set)
known_ips = set()

PACKET_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 15

def analyze(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
         
        if ipaddress.ip_address(src) not in NETWORK:
           return
        packet_count[src] += 1

        if src not in known_ips:
            known_ips.add(src)
            print(f"[New Devive] {src}")

        if packet_count[src] == PACKET_THRESHOLD:
            print(f"[ALERT] {src} high traffic ({packet_count}[src] packets)")

        if packet.haslayer(TCP):
            port = packet[TCP].dport
            ports_hit[src].add(port)

            if len(port_hit[src]) == PORT_THRESHOLD:
                print(f"[ALERT] {src} possibke port scan...")

sniff(prn=analyze, store=False)
