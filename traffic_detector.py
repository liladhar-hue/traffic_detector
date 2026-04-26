from scapy.all import sniff, IP, TCP
from collections import defaultdict
import ipaddress
import socket
from datetime import datetime
import logging
import os

MY_IP = socket.gethostbyname(socket.gethostname())
NETWORK = ipaddress.ip_network(MY_IP + "/24", strict=False)

packet_count = defaultdict(int)
port_hit = defaultdict(set)
known_ips = set()

PACKET_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 15

#adding code details for basic log system 
os.makedirs("logs", exist_ok=True)
log_filename = f"logs/detector_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_filename),      # save into a file 
        logging.StreamHandler()                  # just for showing in trminal { may be gui can handle but nope}
    ]
)

def analyze(packet):
    if packet.haslayer(IP):
        src = packet[IP].src

        if ipaddress.ip_address(src) not in NETWORK:
            return

        packet_count[src] += 1

        if src not in known_ips:
            known_ips.add(src)
            logging.info(f"[New Device] {src}")

        if packet_count[src] == PACKET_THRESHOLD:
            logging.warning(f"[HIGH TRAFFIC] {src} sent {packet_count[src]} packets")

        if packet.haslayer(TCP):
            port = packet[TCP].dport
            port_hit[src].add(port)
            if len(port_hit[src]) == PORT_SCAN_THRESHOLD:
                logging.critical(f"[PORT SCAN] {src} hit {len(port_hit[src])} ports!")

logging.info(f"Monitoring network: {NETWORK}")
logging.info(f"Logs saving to: {log_filename}")
sniff(prn=analyze, store=False)
