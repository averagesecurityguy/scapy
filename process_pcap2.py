# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

packets = rdpcap('data/dns.cap')

for packet in packets:
    src = packet[IP].src
    dst = packet[IP].dst

    if UDP in packet:
        udp = packet[UDP]
        print('UDP: {0}:{1} -> {2}:{3}'.format(src, udp.sport, dst, udp.dport))

    if TCP in packet:
        tcp = packet[TCP]
        print('TCP: {0}:{1} -> {2}:{3}'.format(src, tcp.sport, dst, tcp.dport))
