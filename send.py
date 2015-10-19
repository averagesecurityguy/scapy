# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

server = '10.230.228.146'
server2 = '10.230.228.147'
port = 8000

eth_pkt = Ether() / IP(dst=server) / TCP(dport=port)
print('ETH_PKT\n-------')
print(eth_pkt.summary())
sendp(eth_pkt)

ip_pkt = IP(dst=server2) / TCP(dport=port)
print('IP_PKT\n------')
print(ip_pkt.summary())

send(ip_pkt)
