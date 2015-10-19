# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

old_server = '10.230.228.146'
new_server = '10.230.228.104'
old_port = 8000
new_port = 8888
timeout = 5
filter = 'tcp'


def rewrite(pkt):
    if pkt[IP].dst == old_server and pkt[TCP].dport == old_port:
        # Modify the packet
        print('ORIG: {0}'.format(pkt.summary()))
        pkt[IP].src = new_server
        pkt[TCP].dport = new_port
        print('NEW: {0}'.format(pkt.summary()))
        print()

        # Send the modified packet
        sendp(pkt)

sniff(filter=filter, prn=rewrite)
