# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

# Build our packet layer by layer
server = 'google.com'

packet = Ether(src='00:00:00:11:11:11')
print('Ethernet: {0}\n'.format(repr(packet)))

ip = packet/IP(dst=server)
print('IP: {0}\n'.format(repr(ip)))

tcp = ip/TCP(dport=80)
print('TCP: {0}\n'.format(repr(tcp)))

http = tcp/"GET /index.html HTTP/1.0\r\n\r\n"
print('HTTP-1: {0}'.format(repr(http)))

# Build the packet in one step
http = Ether()/IP(dst=server)/TCP(dport=80)/"GET /index.html HTTP/1.0\r\n\r\n"
print('HTTP-2: {0}'.format(repr(http)))
