# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

# The server should not be the local machine.
server = '10.230.228.104'
ports = (8000, 8002)
timeout = 5

pkt = IP(dst=server) / TCP(dport=ports, flags='S')
ans, unans = sr(pkt, timeout=timeout)

print('ANSWERED\n--------')
print(ans.summary())
print('')
print('UNANSWERED\n----------')
print(unans.summary())
