# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

server = 'google.com'
port = 80
timeout = 5


def handshake(dst, port):
    ip = Ether()/IP(dst=dst)
    tcp = TCP(dport=port, flags='S')
    print 'SYN\n---'
    print (ip/tcp).summary()
    sa = srp1(ip/tcp, timeout=timeout)

    print '\nSYN_ACK\n-------'
    print sa.summary()

    print '\nACK\n---'
    tcp = TCP(sport=sa[TCP].dport, dport=sa[TCP].sport, flags="A", seq=sa[TCP].ack, ack=sa[TCP].seq+1)
    print (ip/tcp).summary()
    sock = srp1(ip/tcp, timeout=timeout)

    print '\nSOCK\n----'
    print sock.summary()


print('Send packet...')
handshake(server, port)
