# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
from scapy.all import *

filter = "udp port 53"


def process_dns(packet):
    dns = packet[DNS]
    if dns.qr == 0:
        query = dns[DNSQR]
        qtype = dnsqtypes.get(query.qtype)
        print('Request: {0} ({1})'.format(query.qname, qtype))

    if dns.qr == 1:
        if dns.an is not None:
            rcount = dns.ancount
        if dns.ns is not None:
            rcount = dns.nscount
        if dns.ar is not None:
            rcount += dns.arcount

        i = 1
        while i < rcount:
            ans = packet[0][i+4]
            print('Response{0}: {1} ({2})'.format(i, ans.rrname, ans.rdata))
            i += 1

sniff(filter=filter, prn=process_dns)
