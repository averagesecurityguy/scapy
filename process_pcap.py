# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Begin our Scapy script.
import scapy.all

packets = scapy.all.rdpcap('data/dns.cap')

for packet in packets:
    print('----------')
    print('src_mac: {0}'.format(packet.src))
    print('dst_mac: {0}'.format(packet.dst))

    ip = packet.payload
    print('src_ip: {0}'.format(ip.src))
    print('dst_ip: {0}'.format(ip.dst))

    if ip.proto == 17:
        udp = ip.payload
        print('udp_sport: {0}'.format(udp.sport))
        print('udp_dport: {0}'.format(udp.dport))

    if ip.proto == 6:
        tcp = ip.payload
        print('tcp_sport: {0}'.format(tcp.sport))
        print('tcp_dport: {0}'.format(tcp.dport))

    print('----------\n')
