from scapy.all import *

packets = rdpcap('example.pcap')

for packet in packets[:10]:
    for item in packet:
        print(type(item))
        print(item.summary())
