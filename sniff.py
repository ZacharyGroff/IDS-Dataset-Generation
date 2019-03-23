from scapy.all import *
from scapy_http.http import HTTPRequest
import json
import time as t
from datetime import datetime
import requests
from models.packet import Packet

def readPcap(path):
    startTime = t.time()
    
    packets = rdpcap(path)
    plist = []
    for packet in packets:
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                layer = packet.getlayer(IP)
                sport = layer.sport
                dport = layer.dport
                src = layer.src
                dst = layer.dst
                headerLength = layer.ihl * 4
                length = layer.len
                flags = list(packet.getlayer(TCP).flags)
                time = packet.time
                label = 'BENIGN'
                
                if packet.haslayer(HTTPRequest): 
                    headers = packet.getlayer(HTTPRequest).Headers.decode('utf-8')
                    if headers.find('Mozzila/5.0'):
                        label = 'Hulk'
                    elif headers.find('Mozzila/4.0'):
                        label = 'GoldenEye'
                    elif headers.find('Mozilla/3.0'):
                        label = 'SlowLoris'

                plist.append(Packet(sport, dport, src, dst, length, headerLength, flags, time, label))
            
            elif packet.haslayer(UDP):
                pass
        #arp or weird local android udp packet (HOPOPT)
        else:
            pass
            #if packet.haslayer(UDP):
            #    packet.show()
            #    print()

    headers = {'Content-type': 'application/json'}
    responses = {}
    for packet in plist:
        url = "http://localhost:9200/trafficlogs/packets/{}".format(packet.id)
        response = requests.post(url, packet.toJSON(), headers=headers).status_code
        if response not in responses:
            responses[response] = 1
        else:
            responses[response] += 1

    print('Reponses:')
    [print('{}: {}'.format(k,v)) for k,v in responses.items()]
    
    print('Finished reading pcap in {} seconds.'.format(int(t.time() - startTime)))

if __name__ == '__main__':
    readPcap('example.pcap')
