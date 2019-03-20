from scapy.all import *
import json
import time as t
from datetime import datetime
import requests

class Packet():
    def __init__(self, sport, dport, src, dst, length, flags, timestamp):
        self.id = ':'.join(['->'.join([src, dst]), str(timestamp)])
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.length = length
        self.time = self.fmtTime(timestamp)
        self.FIN, self.SYN, self.RST, self.PSH, self.ACK, self.URG, self.ECE, self.CWR = self.mapFlags(flags)

    def mapFlags(self, flags):
        flagDict = {'F': False,
                    'S': False,
                    'R': False,
                    'P': False,
                    'A': False,
                    'U': False,
                    'E': False,
                    'C': False}
       
        for flag in flags:
            flagDict[flag] = True
        
        return flagDict.values()

    def fmtTime(self, timestamp):
        localTime = datetime.fromtimestamp(timestamp)
        
        return str(localTime)

    def toJSON(self):
        return json.dumps(self, default=lambda x: x.__dict__)

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
                length = layer.len
                flags = list(packet.getlayer(TCP).flags)
                time = packet.time
                plist.append(Packet(sport, dport, src, dst, length, flags, time))
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
