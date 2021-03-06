from scapy.all import *
from scapy_http.http import HTTPRequest
import json
import sys
import time as _time
from datetime import datetime
import requests
from models.packet import Packet
from queue import Queue
import threading

def send(packet):
    headers = {'Content-type': 'application/json'}
    url = "http://localhost:9200/trafficlogs/packets/{}".format(packet.id)
    response = requests.post(url, packet.toJSON(), headers=headers).status_code
    if response not in responses:
        responses[response] = 1
    else:
        responses[response] += 1

def worker():
    while True:
        packet = q.get()
        send(packet)
        q.task_done()

def readPcap(path):
    startTime = _time.time()
    
    packets = rdpcap(path)
    packetList = []
    print('Read {} packets from pcap'.format(len(packets)))
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

                #if src == '192.168.0.109' and dst == '192.168.0.118' and length > 50:
                #    if 'A' in flags and 'P' in flags:
                #        if len(packet[TCP].payload) > 50:
                #            label = 'SlowLoris'

                if packet.haslayer(HTTPRequest): 
                    headers = packet.getlayer(HTTPRequest).Headers.decode('utf-8')
                    if headers.find('Mozilla/25.0') != -1:
                        label = 'Hulk'
                    elif headers.find('Mozilla/24.0') != -1:
                        label = 'GoldenEye'
                    elif headers.find('Mozilla/23.0') != -1:
                        label = 'SlowLoris'

                packetList.append(Packet(sport, dport, src, dst, length, headerLength, flags, time, label))
            
            elif packet.haslayer(UDP):
                pass
        #arp or weird local android udp packet (HOPOPT)
        else:
            pass
            #if packet.haslayer(UDP):
            #    packet.show()
            #    print()
    return packetList

def sendPcap(packetList):
    global q
    global responses

    q = Queue()
    responses = {}

    for i in range(200):
        t = threading.Thread(target=work)
        t.daemon = True
        t.start()

    for packet in packetList:
        q.put(packet)
 
    q.join()

    print('Reponses:')
    [print('{}: {}'.format(k,v)) for k,v in responses.items()]
    
    print('Finished reading pcap in {} seconds.'.format(int(_time.time() - startTime)))

def writePcapJSON(packetList):
    with open(sys.argv[2], 'w') as f:
        for packet in packetList:
            f.write(packet.toJSON())
            f.write('\n')
    print('Wrote {} packets to {}.'.format(len(packetList), sys.argv[2]))


def writePcapCSV(packetList):
    with open(sys.argv[2], 'w') as f:
        f.write(packetList[0].toHeader())
        f.write('\n')
        for packet in packetList:
            f.write(packet.toCSV())
            f.write('\n')
    print('Wrote {} packets to {}.'.format(len(packetList), sys.argv[2]))

if __name__ == '__main__':
    packetList = readPcap(sys.argv[1])
    #sendPcap(packetList)
    writePcapJSON(packetList)
