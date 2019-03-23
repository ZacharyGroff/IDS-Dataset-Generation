import json
from datetime import datetime

class Flow(): 
    def __init__(self, timestamp, clientIP, serverIP, clientPort, serverPort):
        self.timestamp = timestamp
        self.clientIP = clientIP
        self.serverIP = serverIP
        self.clientPort = clientPort
        self.serverPort = serverPort
        self.duration = None
        self.id = self.getID()

        self.initFwdLength = -1
        self.initBwdLength = -1

        self.fwdHeaderLength = 0
        self.bwdHeaderLength = 0
        self.fwdBytes = 0
        self.bwdBytes = 0
        self.fwdPackets = 0
        self.bwdPackets = 0

        self.fwdPacketMin = float("inf")
        self.fwdPacketMax = 0
        self.bwdPacketMin = float("inf")
        self.bwdPacketMax = 0

        self.fwdFIN = 0
        self.fwdSYN = 0
        self.fwdRST = 0
        self.fwdPSH = 0
        self.fwdACK = 0
        self.fwdURG = 0
        self.fwdECE = 0
        self.fwdCWR = 0
        
        self.bwdFIN = 0
        self.bwdSYN = 0
        self.bwdRST = 0
        self.bwdPSH = 0
        self.bwdACK = 0
        self.bwdURG = 0
        self.bwdECE = 0
        self.bwdCWR = 0

        self.label = 'BENIGN'

    def getID(self):
        client = ':'.join([self.clientIP, str(self.clientPort)])
        server = ':'.join([self.serverIP, str(self.serverPort)])
        return '@'.join(['->'.join([client, server]), str(self.timestamp)])

    def increment(self, packet, isLastPacket=False):
        if isLastPacket:
            start = datetime.strptime(self.timestamp, '%Y-%m-%d %H:%M:%S.%f')
            end = datetime.strptime(packet['time'], '%Y-%m-%d %H:%M:%S.%f')
            self.duration = (end - start).total_seconds()
        
        if self.isClient(packet['src']):
            self.incrementClient(packet)

        if self.isServer(packet['src']):
            self.incrementServer(packet)

    def updateLabel(self, packet):
        if self.label == 'BENIGN' and packet['label'] != 'BENIGN':
            self.label = packet['label']
        
        #ensure no flow has packets with differing non-benign labels
        if self.label != 'BENIGN' and self.label != packet['label']:
            assert(packet['label'] == 'BENIGN')

    def incrementClient(self, packet):
        if not self.seenClientPacket():
            self.initFwdLength = packet['length']
       
        self.updateLabel(packet)
        
        self.fwdPackets += 1
        self.fwdHeaderLength += packet['headerLength']
        self.fwdBytes += packet['length']
        
        self.fwdFIN += 1 if packet['FIN'] else 0
        self.fwdSYN += 1 if packet['SYN'] else 0
        self.fwdRST += 1 if packet['RST'] else 0
        self.fwdPSH += 1 if packet['PSH'] else 0
        self.fwdACK += 1 if packet['ACK'] else 0
        self.fwdURG += 1 if packet['URG'] else 0
        self.fwdECE += 1 if packet['ECE'] else 0
        self.fwdCWR += 1 if packet['CWR'] else 0

        if self.fwdPacketMin > packet['length']:
            self.fwdPacketMin = packet['length']

        if self.fwdPacketMax < packet['length']:
            self.fwdPacketMax = packet['length']

    def incrementServer(self, packet):
        if not self.seenServerPacket():
            self.initBwdLength = packet['length']
       
        self.updateLabel(packet)

        self.bwdPackets += 1
        self.bwdHeaderLength += packet['headerLength']
        self.bwdBytes += packet['length']
        
        self.bwdFIN += 1 if packet['FIN'] else 0
        self.bwdSYN += 1 if packet['SYN'] else 0
        self.bwdRST += 1 if packet['RST'] else 0
        self.bwdPSH += 1 if packet['PSH'] else 0
        self.bwdACK += 1 if packet['ACK'] else 0
        self.bwdURG += 1 if packet['URG'] else 0
        self.bwdECE += 1 if packet['ECE'] else 0
        self.bwdCWR += 1 if packet['CWR'] else 0

        if self.bwdPacketMin > packet['length']:
            self.bwdPacketMin = packet['length']

        if self.bwdPacketMax < packet['length']:
            self.bwdPacketMax = packet['length']

    def isClient(self, srcIP):
        return self.clientIP == srcIP
    
    def isServer(self, srcIP):
        return self.serverIP == srcIP

    def seenClientPacket(self):
        return self.fwdPackets > 0

    def seenServerPacket(self):
        return self.bwdPackets > 0

    def toJSON(self):
        return json.dumps(self, default=lambda x: x.__dict__)
