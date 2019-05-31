import json
from datetime import datetime

class Flow(): 
    def __init__(self, timestamp=None, clientIP=None, serverIP=None, clientPort=None, serverPort=None, duration=None, _id=None, initFwdLength=-1, initBwdLength=-1, fwdHeaderLength=0, bwdHeaderLength=0, fwdBytes=0, bwdBytes=0, fwdPackets=0, bwdPackets=0, fwdPacketMin=float("inf"), fwdPacketMax=0, bwdPacketMin=float("inf"), bwdPacketMax=0, fwdFIN=0, fwdSYN=0, fwdRST=0, fwdPSH=0, fwdACK=0, fwdURG=0, fwdECE=0, fwdCWR=0, bwdFIN=0, bwdSYN=0, bwdRST=0, bwdPSH=0, bwdACK=0, bwdURG=0, bwdECE=0, bwdCWR=0, label='BENIGN'):
        self.timestamp = timestamp
        self.clientIP = clientIP
        self.serverIP = serverIP
        self.clientPort = clientPort
        self.serverPort = serverPort
        self.duration = duration
        self.id = self.getID() if not _id else _id

        self.initFwdLength = initFwdLength
        self.initBwdLength = initBwdLength

        self.fwdHeaderLength = fwdHeaderLength
        self.bwdHeaderLength = bwdHeaderLength
        self.fwdBytes = fwdBytes
        self.bwdBytes = bwdBytes
        self.fwdPackets = fwdPackets
        self.bwdPackets = bwdPackets

        self.fwdPacketMin = fwdPacketMin
        self.fwdPacketMax = fwdPacketMax
        self.bwdPacketMin = bwdPacketMin
        self.bwdPacketMax = bwdPacketMax

        self.fwdFIN = fwdFIN
        self.fwdSYN = fwdSYN
        self.fwdRST = fwdRST
        self.fwdPSH = fwdPSH
        self.fwdACK = fwdACK
        self.fwdURG = fwdURG
        self.fwdECE = fwdECE
        self.fwdCWR = fwdCWR
        
        self.bwdFIN = bwdFIN
        self.bwdSYN = bwdSYN
        self.bwdRST = bwdRST
        self.bwdPSH = bwdPSH
        self.bwdACK = bwdACK
        self.bwdURG = bwdURG
        self.bwdECE = bwdECE
        self.bwdCWR = bwdCWR

        self.label = label

    def load(self, flowDict):
        self.timestamp = flowDict['timestamp']
        self.clientIP = flowDict['clientIP']
        self.serverIP = flowDict['serverIP']
        self.clientPort = flowDict['clientPort']
        self.serverPort = flowDict['serverPort']
        self.duration = flowDict['duration']
        self.id = flowDict['id']

        self.initFwdLength = flowDict['initFwdLength']
        self.initBwdLength = flowDict['initBwdLength']

        self.fwdHeaderLength = flowDict['fwdHeaderLength']
        self.bwdHeaderLength = flowDict['bwdHeaderLength']
        self.fwdBytes = flowDict['fwdBytes']
        self.bwdBytes = flowDict['bwdBytes']
        self.fwdPackets = flowDict['fwdPackets']
        self.bwdPackets = flowDict['bwdPackets']

        self.fwdPacketMin = flowDict['fwdPacketMin']
        self.fwdPacketMax = flowDict['fwdPacketMax']
        self.bwdPacketMin = flowDict['bwdPacketMin']
        self.bwdPacketMax = flowDict['bwdPacketMax']

        self.fwdFIN = flowDict['fwdFIN']
        self.fwdSYN = flowDict['fwdSYN']
        self.fwdRST = flowDict['fwdRST']
        self.fwdPSH = flowDict['fwdPSH']
        self.fwdACK = flowDict['fwdACK']
        self.fwdURG = flowDict['fwdURG']
        self.fwdECE = flowDict['fwdECE']
        self.fwdCWR = flowDict['fwdCWR']
        
        self.bwdFIN = flowDict['bwdFIN']
        self.bwdSYN = flowDict['bwdSYN']
        self.bwdRST = flowDict['bwdRST']
        self.bwdPSH = flowDict['bwdPSH']
        self.bwdACK = flowDict['bwdACK']
        self.bwdURG = flowDict['bwdURG']
        self.bwdECE = flowDict['bwdECE']
        self.bwdCWR = flowDict['bwdCWR']

        self.label = flowDict['label']


    def getID(self):
        try:
            client = ':'.join([self.clientIP, str(self.clientPort)])
            server = ':'.join([self.serverIP, str(self.serverPort)])
            return '@'.join(['->'.join([client, server]), str(self.timestamp)])
        except(TypeError):
            return None

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
            #logging.debug('Differing non-benign labels discovered in packet {}'.format(packet.__dict__))
            pass

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

    def toCSV(self):
        values = [str(value) for attr, value in self.__dict__.items()]
        return ','.join(values)

    def toHeader(self):
        values = [attr for attr, value in self.__dict__.items()]
        return ','.join(values)

    def toJSON(self):
        return json.dumps(self, default=lambda x: x.__dict__)
