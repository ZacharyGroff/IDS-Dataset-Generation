from datetime import datetime
import json

class Packet():
    def __init__(self, sport, dport, src, dst, length, headerLength, flags, timestamp, label):
        self.id = ':'.join(['->'.join([src, dst]), str(timestamp)])
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.length = length
        self.headerLength = headerLength
        self.time = self.fmtTime(timestamp)
        self.FIN, self.SYN, self.RST, self.PSH, self.ACK, self.URG, self.ECE, self.CWR = self.mapFlags(flags)
        self.label = label

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

    def isClient(self, clientIP):
        return self.src == clientIP

    def isServer(self, serverIP):
        return self.src == serverIP 

