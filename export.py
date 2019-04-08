import sys
import json
from aggregate import getPackets

packets = getPackets()

with open(sys.argv[1], 'w') as f:
    for packet in packets:
        f.write(json.dumps(packet))
