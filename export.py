import sys
import json
from aggregate import getPackets

packets = getPackets()
print('Writing {} packets to: {}'.format(len(packets), sys.argv[1]))
with open(sys.argv[1], 'w') as f:
    for packet in packets:
        json.dump(packet, f)
        f.write('\n')
