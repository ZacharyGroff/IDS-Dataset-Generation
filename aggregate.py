import json
import requests
from datetime import datetime
from models.flow import Flow

def baseQuery():
    query = json.dumps( 
    {
        "query": {
            "range" : {
                "time" : {
                    "gte": "18/01/01",
                    "lte": "20/01/01",
                    "format": "yy/MM/dd"
                }
            }
        },
#            "sort" : ["src", "dst", {"time": {"order" : "asc"}}]
            "sort" : [{"time": {"order" : "asc"}}]
    }
    )
    headers = {'Content-type': 'application/json'}
    url = "http://localhost:9200/trafficlogs/_search?scroll=1m"

    response = requests.get(url, data=query, headers=headers)
    data = json.loads(response.text)

    scrollId = data['_scroll_id']
    numHits = data['hits']['total'] - 10
    initialHits = data['hits']['hits']

    return scrollId, numHits, initialHits

def getResults(scrollId, numHits, initialHits):
    results = []
    while len(results) < numHits:
        params = {
            "scroll" : "1m", 
            "scroll_id": scrollId 
        }
        headers = {'Content-type': 'application/json'}
        url = "http://localhost:9200/_search/scroll"

        response = requests.post(url, params=params, headers=headers)
        hits = json.loads(response.text)['hits']['hits']
        
        results.extend(hits)
    
    return results

def validIPs(packet1, packet2):
    clientIP = packet1['src']
    serverIP = packet1['dst']    
    
    if packet2['src'] != clientIP and packet2['src'] != serverIP:
        return False
    if packet2['dst'] != clientIP and packet2['dst'] != serverIP:
        return False

    return True

def validPorts(packet1, packet2):
    clientIP = packet1['src']
    serverIP = packet1['dst']    
 
    clientPort = packet1['sport']
    serverPort = packet1['dport']

    if packet2['src'] == clientIP and packet2['sport'] != clientPort:
        return False
    if packet2['src'] == serverIP and packet2['sport'] != serverPort:
        return False

    if packet2['dst'] == clientIP and packet2['dport'] != clientPort:
        return False
    if packet2['dst'] == serverIP and packet2['dport'] != serverPort:
        return False

    return True

def isAdditionalConnection(packet1, packet2):
    clientIP = packet1['src']
    serverIP = packet1['dst']    
 
    clientPort = packet1['sport']
    serverPort = packet1['dport']

    if packet2['src'] == clientIP and packet2['dst'] == serverIP:
        if packet2['sport'] == clientPort and packet2['dport'] == serverPort:
            if packet2['SYN']:
                return True

    return False

def getRSTPackets(packets, packet1):
    clientIP = packet1['src']
    serverIP = packet1['dst']    
 
    clientPort = packet1['sport']
    serverPort = packet1['dport']

    rstPackets = []
    #check if server is sending RST packets to client
    rstSeen = False
    lastSeenRST = -1
    for packet2 in packets:
        #stop if another connection is attempted
        if isAdditionalConnection(packet1, packet2):
            break
     
        if packet2['src'] != serverIP or packet2['dst'] != clientIP:
            continue
        if packet2['sport'] != serverPort or packet2['dport'] != clientPort:
            continue
       
        if not packet2['RST'] and rstSeen:
            break
        else:
            rstPackets.append(packet2)
            rstSeen = True
            lastSeenRST = packets.index(packet2)

    #also retrieve client->server packets causing additional RSTs
    if lastSeenRST != -1:
        for packet2 in packets[:lastSeenRST]:
            if packet2['src'] == clientIP and packet2['dst'] == serverIP:
                if packet2['sport'] == clientPort and packet2['dport'] == serverPort:
                    rstPackets.append(packet2) 

    return rstPackets

def getFlows(packets):
    flows = []
    
    for packet1 in packets:
        if not packet1['SYN']:
            continue
        if packet1['ACK']:
            continue
        flow = [packet1]
 
        clientIP = packet1['src']
        serverIP = packet1['dst']    
       
        srcFin = True if packet1['FIN'] else False
        dstFin = False

        seenConnection = False
        for packet2 in packets[packets.index(packet1):]:
            #only care if server ends connection
            if srcFin and dstFin:
                flow.extend(getRSTPackets(packets[packets.index(packet1):], packet1))
                break
            
            #break if client attempts to establish new connection with same IPs/Ports
            if seenConnection and isAdditionalConnection(packet1, packet2):
                break
 
            if not validIPs(packet1, packet2):
                continue
            
            if not validPorts(packet1, packet2):
                continue

            if packet2['SYN'] and packet2['ACK']:
                seenConnection = True    
            if not seenConnection:
                continue 
            
            #if packet2 indicates a reset connection, find all additional RST packets
            if packet2['RST'] and packet2['src'] == serverIP:
                flow.extend(getRSTPackets(packets[packets.index(packet1):], packet1))
                break
            
            if packet2['FIN'] and packet2['src'] == serverIP:
                dstFin = True

            flow.append(packet2)

        flows.append(flow)

    return flows

def aggregate(flows):
    aggregatedFlows = []
    for flow in flows:
        assert(flow[0]['SYN'])
        assert(not flow[0]['ACK'])
        
        timestamp = flow[0]['time']
        clientIP = flow[0]['src']
        serverIP = flow[0]['dst']
        clientPort = flow[0]['sport']
        serverPort = flow[0]['dport']

        currentFlow = Flow(timestamp, clientIP, serverIP, clientPort, serverPort)
        for packet in flow:
            isLastPacket = True if packet == flow[-1] else False
            currentFlow.increment(packet, isLastPacket)

        aggregatedFlows.append(currentFlow)

    return aggregatedFlows

def postFlows(flows):
    headers = {'Content-type': 'application/json'}
    responses = {}
    for flow in flows:
        url = "http://localhost:9200/trafficlogs/flows/{}".format(flow.id)
        response = requests.post(url, flow.toJSON(), headers=headers).status_code
        if response not in responses:
            responses[response] = 1
        else:
            responses[response] += 1
    
    print('Reponses:')
    [print('{}: {}'.format(k,v)) for k,v in responses.items()]

scrollId, numHits, initialHits = baseQuery()
results = getResults(scrollId, numHits, initialHits)
packets = [results[i]['_source'] for i in range(len(results))]
packetFlows = getFlows(packets)
flows = aggregate(packetFlows)
postFlows(flows)
