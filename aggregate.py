import sys
import os
import json
import requests
import logging
import multiprocessing
import math
from datetime import datetime
from models.flow import Flow

def baseQuery():
    query = json.dumps( 
    {
        "size": 10000,
        "query": {
            "range" : {
                "time" : {
                    "gte": "18/01/01",
                    "lte": "20/01/01",
                    "format": "yy/MM/dd"
                }
            }
        },
            "sort" : [{"time": {"order" : "asc"}}]
    }
    )
    headers = {'Content-type': 'application/json'}
    url = "http://localhost:9200/trafficlogs/_search?scroll=1m"

    response = requests.get(url, data=query, headers=headers)
    data = json.loads(response.text)
    
    scrollId = data['_scroll_id']
    numHits = data['hits']['total'] - 10000
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
        print('Results Gathered: {}'.format(len(results))) 

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

def isTimeout(time1, time2):
    if not time1:
        return False
    if (time2-time1).total_seconds() > 600:
        return True
    return False 

def flowWorker(data):
    start, end, packets = data
    flows = []
    for packet1 in packets[start:end]:
        if not packet1['SYN']:
            continue
        if packet1['ACK']:
            continue
        
        flow = [packet1]
 
        clientIP = packet1['src']
        serverIP = packet1['dst']    
       
        seenConnection = False

        lastPacketTime = None
        packet1Index = packets.index(packet1)
        for packet2 in packets[packet1Index+1:]:
            #break if client attempts to establish new connection with same IPs/Ports
            if seenConnection and isAdditionalConnection(packet1, packet2):
                break
 
            try:
                packetTime = datetime.strptime(packet2['time'], '%Y-%m-%d %H:%M:%S.%f')
            except(ValueError):
                packetTime = datetime.strptime(packet2['time'], '%Y-%m-%d %H:%M:%S')
 
            if isTimeout(lastPacketTime, packetTime):
                break

            if not validIPs(packet1, packet2):
                continue
            
            if not validPorts(packet1, packet2):
                continue

            if packet2['SYN'] and packet2['ACK']:
                seenConnection = True
            
            lastPacketTime = packetTime 

            flow.append(packet2)

        flows.append(flow)
        if len(flows) % 100 == 0:
            print('Process: {}\tFlows Gathered: {}'.format(os.getpid(), len(flows)))

    return flows

def flowBuilder(packets, threads):
    p = multiprocessing.Pool(threads)
    target = []
 
    _range = math.ceil(len(packets) / threads)
    for i in range(threads):
        start = _range * i
        end = start + _range
        if end > len(packets):
            end = len(packets)
        target.append((start, end, packets)) 
    
    flowLists = p.map(flowWorker, target)
    
    flows = []
    for flowList in flowLists:
        for flow in flowList:
            flows.append(flow)

    return flows

def aggregateWorker(flow):
    timestamp = flow[0]['time']
    clientIP = flow[0]['src']
    serverIP = flow[0]['dst']
    clientPort = flow[0]['sport']
    serverPort = flow[0]['dport']

    currentFlow = Flow(timestamp, clientIP, serverIP, clientPort, serverPort)
    for packet in flow:
        isLastPacket = True if packet == flow[-1] else False
        currentFlow.increment(packet, isLastPacket)

    return currentFlow

def aggregateBuilder(flows):
    p = multiprocessing.Pool()
    aggregatedFlows = p.map(aggregateWorker, flows)

    return aggregatedFlows

def postFlows():
    headers = {'Content-type': 'application/json'}
    responses = {}
    for flow in aggregatedFlows:
        url = "http://localhost:9200/trafficflows/flows/{}".format(flow.id)
        response = requests.post(url, flow.toJSON(), headers=headers).status_code
        if response not in responses:
            responses[response] = 1
        else:
            responses[response] += 1
    
    print('Reponses:')
    [print('{}: {}'.format(k,v)) for k,v in responses.items()]

def writeFlowsJSON(dataFile, aggregatedFlows):
    with open(dataFile, 'w') as f:
        for flow in aggregatedFlows:
            f.write(flow.toJSON())
            f.write('\n')

def writeFlowsCSV(dataFile, aggregatedFlows):
    with open(dataFile, 'w') as f:
        f.write(aggregatedFlows[0].toHeader())
        f.write('\n')
        for flow in aggregatedFlows:
            f.write(flow.toCSV())
            f.write('\n')

def getPackets():
    scrollId, numHits, initialHits = baseQuery()
    print('Gathering Packets...')
    results = getResults(scrollId, numHits, initialHits)
    print('Transforming results...')

    return [results[i]['_source'] for i in range(len(results))]

def importPacketsJSON(dataFile):
    data = []
    with open(dataFile, 'r') as f:
        for packet in f.readlines():
            data.append(json.loads(packet))
    
    return data

if __name__ == '__main__':
    threads = 4

    logging.basicConfig(filename='aggregate.log', level=logging.DEBUG)
    #packets = getPackets()
    packets = importPacketsJSON(sys.argv[1])
    print('Gathering Flows...')
    flows = flowBuilder(packets, threads)
    print('Aggregating Flows...')
    aggregatedFlows = aggregateBuilder(flows)
    #postFlows()
    writeFlowsCSV(sys.argv[2], aggregatedFlows)
