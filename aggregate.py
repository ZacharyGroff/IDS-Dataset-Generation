import json
import requests
from datetime import datetime

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
            if srcFin and dstFin:
                break
           
            if packet2['src'] != clientIP and packet2['src'] != serverIP:
                continue
            if packet2['dst'] != clientIP and packet2['dst'] != serverIP:
                continue
          
            if packet2['SYN'] and packet2['ACK']:
                seenConnection = True    
            if not seenConnection:
                continue 
            
            if packet2['FIN'] and packet2['src'] == clientIP:
                srcFin = True

            if packet2['FIN'] and packet2['src'] == serverIP:
                dstFin = True

            flow.append(packet2)

        if srcFin and dstFin:
            flows.append(flow)

    return flows

scrollId, numHits, initialHits = baseQuery()
results = getResults(scrollId, numHits, initialHits)
packets = [results[i]['_source'] for i in range(len(results))]
packetFlows = getFlows(packets)
