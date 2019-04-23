import sys
import json
import requests
from models.flow import Flow

def baseQuery():
    query = json.dumps( 
    {
        "size": 100,
    }
    )
    headers = {'Content-type': 'application/json'}
    url = "http://localhost:9200/trafficflows/_search?scroll=1m"

    response = requests.get(url, data=query, headers=headers)
    data = json.loads(response.text)
    
    scrollId = data['_scroll_id']
    numHits = data['hits']['total'] - 100
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

def jsonToFlows(flowsJson):
    flowsJson = [i['_source'] for i in flowsJson]
    flows = []
    for flowJson in flowsJson:
        flow = Flow()
        flow.load(flowJson)
        flows.append(flow)

    return flows

def writeCSV(flows):
    with open(sys.argv[1], 'w') as f:
        f.write(flows[0].toHeader())
        f.write('\n')
        for flow in flows:
            f.write(flow.toCSV())
            f.write('\n')

if __name__ == '__main__':
    scrollId, numHits, initialHits = baseQuery()
    flowsJson = getResults(scrollId, numHits, initialHits)
    flows = jsonToFlows(flowsJson)
    writeCSV(flows)
