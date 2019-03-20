import json
import requests

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

scrollId, numHits, initialHits = baseQuery()
results = getResults(scrollId, numHits, initialHits)
print(len(results))
