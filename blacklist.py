
############################################################################
# Simple blacklist to detector conversion
############################################################################

import requests
import uuid

class Blacklist:

    def __init__(self):
        self.bl = []

    def read_from_file(self, file):

        with open(file) as f:
            for line in f:
                line = line.strip()
                if len(line) == 0: continue
                if line[0] == '#': continue
                self.bl.append(line)

    def read_from_url(self, url):

        resp = requests.get(url)

        if resp.status_code != 200:
            raise RuntimeError(resp.text)
        
        for line in resp.text.splitlines():
            line = line.strip()
            if len(line) == 0: continue
            if line[0] == '#': continue
            self.bl.append(line)

    def to_detector(self, match="dns", type="hostname", id=None,
                    category="exploit", author="mark.adams@trustnetworks.com",
                    source="TN blacklist conversion", probability=0.8,
                    description=None):

        inds = []

        for b in self.bl:
            ind = {
                "pattern": {
                    "type": type,
                    "match": match,
                    "value": b
                }
            }
            inds.append(ind)

        if id == None:
            id = str(uuid.uuid4())

        inds = {
            "id": id,
            "indicator": {
                "category": category,
                "author": author,
                "source": source,
                "probability": probability
            },
            "operator": "OR",
            "children": inds
        }

        if description != None:
            inds["indicator"]["description"] = description

        return {
            "version": 3,
            "description": "Trust Networks IOCs",
            "definitions": [inds]
        }
