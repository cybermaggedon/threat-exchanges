
############################################################################
# Bambenek OSint to detector conversion
############################################################################

import requests
import uuid
import io
import hashlib
import csv

class Bambenek:

    def __init__(self):
        self.bl = []

    def read_from_url(self, url):

        resp = requests.get(url)

        if resp.status_code != 200:
            raise RuntimeError(resp.text)

        strf = io.StringIO(resp.text)
        reader = csv.reader(strf)

        for line in reader:
            self.bl.append(line)

    def to_detector(self, match="dns", type="hostname",
                    category="exploit", author="osint.bambenekconsulting.com",
                    source="TN blacklist conversion", probability=0.8,
                    description=None):

        inds = []

        for b in self.bl:
            if len(b) < 1: continue
            if b[0][0] == '#': continue
            if len(b) < 4: continue
            
            value = b[0]

            ind = {
                "pattern": {
                    "type": type,
                    "match": match,
                    "value": value
                }
            }

            h = hashlib.new('md5')
            h.update(("bamabenek:" + value).encode("utf-8"))
            id = h.hexdigest()

            ind = {
                "id": id,
                "indicator": {
                    "category": category,
                    "author": author,
                    "source": source,
                    "probability": probability,
                    "description": b[1]
                },
                "operator": "OR",
                "children": [ind]
            }

            inds.append(ind)

        return {
            "version": 3,
            "description": "Trust Networks IOCs",
            "definitions": [inds]
        }
