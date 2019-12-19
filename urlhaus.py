
############################################################################
# URLhaus to detector conversion
############################################################################

import requests
import uuid
import io
import hashlib
import csv

from cyberprobe.indicators import Indicator, Indicators, Descriptor
import cyberprobe.logictree as lt

class UrlHaus:

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

    def to_detector(self, type="hostname",
                    category="exploit", author=None,
                    source="Blacklist conversion", prob=0.7,
                    description=None):

        inds = []

        for b in self.bl:
            if len(b) < 1: continue
            if b[0][0] == '#': continue
            if len(b) < 7: continue
            
            url = b[2]

            h = hashlib.new('md5')
            h.update(("urlhaus:" + url).encode("utf-8"))
            id = h.hexdigest()

            des = Descriptor(category=category, author=author,
                             source=source, prob=prob,
                             type=type, value=b)
            if description != None:
                des.description = description
            ii = Indicator(des, id)
            ii.value = lt.Match(type, b)
            inds.append(ii)

        return Indicators(version=1, 
                          description="Urlhaus IOCs",
                          indicators=inds)

