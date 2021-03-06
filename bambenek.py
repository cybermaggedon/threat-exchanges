
############################################################################
# Bambenek OSint to detector conversion
############################################################################

import requests
import uuid
import io
import hashlib
import csv
from cyberprobe.indicators import Indicator, Indicators, Descriptor
import cyberprobe.logictree as lt

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
                    source="Blacklist conversion", prob=0.7,
                    description=None):

        inds = []

        for b in self.bl:
            if len(b) < 1: continue
            if b[0][0] == '#': continue
            if len(b) < 4: continue
            
            value = b[0]

            des = Descriptor(category=category, author=author, source=source,
                             prob=prob, type=type, value=value)

            h = hashlib.new('md5')
            h.update(("bamabenek:" + value).encode("utf-8"))
            id = h.hexdigest()

            ind = Indicator(des, id)

            ind.value = lt.Match(type=type, value=value)

            inds.append(ind)

        return Indicators(version=1, description="Bambenek IOCs",
                          indicators=inds)
