
############################################################################
# Simple blacklist to detector conversion
############################################################################

import requests
import uuid
from cyberprobe.indicators import Indicator, Indicators, Descriptor
import cyberprobe.logictree as lt

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

    def to_indicators(self, type="hostname",
                    category="exploit", author=None,
                    source="Blacklist conversion", prob=0.7,
                    description=None, version=1):

        inds = []

        for b in self.bl:

            des = Descriptor(category=category, author=author,
                             source=source, prob=prob,
                             type=type, value=b)
            if description != None:
                des.description = description
            ii = Indicator(des)
            ii.value = lt.Match(type, b)
            inds.append(ii)

        i = Indicators(
            version=version, description="Blacklist",
            indicators=inds
        )

        return i
