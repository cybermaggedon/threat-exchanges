
import requests
import json
import urllib
import datetime
import time

class RateLimit(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class ApiError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Obj:
    """
    Base class for a number of openchannel objects, encapsulates standard
    JSON parsing, and string conversion.
    """
    def parse(self, data):
        for v in data:
            setattr(self, v, data[v])
        return self
    def __str__(self):
        return str({v: getattr(self, v) for v in self.__dict__})
    def to_dict(self):
        return {v: getattr(self, v) for v in self.__dict__}

class Owner(Obj):
    def __init__(self):
        self.id = None
        self.name = None

class Indicator(Obj):
    def __init__(self):
        pass
                                
class Threat(Obj):
    def __init__(self):
        self.severity = "UNKNOWN"
        self.status = "UNKNOWN"
        self.confidence = "UNKNOWN"
        self.owner = None
        self.indicator = None
    def parse(self, obj):
        Obj.parse(self, obj)
        if "owner" in obj:
            self.owner = Owner().parse(obj["owner"])
        if "indicator" in obj:
            self.indicator = Indicator().parse(obj["indicator"])
        return self
    def to_dict(self):
        d = self.__dict__
        obj = { k: d[k] for k in d }
        if self.owner != None:
            obj["owner"] = self.owner.to_dict()
        else:
            del obj["owner"]
        if self.indicator != None:
            obj["indicator"] = self.indicator.to_dict()
        else:
            del obj["indicator"]
        return obj

    def to_detector_ioc(self):

        if not hasattr(self, 'indicator'): return None
        if self.indicator == None: return None
        if not hasattr(self.indicator, 'indicator'): return None

        type = None

        if self.indicator.type == "DOMAIN": type = "hostname"
        if self.indicator.type == "EMAIL_ADDRESS": type = "email"
        if self.indicator.type == "HASH_MD5": type = "md5"
        if self.indicator.type == "HASH_SHA1": type = "sha1"
        if self.indicator.type == "HASH_SHA256": type = "sha256"
        if self.indicator.type == "IP_ADDRESS": type = "ipv4"
        if self.indicator.type == "NAME_SERVER": type = "hostname"
        if self.indicator.type == "SOURCE_PORT": type = "src.tcp"
        if self.indicator.type == "DEST_PORT": type = "dest.tcp"
        if self.indicator.type == "URI": type = "url"
        if self.indicator.type == "USERAGENT": type = "useragent"

        if type == None: return None

        ind = {
            "id": self.id,
            "indicator": {
                "category": "test",
                "author": self.owner.name,
                "source": "FaceBook threat exchange"
            },
            "operator": "AND",
            "children": [
                {
                    "pattern": {
                        "match": type,
                        "value": self.indicator.indicator
                    }
                }
            ]
        }

        if hasattr(self, "description"):
            ind["indicator"]["description"] = self.description

        ind["indicator"]["category"] = "unspecified"

        return  ind

    def severity_score(self):
        return {
            "UNKNOWN": 0.1,
            "INFO": 0.3,
            "WARNING": 0.8,
            "SUSPICIOUS": 0.9,
            "SEVERE": 0.95,
            "APOCALYPSE": 1.0
        }.get(self.severity, 0.0)

    def status_score(self):
        return {
            "UNKNOWN": 0.1,
            "NON_MALICIOUS": 0.0,
            "SUSPICIOUS": 0.9,
            "MALICIOUS": 1.0
        }.get(self.status, 0.0)

    def score(self):
        return self.severity_score() * self.status_score()
        
class Facebook:
    def __init__(self, id, secret):
        self.id = id
        self.secret = secret
        self.base = "https://graph.facebook.com/"

    def get_ip_report(self, ip):
        
        query_params = urllib.parse.urlencode({
            'access_token': self.id + '|' + self.secret,
            'type': "IP_ADDRESS",
            'text': ip,
            'strict_text' : True
        })

        url = "%s/v2.4/threat_descriptors?" % self.base + query_params

        r = requests.get(url)
        
        if r.status_code != 200:
            raise ApiError(r.text)

        return r.json()

    def get_domain_report(self, domain):
        
        query_params = urllib.parse.urlencode({
            'access_token': self.id + '|' + self.secret,
            'type': "DOMAIN",
            'text': domain,
            'strict_text': True
        })

        url = "%s/v2.4/threat_descriptors?" % self.base + query_params

        r = requests.get(url)
        
        if r.status_code != 200:
            raise ApiError(r.text)

        return r.json()

    def sev_prob(self, x):
        return {
            "UNKNOWN": 0.1,
            "INFO": 0.3,
            "WARNING": 0.5,
            "SUSPICIOUS": 0.7,
            "SEVERE": 0.9,
            "APOCALYPSE": 1.0
        }.get(x, 0.0)

    def status_prob(self, x):
        return {
            "UNKNOWN": 0.1,
            "NON_MALICIOUS": 0.0,
            "SUSPICIOUS": 0.7,
            "MALICIOUS": 1.0
        }.get(x, 0.0)

    def get_indicators(self, owner=None, since=None, until=None, limit=100):

        pagesize=limit
        if pagesize > 250: pagesize = 250

        if since == None:
            since = time.time() - 86400 * 3
            since = time.gmtime(since)
            since = time.strftime("%Y-%m-%dT%H:%M:%S+0000", since)

        if until == None:
            until = time.time()
            until = time.gmtime(until)
            until = time.strftime("%Y-%m-%dT%H:%M:%S+0000", until)
        
        query_params = {
            'access_token': self.id + '|' + self.secret
        }

        if owner != None:
            query_params["owner"] = owner

        query_params["limit"] = pagesize
        query_params["since"] = since
        query_params["until"] = until
        
        query_params = urllib.parse.urlencode(query_params)
        url = "%s/v2.4/threat_descriptors?" % self.base + query_params

        while limit > 0:

            r = requests.get(url)
        
            if r.status_code != 200:
                raise ApiError(r.text)

            res = r.json()
            
            for v in res["data"]:

                yield Threat().parse(v)

                limit -= 1
                if limit <= 0:
                    break

            if limit <= 0: break

            if "paging" not in res: break
            if "next" not in res["paging"]: break

            url = res["paging"]["next"]

