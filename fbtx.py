
############################################################################
# Facebook Threat Exchange API
############################################################################

import requests
import json
import urllib
import datetime
import time

############################################################################
# Some API exceptions.  Probably not all used.
############################################################################

# Rate limit.  Not managed to trigger this yet.
class RateLimit(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

# All other API errors.
class ApiError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

############################################################################
# Base object class, converts between native objects and dictionaries.
############################################################################

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

############################################################################
# FBTX owner
############################################################################

class Owner(Obj):
    def __init__(self):
        self.id = None
        self.name = None

############################################################################
# Indicator
############################################################################

class Indicator(Obj):
    def __init__(self):
        pass

############################################################################
# FBTX threat indicator
############################################################################
                                
class Threat(Obj):

    # Initialise.
    def __init__(self):
        self.severity = "UNKNOWN"
        self.status = "UNKNOWN"
        self.confidence = "UNKNOWN"
        self.owner = None
        self.indicator = None

    # Parse - takes the output of json.loads.  Usage:
    #   Threat().parse(json.loads(raw))
    def parse(self, obj):
        Obj.parse(self, obj)
        if "owner" in obj:
            self.owner = Owner().parse(obj["owner"])
        if "indicator" in obj:
            self.indicator = Indicator().parse(obj["indicator"])
        return self

    # Converts to dict.  Should be able to convert back to FBTX's JSON
    # like this...
    #    json.dumps(threat.to_dict())
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

    # Convert to an object representing a detector IOC.  Usage:
    #    with open("file.json", "w") as f:
    #        f.write(json.dumps(threat.to_detector_ioc()))
    #        f.close()
    def to_detector_ioc(self):

        # If no indicator, bail out.
        if not hasattr(self, 'indicator'): return None
        if self.indicator == None: return None
        if not hasattr(self.indicator, 'indicator'): return None

        # Convert to detector's types.
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

        match = "string"
        if type == "hostname":
            match = "dns"

        # If type not understand, do nothing.
        if type == None: return None

        # FIXME: No idea what category to put on it, so must likely to
        # exploitation.
        # FIXME: Is that even true?

        # Create base indicator
        ind = {
            "id": self.id,
            "indicator": {
                "category": "exploit",
                "author": self.owner.name,
                "source": "FaceBook threat exchange",
                "probability": self.score()
            },
            "operator": "AND",
            "pattern": {
                "type": type,
                "value": self.indicator.indicator,
                "match": match
            }
        }

        # Add description, if provided
        if hasattr(self, "description"):
            ind["indicator"]["description"] = self.description

        return  ind

    # Return score based on severity
    def severity_score(self):
        return {
            "UNKNOWN": 0.1,
            "INFO": 0.3,
            "WARNING": 0.8,
            "SUSPICIOUS": 0.9,
            "SEVERE": 0.95,
            "APOCALYPSE": 1.0
        }.get(self.severity, 0.0)

    # Return score based on status
    def status_score(self):
        return {
            "UNKNOWN": 0.1,
            "NON_MALICIOUS": 0.0,
            "SUSPICIOUS": 0.9,
            "MALICIOUS": 1.0
        }.get(self.status, 0.0)

    # Return score
    def score(self):
        if hasattr(self, "review_status"):
            if self.review_status == "UNREVIEWED":
                return 0.0
        return self.severity_score() * self.status_score()

############################################################################
# FBTX API
############################################################################
    
class Facebook:

    # Constructor
    def __init__(self, id, secret):
        self.id = id
        self.secret = secret
        self.base = "https://graph.facebook.com/"

    # Get report for a single IP.
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

        return Threat().parse(r.json())

    # Get report for a single domain.
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

        return Threat().parse(r.json())

    # Returns a generator, dumping FBTX indicators. Generates Threat objects.
    def get_indicators(self, owner=None, since=None, until=None, limit=100):

        # We fetch in pages, page size is same as limit, unless limit > 250,
        # in which case we'll fetch in batches of 250.
        pagesize=limit
        if pagesize > 250: pagesize = 250

        # Default 'since' value is 3 days ago
        if since == None:
            since = time.time() - 86400 * 3
            since = time.gmtime(since)
            since = time.strftime("%Y-%m-%dT%H:%M:%S+0000", since)

        # Default 'until' value is now.
        if until == None:
            until = time.time()
            until = time.gmtime(until)
            until = time.strftime("%Y-%m-%dT%H:%M:%S+0000", until)
        
        # Construct query parameters.
        query_params = {
            'access_token': self.id + '|' + self.secret,
            'since': since,
            'until': until,
            'limit': pagesize
        }

        # Add owner to query params, if present
        if owner != None:
            query_params["owner"] = owner

        # Convert to URL
        query_params = urllib.parse.urlencode(query_params)
        url = "%s/v2.4/threat_descriptors?" % self.base + query_params

        # Keep going until we've fetched the number of items the caller asked
        # for.
        while limit > 0:

            # Fetch the next page
            r = requests.get(url)

            # 200 code indicates success.
            if r.status_code != 200:
                raise ApiError(r.text)

            # Convert to JSON
            res = r.json()

            # Iterate over return values
            for v in res["data"]:

                # Return one threat
                yield Threat().parse(v)

                # Keep going until limit, then break out of inner loop.
                limit -= 1
                if limit <= 0:
                    break

            # This is a bailing point for the outer loop.
            if limit <= 0: break

            # Get the URL for next page, and loop back.
            if "paging" not in res: break
            if "next" not in res["paging"]: break
            url = res["paging"]["next"]

