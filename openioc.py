
import json
import xml.etree.ElementTree as ET

namespaces={
    "ioc": "http://schemas.mandiant.com/2010/ioc"
}

class Base:
    def to_dict(self):
        obj = {}
        for k in self.__dict__:
            v = getattr(self, k)
            if isinstance(v, Base):
                obj[k] = v.to_dict()
            else:
                obj[k] = v
        return obj

class Indicator(Base):
    pass

class Context(Base):
    def __init__(self, document, search, type):
        self.document = document
        self.search = search
        self.type = type

class Content(Base):
    def __init__(self, type, value):
        self.type = type
        self.value = value

detector_mapping = {
    ("FileItem", "FileItem/Md5sum", "mir"): {
        "match": "string", "type": "md5"
    },
    ("FileItem", "FileItem/SizeInBytes", "mir"): {
        "match": "int", "type": "payload-length"
    },
    ("PortItem", "PortItem/remoteIP", "mir"): {
        "match": "string", "type": "ipv4"
    },
    ("DnsEntryItem", "DnsEntryItem/Host", "mir"): {
        "match": "dns", "type": "hostname"
    },
    ("DnsEntryItem", "DnsEntryItem/RecordName", "mir"): {
        "match": "dns", "type": "hostname"
    },
    ("Email", "Email/From", "email"): {
        "match": "string", "type": "email"
    },
    ("Network", "Network/URI", "network"): {
        "match": "substring", "type": "url"
    },
    ("Network", "Network/UserAgent", "network"): {
        "match": "substring", "type": "useragent"
    }
}

class IndicatorItem(Indicator):
    def __init__(self, id, context, content):
        self.context = context
        self.content = content
    def to_detector(self):
        k = (self.context.document, self.context.search, self.context.type)
        if k in detector_mapping:
            map = detector_mapping[k]
            return {
                "pattern": {
                    "match": map["match"],
                    "type": map["type"],
                    "value": self.content.value
                }
            }
        else:
            return {
                "match": "string",
                "type": "NOT_MATCHABLE>>>" + self.context.search,
                "value": self.content.value
            }

class CompoundIndicator(Indicator):
    def __init__(self, id, operator, indicators):
        self.operator = operator
        self.indicators = indicators
    def to_dict(self):
        return {
            "operator": self.operator,
            "indicators": [v.to_dict() for v in self.indicators]
        }
    def to_detector(self):
        return {
            "operator": self.operator,
            "children": [v.to_detector() for v in self.indicators]
        }

class IocDefinition(Base):

    def __init__(self):
        self.link = {}

    def parse_file(self, path):

        tree = ET.parse(path)
        root = tree.getroot()

        for elt in root.findall("ioc:links", namespaces):
            for elt2 in elt.findall("ioc:link", namespaces):
                self.link[elt2.attrib["rel"]] = elt2.text

        defs = root.findall("ioc:definition", namespaces)
        if len(defs) != 1:
            raise RuntimeError("Require exactly one <definition> tag")
        defs = defs[0]

        short_desc = root.find("ioc:short_description", namespaces)
        if short_desc != None:
            self.short_description = short_desc.text

        desc = root.find("ioc:description", namespaces)
        if desc != None:
            self.description = desc.text

        authored_by = root.find("ioc:authored_by", namespaces)
        if authored_by != None:
            self.authored_by = authored_by.text

        authored_date = root.find("ioc:authored_date", namespaces)
        if authored_date != None:
            self.authored_date = authored_date.text

        self.id = root.attrib["id"]

        self.definition = self.decode(defs[0])

    def decode(self, elt):

        if elt.tag == "{http://schemas.mandiant.com/2010/ioc}Indicator":
            id = elt.attrib["id"]
            oper = elt.attrib["operator"]
            return CompoundIndicator(id, oper, [self.decode(v) for v in elt])
        elif elt.tag == "{http://schemas.mandiant.com/2010/ioc}IndicatorItem":
            id = elt.attrib["id"]
            ctxt = elt.find("ioc:Context", namespaces)
            ctnt = elt.find("ioc:Content", namespaces)
            return IndicatorItem(
                id,
                Context(ctxt.attrib["document"],
                        ctxt.attrib["search"],
                        ctxt.attrib["type"]),
                Content(ctnt.attrib["type"],
                        ctnt.text)
            )
        else:
            raise RuntimeError("Require <Indicator> or <IndicatorItem> tag")

    def to_detector(self):
        obj = self.definition.to_detector()
        obj["id"] = self.id
        obj["indicator"] = {
            "category": "exploit",
            "author": "mark.adams@trustnetworks.com",
            "source": "Trust Networks OpenIOC converter",
            "probability": 1.0
        }
        return obj
