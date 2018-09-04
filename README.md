
# Threat Exchange integration

But not enough to be useful.

## Comparitor

| | | Accuracy | Expressivity | Applicability |
|-|-|----------|--------------|---------------|
| FBTX | Crowd-sourced - User has to work out who to trust | LOW.  The Facebook Admin publisher is more consistent than other publishers.  User has to work out who to trust or not. | LOW.  Can only represent a single term with no boolean logic. | HIGH.  Very easy to consume the terms and work out how to apply. |
| OpenIOC | A format, not an exchange | HIGH. Tends to be hand-crafted expressions combining many factors to give low false-positive. | HIGH.  Very powerful language, although many of the terms are specific to specific Mandiant endpoint capabilities. | MEDIUM.  OpenIOC is designed to be used with a particular set of Mandiat capabilities, some terms are very specific to this.  Some rules are specific to endpoint analysis, and can't be applied to network data. |
| abuse.ch | Variety of automated curation of botnet blocklists | HIGH.  Targeted operation which is accurate against certain botnets. | LOW.  Only botnets which can be blocked through blocklists, although this is fine for the particular applications. | HIGH. Blocklists are very easy to deploy. |

# OpenIOC

Basic OpenIOC to detector conversion.  Detector doesn't support all OpenIOC
primitives.  OpenIOC is really intended to be used in endpoint scenarios
where the scanner has access to reports from various sources (process list,
network cache, scanning emails) and can run a rule which accesses all these
reports.

The FireEye APT examples are in `fireeye/`, stolen from
`https://github.com/fireeye/iocs`.

Convert to detector format:

```
$ ./openioc-to-detector
```

# abuse.ch

Collection of malware trackers.

```
$ ./abusech-to-detector
```

# Bambenek consulting

Collection of malware trackers.

```
$ ./bambenek-to-detector
```

# URLhaus

Part of abuse.ch.  Collection of malware trackers.

```
$ ./urlhaus-to-detector
```

# Facebook

The file `facebook-creds` contains an API secret, which is taken from the
Trust Networks app in Carey's FaceBook dev account.  If it doesn't work, maybe
generate another one.

## Convert threat exchange to detectors IOCs

```
$ mkdir ioc/
$ ./fbtx-to-detector
```

Dumps a load of stuff in IOC, and also writes out a detector-style
IOC file to `all-iocs.json`.

I've put a sample file in `all-iocs.json` so you don't have to run the thing.
Because... it takes 15 mins to run, you know.

The IOCs may not all work in `detector` because the risk category is hard-coded
as `exploit` which is a proposed category in the risk category, not
implemented.  Also, not all types are used.

## Look up a domain

```
$ ./fbtx-lookup-domain www.google.com
----------- www.google.com
{
    "severity": "UNKNOWN",
    "status": "UNKNOWN",
    "confidence": "UNKNOWN",
    "data": [
        {
            "added_on": "2015-06-19T22:34:27+0000",
            "confidence": 1,
            "description": "Non malicious",
            "id": "1118998238117567",
            "indicator": {
                "id": "731370023621054",
                "indicator": "www.google.com",
                "type": "DOMAIN"
            },
            "last_updated": "2018-08-30T20:09:39+0000",
            "owner": {
                "id": "820763734618599",
                "email": "threatexchange@support.facebook.com",
                "name": "Facebook Administrator"
            },
            "precision": "UNKNOWN",
            "privacy_type": "VISIBLE",
            "raw_indicator": "www.google.com",
            "review_status": "REVIEWED_AUTOMATICALLY",
            "severity": "INFO",
            "share_level": "GREEN",
            "status": "NON_MALICIOUS",
            "type": "DOMAIN"
        }
    ]
}
```