
# Threat Exchange integration

But not enough to be useful.

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