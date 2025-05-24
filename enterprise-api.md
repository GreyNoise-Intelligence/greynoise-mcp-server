### IP Context

Get more information about a given IP address. Returns time ranges, IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, activity tags, and raw port scan and web request information.

request:

`GET https://api.greynoise.io/v2/noise/context/{ip}`

- `ip`: IP address to query

```js
const options = {
  method: 'GET',
  headers: {
    accept: 'application/json',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/v2/noise/context/ip', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response: 

```json
{
  "ip": "14.224.159.177",
  "first_seen": "2024-12-29",
  "last_seen": "2025-04-12",
  "seen": true,
  "tags": [
    "SMBv1 Crawler",
    "WannaCry Variant SMB Connection Attempt"
  ],
  "actor": "unknown",
  "spoofable": false,
  "classification": "malicious",
  "cve": [],
  "bot": false,
  "vpn": false,
  "vpn_service": "",
  "metadata": {
    "asn": "AS45899",
    "city": "Vĩnh Yên",
    "country": "Vietnam",
    "country_code": "VN",
    "organization": "VNPT Corp",
    "category": "isp",
    "tor": false,
    "rdns": "static.vnpt.vn",
    "os": "unknown",
    "region": "Vĩnh Phúc Province",
    "destination_countries": [
      "United States",
      "Germany",
      "Singapore",
      "United Kingdom",
      "Netherlands",
      "Japan",
      "Canada",
      "France",
      "Israel",
      "Malaysia",
      "Peru",
      "Serbia",
      "Ukraine",
      "Belarus",
      "Kazakhstan",
      "Lithuania",
      "Luxembourg",
      "Switzerland",
      "Turkey"
    ],
    "destination_country_codes": [
      "US",
      "DE",
      "GB",
      "SG",
      "NL",
      "JP",
      "CA",
      "FR",
      "IL",
      "MY",
      "PE",
      "RS",
      "UA",
      "BY",
      "CH",
      "KZ",
      "LT",
      "LU",
      "TR"
    ],
    "source_country": "Vietnam",
    "source_country_code": "VN",
    "sensor_hits": 36662,
    "sensor_count": 1073
  },
  "raw_data": {
    "scan": [
      {
        "port": 445,
        "protocol": "tcp"
      }
    ],
    "web": {},
    "ja3": [],
    "hassh": []
  }
}
```

### IP Quick Check

Check whether a given IP address is “Internet background noise”, or has been observed scanning or attacking devices across the Internet.

Notes:

- This API endpoint is real-time
- This API endpoint contains a “code” which correlates to why GreyNoise labeled the IP as "noise"
- This API endpoint checks the IP against the RIOT data set, setting the bool flag of "riot" if it appears
- An IP delivered via this endpoint does not include a “malicious” or “benign” categorizations
- This API endpoint only checks against the last 90 days of Internet scanner data

Return code:

- `0x00`: The IP has never been observed scanning the Internet
- `0x01`: The IP has been observed by the GreyNoise sensor network
- `0x02`: The IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed
- `0x05`: This IP is commonly spoofed in Internet-scan activity
- `0x06`: This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently
- `0x07`: This IP is invalid
- `0x08`: This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 90 days
- `0x09`: This IP was found in RIOT
- `0x10`: The IP has been observed by the GreyNoise sensor network and was found in RIOT

request:

`GET https://api.greynoise.io/v2/noise/quick/{ip}`

- `ip`: IP address to query

```js
const options = {
  method: 'GET',
  headers: {
    accept: 'application/json',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/v2/noise/quick/14.224.159.177', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response:

```json
{
  "code": "0x01",
  "ip": "14.224.159.177",
  "noise": true,
  "riot": false
}
```

### Multi-IP Quick Check

Check whether a set of IP addresses are "Internet background noise", or have been observed scanning or attacking devices across the Internet. This endpoint is functionality identical to the /v2/noise/quick/{ip} endpoint, except it processes more than one checks simultaneously. This endpoint is useful for filtering through large log files.

Can process up to 1,000 IPs per request.

Notes:

- This API endpoint updates in real-time
- This API endpoint can either be used via GET parameter or within the body of the request
- This API endpoint contains a “code” which correlates to why GreyNoise labeled the IP as "noise"
- This API endpoint checks the IP against the RIOT data set, setting the bool flag of "riot" if it appears
- An IP delivered via this endpoint does not include "malicious" or "benign" categorizations
- This API endpoint only checks against the last 90 days of Internet scanner data

Return code:

- `0x00`: The IP has never been observed scanning the Internet
- `0x01`: The IP has been observed by the GreyNoise sensor network
- `0x02`: The IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed
- `0x05`: This IP is commonly spoofed in Internet-scan activity
- `0x06`: This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently
- `0x07`: This IP is invalid
- `0x08`: This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 90 days
- `0x09`: This IP was found in RIOT
- `0x10`: The IP has been observed by the GreyNoise sensor network and was found in RIOT

request:

```js
const options = {
  method: 'POST',
  headers: {
    accept: 'application/json',
    'content-type': 'application/json',
    key: 'GREYNOISE_API_KEY'
  },
  body: JSON.stringify({ips: ['14.224.159.177', '65.18.125.174']})
};

fetch('https://api.greynoise.io/v2/noise/multi/quick', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response:

```json
[
  {
    "code": "0x01",
    "ip": "14.224.159.177",
    "noise": true,
    "riot": false
  },
  {
    "code": "0x01",
    "ip": "65.18.125.174",
    "noise": true,
    "riot": false
  }
}
```

### RIOT IP Lookup

RIOT identifies IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products. The collection of IPs in RIOT is continually curated and verified to provide accurate results.

request:

`GET https://api.greynoise.io/v2/riot/{ip}`

- `ip`: IP address to query

```js
const options = {
  method: 'GET',
  headers: {
    accept: 'application/json',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/v2/riot/14.224.159.177', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response:

```json
{
  "ip": "14.224.159.177",
  "riot": false
}
```

### Retrieve CVE Information

Retrieve details about a specific Common Vulnerabilities and Exposures (CVE).

request:

`GET https://api.greynoise.io/v1/cve/{cve_id}`

- `cve_id`: The CVE ID to query (e.g., CVE-2024-12345)

```js
const options = {
  method: 'GET',
  headers: {
    accept: 'application/json',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/v1/cve/CVE-2023-6549', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response:

```json
{
  "id": "CVE-2023-6549",
  "details": {
    "vulnerability_name": "Citrix NetScaler ADC and NetScaler Gateway Buffer Overflow Vulnerability",
    "vulnerability_description": "Improper Restriction of Operations within the Bounds of a Memory Buffer in NetScaler ADC and NetScaler Gateway allows Unauthenticated Denial of Service and Out-Of-Bounds Memory Read",
    "cve_cvss_score": 8.2,
    "product": "NetScaler ADC and NetScaler Gateway",
    "vendor": "Citrix",
    "published_to_nist_nvd": true
  },
  "timeline": {
    "cve_published_date": "2024-01-17T21:15:11Z",
    "cve_last_updated_date": "2025-01-27T21:48:20Z",
    "first_known_published_date": "2024-01-16T00:00:00Z",
    "cisa_kev_date_added": "2024-01-17T00:00:00Z"
  },
  "exploitation_details": {
    "attack_vector": "NETWORK",
    "exploit_found": true,
    "exploitation_registered_in_kev": true,
    "epss_score": 0.37766
  },
  "exploitation_stats": {
    "number_of_available_exploits": 1,
    "number_of_threat_actors_exploiting_vulnerability": 1,
    "number_of_botnets_exploiting_vulnerability": 0
  },
  "exploitation_activity": {
    "activity_seen": false,
    "benign_ip_count_1d": 0,
    "benign_ip_count_10d": 0,
    "benign_ip_count_30d": 0,
    "threat_ip_count_1d": 0,
    "threat_ip_count_10d": 0,
    "threat_ip_count_30d": 0
  }
}
```

### Tag Metadata

Get a list of tags and their respective metadata.

request:

```js
const options = {
  method: 'GET',
  headers: {
    accept: 'application/json',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/v2/meta/metadata', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response:

```json
{
  "metadata": [
    {
      "id": "1d941f65-5294-4d85-b706-b7ac505bb985",
      "label": "CCBOT",
      "slug": "ccbot",
      "name": "Common Crawl Bot",
      "category": "actor",
      "intention": "benign",
      "description": "IP addresses with this tag belong to Common Crawl, a legitimate research organization that crawls the Internet.",
      "references": [
        "http://commoncrawl.org/big-picture/frequently-asked-questions/"
      ],
      "recommend_block": false,
      "cves": [],
      "created_at": "2020-04-07",
      "related_tags": []
    },
  ]
}
```

### Ping

Provides a simple endpoint to check GreyNoise status and GreyNoise API access

request:

```js
const options = {
  method: 'GET',
  headers: {
    accept: '*/*',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/ping', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response:

```json
{
  "expiration": "2025-12-31",
  "message": "pong",
  "offering": "vip",
  "address": "73.126.107.197"
}
```

### GNQL Stats

Get aggregate statistics for the top organizations, actors, tags, ASNs, countries, classifications, and operating systems of all the results of a given GNQL query.

request:

- `query` is a GNQL query string
- `count` is the number of top aggregates to grab (you should default to 10 but let the user specify a value up to 10,000)

```js
const options = {
  method: 'GET',
  headers: {
    accept: 'application/json',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/v2/experimental/gnql/stats?query=last_seen%3A1d&count=10', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response:

```json
{
  "count": 495247,
  "query": "last_seen:1d",
  "stats": {
    "classifications": [
      {
        "classification": "unknown",
        "count": 242842
      },
      {
        "classification": "malicious",
        "count": 124060
      },
      {
        "classification": "suspicious",
        "count": 117653
      },
      {
        "classification": "benign",
        "count": 10692
      }
    ],
    "spoofable": [
      {
        "spoofable": false,
        "count": 392552
      },
      {
        "spoofable": true,
        "count": 102695
      }
    ],
    "organizations": [
      {
        "organization": "Iran Cell Service and Communication Company",
        "count": 11051
      },
      {
        "organization": "Reliance Jio Infocomm Limited",
        "count": 9559
      },
      {
        "organization": "Amazon.com, Inc.",
        "count": 7344
      }
    ],
    "actors": [
      {
        "actor": "ShadowServer.org",
        "count": 768
      },
      {
        "actor": "BinaryEdge.io",
        "count": 762
      },
      {
        "actor": "ONYPHE",
        "count": 595
      }
    ],
    "countries": [
      {
        "country": "Russia",
        "count": 13908
      },
      {
        "country": "Singapore",
        "count": 10212
      },
      {
        "country": "Germany",
        "count": 9924
      },
      {
        "country": "Nigeria",
        "count": 9307
      }
    ],
    "source_countries": [
      {
        "country": "Singapore",
        "count": 10212
      },
      {
        "country": "Germany",
        "count": 9924
      },
      {
        "country": "Nigeria",
        "count": 9307
      }
    ],
    "destination_countries": [
      {
        "country": "United Kingdom",
        "count": 151303
      },
      {
        "country": "Singapore",
        "count": 144873
      },
      {
        "country": "Australia",
        "count": 136500
      },
      {
        "country": "Japan",
        "count": 134935
      },
      {
        "country": "Spain",
        "count": 121072
      },
      {
        "country": "France",
        "count": 110641
      }
    ],
    "tags": [
  
      {
        "tag": "Generic IoT Default Password Attempt",
        "id": "f620e81c-eaf4-477f-8bc4-ec94ca672615",
        "count": 37776
      },
      {
        "tag": "SSH Alternative Port Crawler",
        "id": "b1859b91-92d5-48d2-b43d-bbfd09db964d",
        "count": 34949
      },
      {
        "tag": "Mirai",
        "id": "ef0cc90d-d80c-436f-92c5-3d8f8665c9ac",
        "count": 33101
      },
      {
        "tag": "Ping Scanner",
        "id": "804e348c-2a55-46f5-bad5-a521f0dd8571",
        "count": 31713
      }
    ],
    "operating_systems": null,
    "categories": [
      {
        "category": "education",
        "count": 1333
      },
      {
        "category": "government",
        "count": 437
      },
      {
        "category": "inactive",
        "count": 30
      }
    ],
    "asns": [
      {
        "asn": "AS55836",
        "count": 9559
      },
      {
        "asn": "AS14061",
        "count": 6649
      }
    ]
  }
}
```

### GNQL Query

GNQL (GreyNoise Query Language) is a domain-specific query language that uses Lucene deep under the hood.

Facets:

- `ip` - The IP address of the scanning device IP
- `classification` - Whether the device has been categorized as unknown, benign, or malicious
- `first_seen` - The date the device was first observed by GreyNoise
- `last_seen` - The date the device was most recently observed by GreyNoise
- `actor` - The benign actor the device has been associated with, such as Shodan, Censys, GoogleBot, etc
- `tags` - A list of the tags the device has been assigned over the past 90 days
- `spoofable` - This IP address has been opportunistically scanning the Internet, however has failed to complete a full TCP connection. Any reported activity could be spoofed.
- `vpn` - This IP is associated with a VPN service. Activity, malicious or otherwise, should not be attributed to the VPN service provider.
- `vpn_service` - The VPN service the IP is associated with
- `cve` - A list of CVEs that the device has been associated with
- `bot` - If the IP is known to belong to a known BOT
- `single_destination` - A boolean parameter that filters source country IPs that have only been observed in a single destination country
- `metadata.category` - Whether the device belongs to a business, isp, hosting, education, or mobile network
- `metadata.country` - The full name of the country the device is geographically located in (This is the same data as `metadata.source_country`. `metadata.source_country` is preferred)
- `metadata.country_code` - The two-character country code of the country the device is geographically located in (This is the same data as `metadata.source_country_code`. `metadata.source_country_code` is preferred)
- `metadata.sensor_hits` - The amount of unique data that has been recorded by the sensor
- `metadata.sensor_count` - The number of sensors the IP Address has been observed on
- `metadata.city` - The city the device is geographically located in
- `metadata.region` - The region the device is geographically located in
- `metadata.organization` - The organization that owns the network that the IP address belongs to
- `metadata.rdns` - The reverse DNS pointer of the IP
- `metadata.asn` - The autonomous system the IP address belongs to
- `metadata.tor` - Whether or not the device is a known Tor exit node
- `metadata.destination_country` - The full name where the GreyNoise sensor is physically located
- `metadata.destination_country_code` - The country code where GreyNoise sensor is physically located
- `metadata.source_country_code` - The two-character country code of the country the device is geographically located in
- `metadata.source_country` - The full name of the country the device is geographically located in
- `raw_data.scan.port` - The port number(s) the devices has been observed scanning
- `raw_data.scan.protocol` - The protocol of the port the device has been observed scanning
- `raw_data.web.paths` - Any HTTP paths the device has been observed crawling the Internet for
- `raw_data.web.useragents` - Any HTTP user-agents the device has been observed using while crawling the Internet
- `raw_data.ja3.fingerprint` - The JA3 TLS/SSL fingerprint
- `raw_data.ja3.port` - The corresponding TCP port for the given JA3 fingerprint
- `raw_data.hassh.fingerprint` - The HASSH fingerprint
- `raw_data.hassh.port` - The corresponding TCP port for the given HASSH fingerprint

Behavior:

- You can subtract facets by prefacing the query with a minus character
- The data that this endpoint queries refreshes once per hour

Shortcuts:

- You can find interesting hosts by using the GNQL query term `interesting`
- You can use the keyword `today` in the `first_seen` and `last_seen` parameters: `last_seen:today` or `first_seen:today`

Examples:

- `last_seen:today` - Returns all IPs scanning/crawling the Internet today
- `tags:Mirai` - Returns all devices with the "Mirai" tag
- `tags:"RDP Scanner"` - Returns all devices with the "RDP Scanner" tag
- `classification:malicious metadata.country:Belgium` — Returns all compromised devices located in Belgium
- `classification:malicious metadata.rdns:*.gov*` - Returns all compromised devices that include .gov in their reverse DNS records
- `metadata.organization:Microsoft classification:malicious` — Returns all compromised devices that belong to Microsoft
- `(raw_data.scan.port:445 and raw_data.scan.protocol:TCP) metadata.os:Windows*` - Return all devices scanning the Internet for port 445/TCP running Windows operating systems (Conficker/EternalBlue/WannaCry)
- `raw_data.scan.port:554` - Returns all devices scanning the Internet for port 554
- `-metadata.organization:Google raw_data.web.useragents:GoogleBot` — Returns all devices crawling the Internet with "GoogleBot" in their useragent from a network that does NOT belong to Google
- `tags:"Siemens PLC Scanner" -classification:benign` - Returns all devices scanning the Internet for SCADA devices who ARE NOT tagged by GreyNoise as "benign" (Shodan/Project Sonar/Censys/Google/Bing/etc)
- `classification:benign` - Returns all "good guys" scanning the Internet
- `raw_data.ja3.fingerprint:795bc7ce13f60d61e9ac03611dd36d90` — Returns all devices crawling the Internet with a matching client JA3 TLS/SSL fingerprint
- `raw_data.hassh.fingerprint:51cba57125523ce4b9db67714a90bf6e` — Returns all devices crawling the Internet with a matching client HASSH fingerprint
- `raw_data.web.paths:"/HNAP1/"` -Returns all devices crawling the Internet for the HTTP path "/HNAP1/"
- `8.0.0.0/8` - Returns all devices scanning the Internet from the CIDR block 8.0.0.0/8
- `cve:CVE-2021-30461` - Returns all devices associated with the supplied CVE
- `source_country:Iran` - Returns all results originating from Iran
- `destination_country:Ukraine single_destination:true` — Returns all results scanning in only Ukraine

request:

- `query`: GNQL query string
- `size`: The number of results provided per page for paginating through all results of a query (you should default to 10 but let the user specify a value up to 10,000)
- `scroll`: Scroll token to paginate through results

```js
const options = {
  method: 'GET',
  headers: {
    accept: 'application/json',
    key: 'GREYNOISE_API_KEY'
  }
};

fetch('https://api.greynoise.io/v2/experimental/gnql?query=tags%3A%22Umbraco%20baseUrl%20SSRF%20Attempt%22%20-classification%3Abenign&size=10', options)
  .then(res => res.json())
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

response: 

```json
{
  "complete": true,
  "count": 5,
  "data": [
    {
      "ip": "104.248.99.110",
      "metadata": {
        "asn": "AS14061",
        "city": "Singapore",
        "country": "Singapore",
        "country_code": "SG",
        "organization": "DigitalOcean, LLC",
        "category": "hosting",
        "tor": false,
        "rdns": "",
        "os": "",
        "sensor_count": 1,
        "sensor_hits": 254839,
        "region": "Singapore",
        "destination_countries": [
          "Lithuania"
        ],
        "source_country": "Singapore",
        "source_country_code": "SG",
        "destination_country_codes": [
          "LT"
        ]
      },
      "bot": false,
      "vpn": false,
      "vpn_service": "",
      "spoofable": false,
      "raw_data": {
        "scan": [
          {
            "port": 0,
            "protocol": "tcp"
          },
          {
            "port": 21,
            "protocol": "tcp"
          }
        ],
        "web": {
          "paths": [
            "/R9iPortal/2vcIuo1zoKWfy6HwrgtmprRHYPE.jsp",
            "/user/City_ajax.aspx",
            "/index.php"
          ],
          "useragents": [
            "Mozilla/5.0 (Knoppix; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
            "Mozilla/5.0 (SS; Linux i686; rv:128.0) Gecko/20100101 Firefox/128.0"
          ]
        },
        "ja3": [],
        "hassh": [
          {
            "fingerprint": "2aec6b44b06bec95d73f66b5d30cb69a",
            "port": 22
          }
        ]
      },
      "first_seen": "2025-03-15",
      "last_seen": "2025-04-12",
      "seen": true,
      "tags": [
        ".DS_Store Scanner",
        "3CX Management Console LFI Attempt",
        "74CMS SQL Injection Attempt",
        "ACME Challenge XSS Check",
        "APsystems Altenergy Power Control Software RCE Attempt",
        "AWIND Presentation Platform RCE CVE-2019-3929"
      ],
      "actor": "unknown",
      "classification": "malicious",
      "cve": [
        "CVE-2020-1938",
        "CVE-2023-27524",
        "CVE-2021-43798"
      ]
    }
  ],
  "message": "",
  "query": "(tags:\"Umbraco baseUrl SSRF Attempt\" -classification:benign) last_seen:90d"
}
```
