# IP Lookup

Get more information about a given IP address. Returns time ranges, IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, activity tags, and raw port scan and web request information.

Use the `quick` parameter to return a subset of the response fields, for a faster response time.

## "Quick"

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v3/ip/118.69.124.186?quick=true' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

```json{
  "ip": "118.69.124.186",
  "business_service_intelligence": {
    "found": false,
    "trust_level": ""
  },
  "internet_scanner_intelligence": {
    "found": true,
    "classification": "suspicious"
  },
  "request_metadata": {
    "restricted_fields": []
  }
}
```

## Normal

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v3/ip/118.69.124.186?quick=false' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

``json
{
  "ip": "118.69.124.186",
  "business_service_intelligence": {
    "found": false,
    "category": "",
    "name": "",
    "description": "",
    "explanation": "",
    "last_updated": "",
    "reference": "",
    "trust_level": ""
  },
  "internet_scanner_intelligence": {
    "first_seen": "2022-09-14",
    "last_seen": "2025-09-19",
    "found": true,
    "tags": [
      {
        "id": "5b840bfd-4377-4b9d-b2a2-beb8ddedc823",
        "slug": "smbv1-scanner",
        "name": "SMBv1 Crawler",
        "description": "IP addresses with this tag have been observed crawling the internet for SMBv1.",
        "category": "activity",
        "intention": "suspicious",
        "references": [
          "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f"
        ],
        "cves": [],
        "recommend_block": false,
        "created": "2021-04-02",
        "updated_at": "2025-09-19T17:27:21.002041Z"
      }
    ],
    "actor": "unknown",
    "spoofable": false,
    "classification": "suspicious",
    "cves": [],
    "bot": false,
    "vpn": false,
    "vpn_service": "",
    "tor": false,
    "metadata": {
      "asn": "AS18403",
      "source_country": "Vietnam",
      "source_country_code": "VN",
      "source_city": "Ho Chi Minh City",
      "domain": "fpt.vn",
      "rdns_parent": "",
      "rdns_validated": false,
      "organization": "FPT Telecom Company",
      "category": "isp",
      "rdns": "",
      "os": "",
      "sensor_count": 7,
      "sensor_hits": 239018,
      "region": "Ho Chi Minh City (HCMC)",
      "mobile": false,
      "single_destination": false,
      "destination_countries": [
        "Turkey",
        "United States",
        "Lithuania"
      ],
      "destination_country_codes": [
        "TR",
        "US",
        "LT"
      ],
      "destination_asns": [
        "AS44477",
        "AS14061",
        "AS209847",
        "AS14618"
      ],
      "destination_cities": [
        "Istanbul",
        "Santa Clara",
        "Vilnius",
        "Ashburn"
      ],
      "carrier": "",
      "datacenter": "",
      "longitude": 106.6296,
      "latitude": 10.823
    },
    "raw_data": {
      "scan": [
        {
          "port": 445,
          "protocol": "tcp"
        },
        {
          "port": 65533,
          "protocol": "tcp"
        }
      ],
      "ja3": [],
      "hassh": [],
      "http": {
        "md5": [],
        "cookie_keys": [],
        "request_authorization": [],
        "request_cookies": [],
        "request_header": [],
        "method": [],
        "path": [],
        "request_origin": [],
        "useragent": []
      },
      "source": {
        "bytes": 13222576
      },
      "tls": {
        "cipher": [],
        "ja4": []
      },
      "ssh": {
        "key": []
      }
    },
    "last_seen_timestamp": "2025-09-19 17:01:34"
  },
  "request_metadata": {
    "restricted_fields": []
  }
}
```

# IP Lookup - Multi

Retrieves information about the submitted set of IP addresses from the Internet Scanner and Business Service intelligence datasets (consolidated response based on subscription entitlements). Returns time ranges, IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, tags, raw port scan data, web request information, classification and/or trust level, and provider information.

Use the `quick` parameter to return a subset of the response fields, for a faster response time.

Can process up to 10,000 IPs per request.

## Quick

Request:

```bash
curl --request POST \
     --url 'https://api.greynoise.io/v3/ip?quick=true' \
     --header 'accept: application/json' \
     --header 'content-type: application/json' \
     --header 'key: GREYNOISE_API_KEY' \
     --data '
{
  "ips": [
    "210.79.154.193",
    "138.197.64.95",
    "45.141.86.201"
  ]
}
'
```

Response:

```bash
{
  "data": [
    {
      "ip": "8.8.8.8",
      "business_service_intelligence": {
        "found": true,
        "category": "hosting",
        "name": "example.com",
        "description": "example.com",
        "explanation": "string",
        "last_updated": "2025-01-15T12:30:45Z",
        "reference": "https://example.com",
        "trust_level": "string"
      },
      "internet_scanner_intelligence": {
        "ip": "71.6.135.131",
        "seen": true,
        "classification": "benign",
        "first_seen": "2018-01-28",
        "last_seen": "2018-2-28",
        "last_seen_timestamp": [
          "2025-01-15T12:30:45Z"
        ],
        "found": true,
        "actor": "Shodan.io",
        "bot": false,
        "spoofable": true,
        "cves": [
          "CVE-2020-1234",
          "CVE-2021-2345"
        ],
        "tor": false,
        "vpn": true,
        "vpn_service": "IPVANISH_VPN",
        "metadata": {
          "mobile": false,
          "source_country": "United States",
          "source_country_code": "US",
          "source_city": "Seattle",
          "region": "Seattle",
          "organization": "DigitalOcean, LLC",
          "rdns": "crawl-66-249-79-17.googlebot.com",
          "asn": "AS521",
          "tor": false,
          "category": "education",
          "os": "Windows 7/8",
          "destination_countries": [
            "Germany"
          ],
          "destination_country_codes": [
            "Germany"
          ],
          "destination_cities": [
            "Berlin"
          ],
          "destination_asns": [
            "AS1234"
          ],
          "single_destination": true,
          "carrier": "AIS",
          "datacenter": "us-west-1",
          "domain": "example.com",
          "rdns_parent": "example.com",
          "rdns_validated": true,
          "latitude": 37.7749,
          "longitude": -122.4194,
          "sensor_count": 10,
          "sensor_hits": 10
        },
        "tags": {
          "id": "ef0cc90d-d80c-436f-92c5-3d8f8665c9ac",
          "slug": "mirai",
          "name": "Mirai",
          "category": "worm",
          "intention": "malicious",
          "description": "This IP address exhibits behavior that indicates it is infected with Mirai or a Mirai-like variant of malware.",
          "references": [
            "https://en.wikipedia.org/wiki/Mirai_(malware)"
          ],
          "recommend_block": false,
          "cves": [
            "CVE-2020-1234"
          ],
          "created_at": "2020-04-07",
          "updated_at": "2020-04-07"
        },
        "raw_data": {
          "scan": [
            {
              "port": 80,
              "protocol": "TCP"
            }
          ],
          "ja3": [
            {
              "fingerprint": "c3a6cf0bf2e690ac8e1ecf6081f17a50",
              "port": 443
            }
          ],
          "hassh": [
            {
              "fingerprint": "51cba57125523ce4b9db67714a90bf6e",
              "port": 2222
            }
          ],
          "http": {
            "md5": "9764955b67107eeb9edfae76f429e783",
            "cookie_keys": [
              [
                "expremotekey"
              ]
            ],
            "request_authorization": [
              [
                "Bearer exampletoken",
                "Basic username:password"
              ]
            ],
            "request_cookies": [
              [
                "session_id=1234567890"
              ]
            ],
            "request_header": [
              [
                "Content-Type: application/json",
                "Accept: application/json"
              ]
            ],
            "method": [
              [
                "GET",
                "POST",
                "PUT",
                "DELETE"
              ]
            ],
            "request_origin": [
              [
                "111.111.1.1"
              ]
            ],
            "host": [
              [
                "example.com",
                "example.com:8080"
              ]
            ],
            "uri": [
              "string"
            ],
            "path": [
              "/robots.txt"
            ],
            "useragent": [
              "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\n"
            ]
          },
          "tls": {
            "cipher": "TLS_AES_128_GCM_SHA256",
            "ja4": [
              "TLS_AES_128_GCM_SHA256",
              "TLS_AES_256_GCM_SHA384",
              "TLS_CHACHA20_POLY1305_SHA256"
            ]
          },
          "ssh": {
            "key": [
              [
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1234567890"
              ]
            ]
          },
          "source": {
            "bytes": 1024
          }
        }
      }
    }
  ],
  "request_metadata": {
    "restricted_fields": [
      [
        "ip",
        "cve",
        "destination_cities"
      ]
    ],
    "message": "ok",
    "ips_not_found": [
      "string"
    ]
  }
}
```

## Normal

Request:

```bash
curl --request POST \
     --url 'https://api.greynoise.io/v3/ip?quick=false' \
     --header 'accept: application/json' \
     --header 'content-type: application/json' \
     --header 'key: GREYNOISE_API_KEY' \
     --data '
{
  "ips": [
    "210.79.154.193",
    "138.197.64.95",
    "45.141.86.201"
  ]
}
'
```

Response:

```json
{
  "data": [
    {
      "ip": "210.79.154.193",
      "business_service_intelligence": {
        "found": false,
        "category": "",
        "name": "",
        "description": "",
        "explanation": "",
        "last_updated": "",
        "reference": "",
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "first_seen": "2025-09-19",
        "last_seen": "2025-09-19",
        "found": true,
        "tags": [],
        "actor": "unknown",
        "spoofable": false,
        "classification": "unknown",
        "cves": [],
        "bot": false,
        "vpn": false,
        "vpn_service": "",
        "tor": false,
        "metadata": {
          "asn": "AS38136",
          "source_country": "Taiwan",
          "source_country_code": "TW",
          "source_city": "Taipei",
          "domain": "akari.hk",
          "rdns_parent": "",
          "rdns_validated": false,
          "organization": "Akari Networks",
          "category": "hosting",
          "rdns": "",
          "os": "",
          "sensor_count": 1147,
          "sensor_hits": 328268,
          "region": "Taiwan",
          "mobile": false,
          "single_destination": false,
          "destination_countries": [
            "Spain",
            "United States",
            "Belgium",
            "Croatia",
            "Estonia",
            "Hungary",
            "Ireland",
            "Japan",
            "Kenya",
            "Mexico",
            "Poland",
            "Switzerland",
            "United Kingdom"
          ],
          "destination_country_codes": [
            "ES",
            "US",
            "BE",
            "CH",
            "EE",
            "GB",
            "HR",
            "HU",
            "IE",
            "JP",
            "KE",
            "MX",
            "PL"
          ],
          "destination_asns": [
            "AS174",
            "AS6939",
            "AS1257",
            "AS138915",
            "AS20473",
            "AS206804",
            "AS209847",
            "AS210772",
            "AS35487",
            "AS57695",
            "AS63949"
          ],
          "destination_cities": [
            "New Orleans",
            "San Sebastián de los Reyes",
            "Federal Way",
            "Washington",
            "Minneapolis",
            "Englewood",
            "Brussels",
            "Budapest",
            "Dublin",
            "London",
            "Mexico City",
            "Nairobi",
            "Santa Clara",
            "Tallinn",
            "Warsaw",
            "Zagreb",
            "Zürich",
            "Ōi"
          ],
          "carrier": "",
          "datacenter": "",
          "longitude": 121.5264,
          "latitude": 25.0531
        },
        "raw_data": {
          "scan": [
            {
              "port": 60443,
              "protocol": "tcp"
            },
            {
              "port": 61443,
              "protocol": "tcp"
            },
            {
              "port": 62443,
              "protocol": "tcp"
            },
            {
              "port": 63443,
              "protocol": "tcp"
            },
            {
              "port": 64443,
              "protocol": "tcp"
            }
          ],
          "ja3": [
            {
              "fingerprint": "2bb8066f8aef758fe0ebdf26ce012609",
              "port": 2007
            }
          ],
          "hassh": [],
          "http": {
            "md5": [
              "690e440f039d37e8098f20406f460c11",
              "9e076f5885f5cc16a4b5aeb8de4adff5",
              "2621b0025eba08059205075d7ce110cf",
              "b55993cb73060a58d829dc134ca2be09",
              "25f0a280e78a5af11b772eb762d28bab",
              "34509c73e9bc6e921e9cff5ee2a2bc0c",
              "b16e82a23b57020293a22a59e0ccc534",
              "f4b6a035314eb57b5e571ce37abc18bc",
              "659aa5f8d3bba3c217a51da6e45e4146",
              "9bbc6056e65aae588c2d21601264e65a",
              "8bfa7c4473cfc2afa0520ad784a1cf08",
              "7f62012bda49b7bf438e680b265a856e",
              "2bc1ec49979842cac97e7127e246dc27"
            ],
            "cookie_keys": [],
            "request_authorization": [],
            "request_cookies": [],
            "request_header": [
              "user-agent",
              "host",
              "accept-language",
              "accept",
              "referer"
            ],
            "method": [
              "GET"
            ],
            "path": [
              "/RDWeb/Pages/",
              "/+CSCOE+/logon.html",
              "/remote/login",
              "/",
              "/auth.html",
              "/sslvpn",
              "/global-protect/login.esp",
              "/cgi-bin/userLogin",
              "/vpn/index.html",
              "/WebInterface/login.html"
            ],
            "request_origin": [],
            "useragent": [
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
            ]
          },
          "source": {
            "bytes": 110680508
          },
          "tls": {
            "cipher": [
              "TLS_AES_128_GCM_SHA256"
            ],
            "ja4": [
              "t13i131000_f57a46bbacb6_2dd10c1a5aba",
              "t13i131100_f57a46bbacb6_9249cab70c77",
              "t13i131200_f57a46bbacb6_7e55ffd90fc1"
            ]
          },
          "ssh": {
            "key": []
          }
        },
        "last_seen_timestamp": "2025-09-19 17:01:04"
      }
    },
    {
      "ip": "138.197.64.95",
      "business_service_intelligence": {
        "found": false,
        "category": "",
        "name": "",
        "description": "",
        "explanation": "",
        "last_updated": "",
        "reference": "",
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "first_seen": "2024-07-19",
        "last_seen": "2025-09-19",
        "found": true,
        "tags": [
          {
            "id": "f620e81c-eaf4-477f-8bc4-ec94ca672615",
            "slug": "generic-iot-default-password-attempt",
            "name": "Generic IoT Default Password Attempt",
            "description": "IP addresses with this tag have been observed attempting to bruteforce IoT devices through telnet or SSH with generic default credentials shared across a wide variety of devices.",
            "category": "activity",
            "intention": "malicious",
            "references": [
              "https://gist.github.com/gabonator/74cdd6ab4f733ff047356198c781f27d"
            ],
            "cves": [],
            "recommend_block": true,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:13.043301Z"
          },
          {
            "id": "ef0cc90d-d80c-436f-92c5-3d8f8665c9ac",
            "slug": "mirai-attempt",
            "name": "Mirai",
            "description": "IP addresses with this tag exhibit behavior that indicates they are infected with Mirai or a Mirai-like variant of malware.",
            "category": "worm",
            "intention": "malicious",
            "references": [
              "https://en.wikipedia.org/wiki/Mirai_(malware)"
            ],
            "cves": [],
            "recommend_block": true,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:17.111944Z"
          },
          {
            "id": "0b84249e-c086-4378-9bc2-66dd8e89ae8a",
            "slug": "mirai-tcp-scanner",
            "name": "Mirai TCP Scanner",
            "description": "IP addresses with this tag exhibit behavior that indicates they are infected with Mirai or a Mirai-like variant of malware.",
            "category": "worm",
            "intention": "malicious",
            "references": [
              "https://en.wikipedia.org/wiki/Mirai_(malware)"
            ],
            "cves": [],
            "recommend_block": true,
            "created": "2024-10-18",
            "updated_at": "2025-09-19T17:27:17.158543Z"
          },
          {
            "id": "db896d7c-6acc-446a-9715-a8bdc2c24618",
            "slug": "telnet-bruteforcer-attempt",
            "name": "Telnet Bruteforcer",
            "description": "IP addresses with this tag have been observed attempting to bruteforce Telnet server credentials.",
            "category": "activity",
            "intention": "malicious",
            "references": [],
            "cves": [],
            "recommend_block": true,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:21.97908Z"
          },
          {
            "id": "6eb3f0fa-869a-4276-a727-bafa51c3e0e3",
            "slug": "telnet-login-attempt",
            "name": "Telnet Login Attempt",
            "description": "IP addresses with this tag have been observed attempting to authenticate to a Telnet server.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Telnet"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-09-30",
            "updated_at": "2025-09-19T17:27:22.005274Z"
          }
        ],
        "actor": "unknown",
        "spoofable": false,
        "classification": "malicious",
        "cves": [],
        "bot": false,
        "vpn": false,
        "vpn_service": "",
        "tor": false,
        "metadata": {
          "asn": "AS14061",
          "source_country": "United States",
          "source_country_code": "US",
          "source_city": "Clifton",
          "domain": "digitalocean.com",
          "rdns_parent": "",
          "rdns_validated": false,
          "organization": "DigitalOcean, LLC",
          "category": "hosting",
          "rdns": "",
          "os": "",
          "sensor_count": 780,
          "sensor_hits": 5358395,
          "region": "New Jersey",
          "mobile": false,
          "single_destination": false,
          "destination_countries": [
            "United States",
            "Spain",
            "Germany",
            "India",
            "Mexico",
            "Japan",
            "Singapore",
            "France",
            "United Kingdom",
            "Indonesia",
            "South Korea",
            "Brazil",
            "Israel",
            "Peru",
            "Norway",
            "Switzerland",
            "Luxembourg",
            "Hong Kong",
            "Australia",
            "Slovenia",
            "Austria",
            "Russia",
            "Canada",
            "Turkey",
            "Finland",
            "Taiwan",
            "United Arab Emirates",
            "Belgium",
            "Belarus",
            "Kenya",
            "Ireland",
            "South Africa",
            "Chile",
            "Netherlands",
            "Iraq",
            "Latvia",
            "Pakistan",
            "Bulgaria",
            "Denmark",
            "Portugal",
            "Qatar",
            "Czech Republic",
            "New Zealand",
            "Malaysia",
            "Colombia",
            "Moldova",
            "Croatia",
            "Ukraine",
            "Hungary",
            "Kazakhstan",
            "Kuwait",
            "Romania"
          ],
          "destination_country_codes": [
            "US",
            "ES",
            "DE",
            "IN",
            "MX",
            "JP",
            "SG",
            "FR",
            "GB",
            "ID",
            "KR",
            "BR",
            "IL",
            "PE",
            "NO",
            "CH",
            "LU",
            "HK",
            "AU",
            "SI",
            "AT",
            "RU",
            "CA",
            "TR",
            "FI",
            "AE",
            "TW",
            "BE",
            "BY",
            "KE",
            "IE",
            "ZA",
            "CL",
            "NL",
            "IQ",
            "LV",
            "PK",
            "BG",
            "DK",
            "PT",
            "QA",
            "CZ",
            "NZ",
            "MY",
            "CO",
            "MD",
            "HR",
            "UA",
            "HU",
            "KW",
            "KZ",
            "RO"
          ],
          "destination_asns": [
            "AS174",
            "AS396982",
            "AS6939",
            "AS16509",
            "AS63949",
            "AS20473",
            "AS14061",
            "AS206804",
            "AS8075",
            "AS45102",
            "AS44477",
            "AS138915",
            "AS14618",
            "AS57169",
            "AS61138",
            "AS35487",
            "AS57578",
            "AS56740",
            "AS209847",
            "AS61317",
            "AS44812",
            "AS50979",
            "AS204957",
            "AS59729",
            "AS7195",
            "AS57695",
            "AS7590",
            "AS9678",
            "AS49720",
            "AS15626",
            "AS210772"
          ],
          "destination_cities": [
            "Washington",
            "San Sebastián de los Reyes",
            "Federal Way",
            "New Orleans",
            "Englewood",
            "Columbus",
            "Frankfurt am Main",
            "Mumbai",
            "Council Bluffs",
            "Tokyo",
            "General Lázaro Cárdenas",
            "Singapore",
            "North Charleston",
            "Paris",
            "London",
            "Jakarta",
            "Los Angeles",
            "Seoul",
            "Indianapolis",
            "Newark",
            "Santa Clara",
            "Boardman",
            "Ashburn",
            "Virginia Beach",
            "São Paulo",
            "Santiago de Querétaro",
            "Salt Lake City",
            "Petaẖ Tiqva",
            "Fremont",
            "Lima",
            "Oslo",
            "Zürich",
            "Luxembourg",
            "Minneapolis",
            "Hong Kong",
            "Ljubljana",
            "Sydney",
            "New York City",
            "Vienna",
            "Cedar Knolls",
            "The Dalles",
            "Istanbul",
            "Las Vegas",
            "Chicago",
            "Lappeenranta",
            "North Bergen",
            "Dubai",
            "Taipei",
            "Brussels",
            "Richardson",
            "Minsk",
            "Nairobi",
            "Toronto",
            "Osaka",
            "Saint Petersburg",
            "Dublin",
            "Johannesburg",
            "Santiago",
            "Baghdad",
            "Riga",
            "Copenhagen",
            "Sofia",
            "St. Louis",
            "Braga",
            "Philadelphia",
            "Moscow",
            "Nashville",
            "San Antonio",
            "Doha",
            "Elk Grove Village",
            "Miami",
            "Chennai",
            "Cheyenne",
            "Leesburg",
            "Mount Eden",
            "Piscataway",
            "Prague",
            "Groningen",
            "Karachi",
            "Kuala Lumpur",
            "Melbourne",
            "Barrio San Luis",
            "Mexico City",
            "Ōi",
            "Chisinau",
            "Incheon",
            "Kansas City",
            "Meppel",
            "Montréal",
            "Rawalpindi",
            "Atlanta",
            "Pune",
            "Zagreb",
            "Bāshettihalli",
            "Kyiv",
            "Almaty",
            "Amsterdam",
            "Bucharest",
            "Budapest",
            "Cape Town",
            "Haarlem",
            "Kent",
            "Kuwait City",
            "Osasco"
          ],
          "carrier": "",
          "datacenter": "",
          "longitude": -74.1377,
          "latitude": 40.8344
        },
        "raw_data": {
          "scan": [
            {
              "port": 23,
              "protocol": "tcp"
            }
          ],
          "ja3": [],
          "hassh": [],
          "http": {
            "md5": [],
            "cookie_keys": [],
            "request_authorization": [],
            "request_cookies": [],
            "request_header": [],
            "method": [],
            "path": [],
            "request_origin": [],
            "useragent": []
          },
          "source": {
            "bytes": 291744542
          },
          "tls": {
            "cipher": [],
            "ja4": []
          },
          "ssh": {
            "key": []
          }
        },
        "last_seen_timestamp": "2025-09-19 17:00:36"
      }
    }
  ],
  "request_metadata": {
    "restricted_fields": [],
    "message": "",
    "ips_not_found": []
  }
}
```

# GNQL Stats

Get aggregate statistics for the top organizations, actors, tags, ASNs, countries, classifications, and operating systems of all the results of a given GNQL query.

Query Params:

- query: string; GNQL query string (required) 
- count: integer; 1 to 10000 (Defaults to 1000)

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v2/experimental/gnql/stats?query=classification%3A%20malicious&count=5' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

```json
{
  "count": 1885442,
  "query": "classification: malicious",
  "adjusted_query": "(classification: malicious) last_seen:90d",
  "stats": {
    "classifications": [
      {
        "classification": "malicious",
        "count": 1885442
      }
    ],
    "spoofable": [
      {
        "spoofable": false,
        "count": 1610116
      },
      {
        "spoofable": true,
        "count": 275326
      }
    ],
    "organizations": [
      {
        "organization": "National Internet Backbone",
        "count": 280790
      },
      {
        "organization": "TE-AS",
        "count": 122177
      },
      {
        "organization": "CHINA UNICOM China169 Backbone",
        "count": 102094
      },
      {
        "organization": "CHINANET-BACKBONE",
        "count": 68867
      },
      {
        "organization": "Administracion Nacional de Telecomunicaciones",
        "count": 59391
      }
    ],
    "actors": [
      {
        "actor": "Stretchoid",
        "count": 1165
      },
      {
        "actor": "LeakIX",
        "count": 57
      },
      {
        "actor": "Recyber Project",
        "count": 25
      },
      {
        "actor": "XMCO.fr",
        "count": 17
      }
    ],
    "countries": [
      {
        "country": "India",
        "count": 350099
      },
      {
        "country": "Brazil",
        "count": 256206
      },
      {
        "country": "China",
        "count": 210519
      },
      {
        "country": "Egypt",
        "count": 125007
      },
      {
        "country": "United States",
        "count": 69772
      }
    ],
    "source_countries": [
      {
        "country": "India",
        "count": 350099
      },
      {
        "country": "Brazil",
        "count": 256206
      },
      {
        "country": "China",
        "count": 210519
      },
      {
        "country": "Egypt",
        "count": 125007
      },
      {
        "country": "United States",
        "count": 69772
      }
    ],
    "destination_countries": [
      {
        "country": "United States",
        "count": 1659543
      },
      {
        "country": "United Kingdom",
        "count": 709356
      },
      {
        "country": "Spain",
        "count": 615317
      },
      {
        "country": "Germany",
        "count": 491597
      },
      {
        "country": "India",
        "count": 434045
      }
    ],
    "tags": [
      {
        "tag": "Telnet Login Attempt",
        "id": "6eb3f0fa-869a-4276-a727-bafa51c3e0e3",
        "count": 805096
      },
      {
        "tag": "Telnet Bruteforcer",
        "id": "db896d7c-6acc-446a-9715-a8bdc2c24618",
        "count": 764188
      },
      {
        "tag": "Mirai",
        "id": "ef0cc90d-d80c-436f-92c5-3d8f8665c9ac",
        "count": 740504
      },
      {
        "tag": "Mirai TCP Scanner",
        "id": "0b84249e-c086-4378-9bc2-66dd8e89ae8a",
        "count": 723049
      },
      {
        "tag": "Web Crawler",
        "id": "869feaa1-dc77-4037-aee2-247b7a39cf7d",
        "count": 686827
      }
    ],
    "operating_systems": null,
    "categories": [
      {
        "category": "isp",
        "count": 1695847
      },
      {
        "category": "hosting",
        "count": 160214
      },
      {
        "category": "business",
        "count": 16162
      },
      {
        "category": "education",
        "count": 1944
      }
    ],
    "asns": [
      {
        "asn": "AS9829",
        "count": 280790
      },
      {
        "asn": "AS8452",
        "count": 122177
      },
      {
        "asn": "AS4837",
        "count": 102094
      },
      {
        "asn": "AS4134",
        "count": 68867
      },
      {
        "asn": "AS6057",
        "count": 59391
      }
    ]
  }
}
```

# GNQL Query

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
- `quick`: If true, the response will only include the IP address and the classification or trust level. (Default is `false`)

## Quick

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v3/gnql?query=tags%3A%22MCP%20and%20SSE%20endpoint%20scanning%22%20classification%3Amalicious&size=5&quick=true' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

```json
{
  "data": [
    {
      "ip": "128.14.237.130",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    },
    {
      "ip": "152.32.206.64",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    },
    {
      "ip": "118.193.64.186",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    },
    {
      "ip": "152.32.135.214",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    },
    {
      "ip": "165.154.119.20",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    }
  ],
  "request_metadata": {
    "restricted_fields": [],
    "scroll": "FGluY2x1ZGVfY29udGV4dF91dWlkDnF1ZXJ5VGhlbkZldGNoAhZZTHg2X2Z4OVJzLWVCcm13R1JreWZBAAAAAAZX0w4WT2hKVjdSZ2dTMzJhMzFPWHJuWl9vdxZrekhLaTlLNFFFSy1jWjZlbXNWN0NRAAAAAAaQvpgWajA0Z0tqdDdUX3UwNjF4TUJrLTk4dw==",
    "message": "",
    "query": "tags:\"MCP and SSE endpoint scanning\" classification:malicious",
    "complete": false,
    "count": 147,
    "adjusted_query": "(tags:\"MCP and SSE endpoint scanning\" classification:malicious) last_seen:90d"
  }
}
```

## Normal:

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v3/gnql?query=tags%3A%22MCP%20and%20SSE%20endpoint%20scanning%22%20classification%3Amalicious&size=1&quick=false' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

```json
{
  "data": [
    {
      "ip": "128.14.237.130",
      "business_service_intelligence": {
        "found": false,
        "category": "",
        "name": "",
        "description": "",
        "explanation": "",
        "last_updated": "",
        "reference": "",
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "first_seen": "2023-08-31",
        "last_seen": "2025-09-19",
        "found": true,
        "tags": [
          {
            "id": "1a2da3d3-57d6-4030-b686-a1fbdafa5987",
            "slug": "azure-omi-rce-check",
            "name": "Azure OMI RCE Check",
            "description": "IP addresses with this tag have been observed scanning the internet for WSMan Powershell providers without an Authorization header, but has not provided a valid SOAP XML Envelope payload.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38649",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38645",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38648",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38647",
              "https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38647",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38648",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38645",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38649"
            ],
            "cves": [
              "CVE-2021-38647"
            ],
            "recommend_block": false,
            "created": "2021-09-16",
            "updated_at": "2025-09-19T17:27:29.982747Z"
          },
          {
            "id": "feb92353-4264-44ce-8f7d-8ddae93719da",
            "slug": "cgi-script-scanner",
            "name": "CGI Script Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for CGI scripts.",
            "category": "activity",
            "intention": "malicious",
            "references": [
              "https://en.wikipedia.org/wiki/Common_Gateway_Interface"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:10.441654Z"
          },
          {
            "id": "79f609f0-4d07-455d-b9b1-56ff7c1a77a9",
            "slug": "carries-http-referer-scanner",
            "name": "Carries HTTP Referer",
            "description": "IP addresses with this tag have been observed scanning the internet with an HTTP client that includes the Referer header in their requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-19",
            "updated_at": "2025-09-19T17:27:10.312905Z"
          },
          {
            "id": "8cdc09c8-15b3-40b2-8eb7-96acdf89c323",
            "slug": "cisco-smart-install-endpoint-scanner",
            "name": "Cisco Smart Install Endpoint Scanner",
            "description": "IP addresses with this tag have been observed scanning for exposed Cisco Smart Install Protocol ports.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.rapid7.com/db/modules/auxiliary/scanner/misc/cisco_smart_install",
              "https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/misc/cisco_smart_install.rb",
              "https://github.com/frostbits-security/SIET/blob/master/cisco-siet.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:10.710733Z"
          },
          {
            "id": "cf2b9808-8f8b-480e-94eb-7a8b5c168398",
            "slug": "citrix-adc-gateway-login-panel-crawler",
            "name": "Citrix ADC Gateway Login Panel Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover Internet-facing Citrix ADC Gateway login pages.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.netscaler.com/en-us/citrix-adc.html",
              "https://github.com/adysec/nuclei_poc/blob/main/poc/detect/citrix-adc-gateway-detect.yaml"
            ],
            "cves": [],
            "recommend_block": true,
            "created": "2025-08-15",
            "updated_at": "2025-09-19T17:27:10.758758Z"
          },
          {
            "id": "f97736ef-88b7-45bb-83b8-2b69b765e57a",
            "slug": "codesys-scanner",
            "name": "Codesys Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over Codesys programming interface.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/CODESYS",
              "https://www.codesys.com/products/codesys-communication/standard-ethernet.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-15",
            "updated_at": "2025-09-19T17:27:11.042796Z"
          },
          {
            "id": "9fa91f79-14be-4a68-aee1-1e830ab62243",
            "slug": "crimson-v3-scanner",
            "name": "Crimson v3 Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover HMI devices that respond via Red Lion Controls Crimson v3 programming interface.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.redlion.net/red-lion-software/crimson/crimson-30",
              "https://github.com/internetofallthethings/cr3-nmap/blob/master/cr3-fingerprint.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-26",
            "updated_at": "2025-09-19T17:27:11.25553Z"
          },
          {
            "id": "29036263-e7ab-411a-984d-bbb15f0dea1c",
            "slug": "crushftp-scanner",
            "name": "CrushFTP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover publicly accessible CrushFTP web interfaces.  This scanning could be related to CVE-2024-4040.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.crushftp.com/index.html",
              "http://web.archive.org/web/20241215003801/https://attackerkb.com/topics/20oYjlmfXa/cve-2024-4040/rapid7-analysis"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-04-22",
            "updated_at": "2025-09-19T17:27:11.274628Z"
          },
          {
            "id": "389ee453-fdac-4a23-aad5-e9daded96543",
            "slug": "cryptocurrency-node-scanner",
            "name": "Cryptocurrency Node Scanner",
            "description": "IP addresses with this tag have been observed attempting to locate cryptocurrency nodes using JSON-RPC.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/ethereum/wiki/wiki/JSON-RPC",
              "https://en.bitcoin.it/wiki/API_reference_(JSON-RPC)"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:11.31479Z"
          },
          {
            "id": "88c01626-5fc9-4f0a-b39f-b57331ded73e",
            "slug": "ehlo-scanner",
            "name": "EHLO Crawler",
            "description": "IP addresses with this tag have been observed scanning the Internet for services that respond to a generic EHLO request.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-11-30",
            "updated_at": "2025-09-19T17:27:12.1033Z"
          },
          {
            "id": "208534a2-274c-4ccf-9fa8-30a61e5c5696",
            "slug": "erlang-port-mapper-daemon-crawler",
            "name": "Erlang Port Mapper Daemon Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover hosts involved in distributed Erlang computations.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://svn.nmap.org/nmap/scripts/epmd-info.nse",
              "http://web.archive.org/web/20240419152645/https://www.erlang.org/doc/man/epmd.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-09-06",
            "updated_at": "2025-09-19T17:27:12.285271Z"
          },
          {
            "id": "1552ec97-eb19-421e-b772-847d7f2d310c",
            "slug": "ethernet-ip-scanner",
            "name": "EtherNet/IP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over EtherNet/IP protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/EtherNet/IP",
              "https://literature.rockwellautomation.com/idc/groups/literature/documents/wp/enet-wp001_-en-p.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T17:27:12.34378Z"
          },
          {
            "id": "cca2496c-fa04-48cb-afaa-c0a76a613619",
            "slug": "favicon-scanner",
            "name": "Favicon Scanner",
            "description": "IP addresses with this tag have been observed checking for the existence of a 'favicon' file on the web server.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://en.wikipedia.org/wiki/Favicon",
              "https://www.w3schools.com/html/html_favicon.asp",
              "https://www.securityhq.com/blog/using-favicon-hashes-to-spot-vulnerabilities/",
              "https://www.ndss-symposium.org/wp-content/uploads/madweb2021_23009_paper.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-11-11",
            "updated_at": "2025-09-19T17:27:12.649906Z"
          },
          {
            "id": "ae5f3238-716b-4a8c-8841-d5a0bf24c73a",
            "slug": "firebirdsql-scanner",
            "name": "FirebirdSQL Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet and attempting to discover FirebirdSQL instances.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/misc/fb_cnct_group.rb",
              "https://svn.nmap.org/nmap/nmap-service-probes"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-06",
            "updated_at": "2025-09-19T17:27:12.747461Z"
          },
          {
            "id": "3d144850-efcc-436a-9008-c5d28ac581ae",
            "slug": "go-http-client-scanner",
            "name": "Go HTTP Client",
            "description": "IP addresses with this tag have been observed scanning the Internet using the Golang HTTP Client.",
            "category": "tool",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:13.533836Z"
          },
          {
            "id": "7ad1354b-800a-4c8d-9f35-b7fc4720c870",
            "slug": "ibm-tn-3270-mainframe-scanner",
            "name": "IBM TN-3270 Mainframe Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet for IBM TN-3270 Mainframes.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/IBM_3270"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:14.625631Z"
          },
          {
            "id": "c849922e-bb9c-412e-a819-6999ab8ad862",
            "slug": "jrmi-scanner",
            "name": "JRMI Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for exposed Java Remote Method Invocation (JRMI) endpoints.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.oracle.com/javase/tutorial/rmi/index.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:15.888118Z"
          },
          {
            "id": "fe34d80c-4d62-4b39-afa4-469494292c7f",
            "slug": "mcp-and-sse-endpoint-scanning",
            "name": "MCP and SSE endpoint scanning",
            "description": "IP addresses with this tag have been observed scanning for Model Context Protocol (MCP) and Server-Sent Events (SSE).",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://hexdocs.pm/mcp_sse/readme.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-06-04",
            "updated_at": "2025-09-19T17:27:16.697748Z"
          },
          {
            "id": "8c5ec3d6-ed9b-4463-a3b3-f358d1fa1c57",
            "slug": "melsec-q-scanner",
            "name": "MELSEC-Q Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover Mitsubishi Electric ICS devices that respond over MELSEC-Q protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.mitsubishielectric.com/fa/products/cnt/plcq/items/index.html",
              "http://web.archive.org/web/20220525232903/http://dl.mitsubishielectric.com/dl/fa/document/manual/school_text/sh080618eng/sh080618enga.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T17:27:16.724069Z"
          },
          {
            "id": "169ff7a3-aab6-4242-a88c-290246f99fae",
            "slug": "mqtt-protocol-scanner",
            "name": "MQTT Protocol Scanner",
            "description": "IP addresses with this tag have been observed scanning the internet for responses used by the MQTT protocol for Internet of Things devices.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20230101140347/https://openlabpro.com/guide/mqtt-packet-format/"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-03-10",
            "updated_at": "2025-09-19T17:27:17.428531Z"
          },
          {
            "id": "fddc4698-fb29-4fd6-946f-5598100fe716",
            "slug": "mssql-login-attempt",
            "name": "MSSQL Login Attempt",
            "description": "IP addresses with this tag have been observed attempting to perform a Microsoft SQL (MSSQL) login.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/7af53667-1b72-4703-8258-7984e838f746",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/ce5ad23f-6bf8-4fa5-9426-6b0d36e14da2"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-10-28",
            "updated_at": "2025-09-19T17:27:17.470226Z"
          },
          {
            "id": "9eacd23a-33c1-410d-86a7-0560c4e9d942",
            "slug": "microsoft-message-queuing-msmq-crawler",
            "name": "Microsoft Message Queuing (MSMQ) Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover Internet-facing Microsoft Windows devices that respond over Microsoft Message Queuing (MSMQ) binary protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Microsoft_Message_Queuing",
              "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/058cdeb4-7a3c-405b-989c-d32b9d6bddae"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-04-12",
            "updated_at": "2025-09-19T17:27:16.875146Z"
          },
          {
            "id": "72077e4d-2a5f-4a86-b2c1-6fdb19bc3645",
            "slug": "modbus-tcp-scanner",
            "name": "Modbus TCP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over Modbus TCP protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Modbus",
              "https://www.fernhillsoftware.com/help/drivers/modbus/modbus-protocol.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-15",
            "updated_at": "2025-09-19T17:27:17.292481Z"
          },
          {
            "id": "66edd69b-50b8-46de-b03c-b596a3d469ef",
            "slug": "pcworx-scanner",
            "name": "PCWorx Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over PCWorx protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://svn.nmap.org/nmap/scripts/pcworx-info.nse",
              "https://web.archive.org/web/20220421135319/https://sergiusechel.medium.com/misconfiguration-in-ilc-gsm-gprs-devices-leaves-over-1-200-ics-devices-vulnerable-to-attacks-over-82c2d4a91561"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T17:27:18.689135Z"
          },
          {
            "id": "8503c116-536a-4a12-bb77-c8250b6acf76",
            "slug": "phoenix-contact-plc-scanner",
            "name": "Phoenix Contact PLC Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet looking for Phoenix Contact PLCs.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20220415164534/http://select.phoenixcontact.com/phoenix/dwld/fl_il_24_bk_pac_um_e_6156_en_05.pdf?asid2=7757471351375"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:18.744077Z"
          },
          {
            "id": "affb73e2-5eb7-4528-99b8-6742a70a109f",
            "slug": "proconos-scanner",
            "name": "ProConOS Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that use ProConOS runtime system.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20220621165517/https://www.phoenixcontact.com/assets/downloads_ed/global/web_dwl_technical_info/db_en_proconos_embedded_clr_106495_en_01.pdf",
              "https://github.com/digitalbond/Redpoint/blob/master/proconos-info.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T17:27:19.222862Z"
          },
          {
            "id": "788eb4be-0ffc-438d-92d6-d700df4fef72",
            "slug": "python-requests-client-scanner",
            "name": "Python Requests Client",
            "description": "IP addresses with this tag have been observed scanning the Internet with a client that uses the Python Requests library.",
            "category": "tool",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:19.41099Z"
          },
          {
            "id": "222cf79e-08a2-400a-a0b8-1c716aa43ec4",
            "slug": "rdp-crawler",
            "name": "RDP Crawler",
            "description": "IP addresses with this tag have been observed crawling the internet for Remote Desktop Protocol (RDP) by intiating a connection request.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-02",
            "updated_at": "2025-09-19T17:27:19.62017Z"
          },
          {
            "id": "e23d491c-6abf-477b-9073-dd9879f46a98",
            "slug": "radmin-scanner",
            "name": "Radmin Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet to identify devices using the Radmin protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:19.557324Z"
          },
          {
            "id": "77069c85-09a3-4322-bbf3-aefda8d46ae7",
            "slug": "sip-options-scanner",
            "name": "SIP OPTIONS Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for SIP devices using OPTIONS requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://tools.ietf.org/html/rfc3261#section-11.1"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:20.830425Z"
          },
          {
            "id": "5b840bfd-4377-4b9d-b2a2-beb8ddedc823",
            "slug": "smbv1-scanner",
            "name": "SMBv1 Crawler",
            "description": "IP addresses with this tag have been observed crawling the internet for SMBv1.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-04-02",
            "updated_at": "2025-09-19T17:27:21.002041Z"
          },
          {
            "id": "e3539e1d-46eb-4c4d-b708-e99c3487d804",
            "slug": "spdy-alpn-negotiation-attempt",
            "name": "SPDY ALPN Negotiation Attempt",
            "description": "IP addresses with this tag have been observed using Application-Layer Protocol Negotiation (ALPN) in the attempt to establish SPDY connections.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://en.wikipedia.org/wiki/SPDY",
              "https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-08-08",
            "updated_at": "2025-09-19T17:27:21.48046Z"
          },
          {
            "id": "b1859b91-92d5-48d2-b43d-bbfd09db964d",
            "slug": "ssh-alternative-port-scanner",
            "name": "SSH Alternative Port Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet for SSH servers running on ports other than 22/TCP.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:21.686299Z"
          },
          {
            "id": "537cee16-c4a9-45cd-baf1-75963ab7bdd2",
            "slug": "ssh-connection-attempt",
            "name": "SSH Connection Attempt",
            "description": "IP addresses with this tag have been observed attempting to negotiate an SSH session.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Secure_Shell"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-09-30",
            "updated_at": "2025-09-19T17:27:21.744098Z"
          },
          {
            "id": "393fed60-f1eb-4376-af03-f92d966a54d6",
            "slug": "sitemap-crawler",
            "name": "Sitemap Crawler",
            "description": "IP addresses with this tag have been observed crawling for sitemap files.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://www.sitemaps.org/protocol.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-01-28",
            "updated_at": "2025-09-19T17:27:20.912464Z"
          },
          {
            "id": "567fdc14-d3ca-481e-9679-8c017dea4665",
            "slug": "t3-rmi-protocol-and-weblogic-version-check",
            "name": "T3 RMI Protocol and Weblogic Version Check",
            "description": "IP addresses with this tag have been observed checking for the T3 RMI protocol and Weblogic version.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/christophetd/nmap-nse-info/blob/master/test/data/weblogic-t3-info.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-05-11",
            "updated_at": "2025-09-19T17:27:21.934004Z"
          },
          {
            "id": "ac32bdeb-b49d-4079-9e6b-8fbca5e0addf",
            "slug": "tls-ssl-scanner",
            "name": "TLS/SSL Crawler",
            "description": "IP addresses with this tag have been observed attempting to opportunistically crawl the Internet and establish TLS/SSL connections.",
            "category": "activity",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:22.235015Z"
          },
          {
            "id": "869feaa1-dc77-4037-aee2-247b7a39cf7d",
            "slug": "web-scanner",
            "name": "Web Crawler",
            "description": "IP addresses with this tag have been seen crawling HTTP(S) servers around the Internet.",
            "category": "activity",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:27:23.500195Z"
          },
          {
            "id": "6c79246a-c56e-4dfa-85a8-b5239ade7f02",
            "slug": "x-server-connection-attempt",
            "name": "X Server CVE-1999-0526 Connection Attempt",
            "description": "IP addresses with this tag have been observed scanning the Internet for X11 servers with access control disabled, which allows for unauthenticated connections.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-1999-0526",
              "https://www.cvedetails.com/cve/CVE-1999-0526/"
            ],
            "cves": [
              "CVE-1999-0526"
            ],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T17:28:07.101034Z"
          },
          {
            "id": "eae8d97d-08c6-4d03-9405-8099cf85af56",
            "slug": "iscsi-scanner",
            "name": "iSCSI Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet and attempting to discover hosts that respond to iSCSI login requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.rfc-editor.org/rfc/rfc7143.html#section-11.2",
              "https://book.hacktricks.xyz/pentesting/3260-pentesting-iscsi"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-01-12",
            "updated_at": "2025-09-19T17:27:15.172557Z"
          },
          {
            "id": "215d03ae-6899-49dd-9167-4c22fe1e832d",
            "slug": "robots-txt-scanner",
            "name": "robots.txt Scanner",
            "description": "IP addresses with this tag have been observed checking for the existence of a 'robots.txt' file on the web server.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://datatracker.ietf.org/doc/html/rfc9309",
              "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
              "https://www.robotstxt.org/",
              "https://www.cloudflare.com/learning/bots/what-is-robots-txt/"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-10-05",
            "updated_at": "2025-09-19T17:27:19.73591Z"
          },
          {
            "id": "783551ed-1915-4771-8a4c-1c858dc02a6b",
            "slug": "sitemap-xml-crawler",
            "name": "sitemap.xml Crawler",
            "description": "IP addresses with this tag have been observed attempting to fetch a sitemap.xml file, which is a very common file used by search engines and crawlers.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://www.xml-sitemaps.com/",
              "https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-08-19",
            "updated_at": "2025-09-19T17:27:20.934563Z"
          }
        ],
        "actor": "unknown",
        "spoofable": false,
        "classification": "malicious",
        "cves": [
          "CVE-1999-0526",
          "CVE-2021-38647"
        ],
        "bot": false,
        "vpn": false,
        "vpn_service": "",
        "tor": false,
        "metadata": {
          "asn": "AS135377",
          "source_country": "Taiwan",
          "source_country_code": "TW",
          "source_city": "Taoyuan City",
          "domain": "ucloud.cn",
          "rdns_parent": "",
          "rdns_validated": false,
          "organization": "UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED",
          "category": "hosting",
          "rdns": "",
          "os": "",
          "sensor_count": 2762,
          "sensor_hits": 471289,
          "region": "Taiwan",
          "mobile": false,
          "single_destination": false,
          "destination_countries": [
            "United States",
            "Germany",
            "Spain",
            "Brazil",
            "Japan",
            "South Korea",
            "India",
            "United Kingdom",
            "Canada",
            "Australia",
            "Indonesia",
            "Singapore",
            "France",
            "Hong Kong",
            "Mexico",
            "Netherlands",
            "Switzerland",
            "Belgium",
            "Israel",
            "Taiwan",
            "United Arab Emirates",
            "Finland",
            "Ireland",
            "South Africa",
            "Malaysia",
            "Peru",
            "Ukraine",
            "Greece",
            "Pakistan",
            "Luxembourg",
            "Thailand",
            "Hungary",
            "Romania",
            "Latvia",
            "Chile",
            "New Zealand",
            "Bahrain",
            "Croatia",
            "Italy",
            "Poland",
            "Turkey",
            "Austria",
            "Norway",
            "Belarus",
            "Portugal",
            "Russia",
            "Bulgaria",
            "Ecuador",
            "Slovakia",
            "Czech Republic",
            "Qatar",
            "Kuwait",
            "Denmark",
            "Estonia",
            "Moldova",
            "Iraq",
            "Sweden",
            "Kazakhstan",
            "Kenya",
            "Saudi Arabia",
            "Lithuania",
            "Ghana",
            "Iceland",
            "Colombia",
            "Georgia",
            "Oman",
            "Cambodia",
            "Serbia",
            "Slovenia"
          ],
          "destination_country_codes": [
            "US",
            "DE",
            "ES",
            "BR",
            "JP",
            "KR",
            "IN",
            "GB",
            "CA",
            "AU",
            "ID",
            "SG",
            "FR",
            "HK",
            "MX",
            "CH",
            "NL",
            "BE",
            "IL",
            "AE",
            "TW",
            "FI",
            "IE",
            "ZA",
            "MY",
            "PE",
            "UA",
            "GR",
            "PK",
            "LU",
            "TH",
            "HU",
            "RO",
            "LV",
            "CL",
            "NZ",
            "BH",
            "HR",
            "IT",
            "PL",
            "TR",
            "AT",
            "NO",
            "BY",
            "PT",
            "RU",
            "BG",
            "EC",
            "SK",
            "CZ",
            "QA",
            "KW",
            "DK",
            "EE",
            "MD",
            "IQ",
            "SE",
            "KE",
            "KZ",
            "SA",
            "LT",
            "GH",
            "IS",
            "CO",
            "GE",
            "OM",
            "KH",
            "RS",
            "SI"
          ],
          "destination_asns": [
            "AS396982",
            "AS16509",
            "AS14061",
            "AS20473",
            "AS8075",
            "AS174",
            "AS63949",
            "AS45102",
            "AS6939",
            "AS44477",
            "AS138915",
            "AS35487",
            "AS14618",
            "AS209847",
            "AS206804",
            "AS61138",
            "AS44709",
            "AS62005",
            "AS50979",
            "AS57695",
            "AS204932",
            "AS202422",
            "AS210772",
            "AS15626",
            "AS16276",
            "AS57169",
            "AS7195",
            "AS56740",
            "AS57578",
            "AS7590",
            "AS49720",
            "AS204957",
            "AS61317",
            "AS136258",
            "AS1257",
            "AS50837",
            "AS327813",
            "AS59729",
            "AS9678",
            "AS23966",
            "AS57814"
          ],
          "destination_cities": [
            "Washington",
            "Frankfurt am Main",
            "Federal Way",
            "Englewood",
            "San Sebastián de los Reyes",
            "New Orleans",
            "São Paulo",
            "Columbus",
            "London",
            "Seoul",
            "Mumbai",
            "Salt Lake City",
            "Los Angeles",
            "Jakarta",
            "Singapore",
            "North Charleston",
            "Santa Clara",
            "Sydney",
            "Paris",
            "Hong Kong",
            "Ashburn",
            "Council Bluffs",
            "Indianapolis",
            "General Lázaro Cárdenas",
            "North Bergen",
            "Las Vegas",
            "Tokyo",
            "The Dalles",
            "Zürich",
            "Toronto",
            "Montréal",
            "Atlanta",
            "New York City",
            "Osaka",
            "Brussels",
            "Incheon",
            "Virginia Beach",
            "Taipei",
            "Boardman",
            "Dallas",
            "San Antonio",
            "San Jose",
            "Bāshettihalli",
            "Pune",
            "Dubai",
            "Dublin",
            "Chicago",
            "Elk Grove Village",
            "Cheyenne",
            "Kuala Lumpur",
            "Lima",
            "Amsterdam",
            "Kyiv",
            "Lappeenranta",
            "Piscataway",
            "Tel Aviv",
            "Luxembourg",
            "Petaẖ Tiqva",
            "Nashville",
            "Kent",
            "Newark",
            "St. Louis",
            "Bangkok",
            "Budapest",
            "Bucharest",
            "Miami",
            "Ōi",
            "Groningen",
            "Riga",
            "Santiago de Querétaro",
            "Santiago",
            "Cape Town",
            "Melbourne",
            "Mount Eden",
            "Cedar Knolls",
            "Karachi",
            "Dār Kulayb",
            "Zagreb",
            "Athens",
            "Fremont",
            "Milan",
            "Warsaw",
            "Haarlem",
            "Al Fujairah City",
            "Rawalpindi",
            "Istanbul",
            "Volos",
            "Oslo",
            "Braga",
            "Johannesburg",
            "Minsk",
            "Richardson",
            "Bratislava",
            "Quito",
            "Sofia",
            "Prague",
            "Saint Petersburg",
            "Aubervilliers",
            "Doha",
            "Rosh Ha‘Ayin",
            "Kuwait City",
            "Copenhagen",
            "Málaga",
            "Chisinau",
            "Tallinn",
            "Baghdad",
            "Stockholm",
            "Almaty",
            "Kansas City",
            "Nairobi",
            "Riyadh",
            "Graz",
            "Vilnius",
            "Accra",
            "Helsinki",
            "Meppel",
            "Vienna",
            "Chennai",
            "Mexico City",
            "Reykjavík",
            "Barrio San Luis",
            "Haifa",
            "Leesburg",
            "Tbilisi",
            "Bexley",
            "Muscat",
            "Belgrade",
            "Lake Ridge",
            "Ljubljana",
            "Minneapolis",
            "Phnom Penh",
            "Moscow",
            "Calais",
            "Osasco"
          ],
          "carrier": "",
          "datacenter": "",
          "longitude": 121.297,
          "latitude": 24.9937
        },
        "raw_data": {
          "scan": [
            {
              "port": 0,
              "protocol": "tcp"
            },
            {
              "port": 1,
              "protocol": "tcp"
            }
          ],
          "ja3": [
            {
              "fingerprint": "cc05126c4210606659557a9d4bcf66bb",
              "port": 443
            },
          ],
          "hassh": [],
          "http": {
            "md5": [
              "690e440f039d37e8098f20406f460c11",
              "9e076f5885f5cc16a4b5aeb8de4adff5",
              "e00de0bdb1b243b31eb412f1c281508b",
              "f4bbb0d73223a94da9d3d3e729f52ed6",
              "9ac63e7f646d5b7f86c90256c24631fc",
              "3e967666e02c20566cdfbd92c669cd4a",
              "f71acc4f12fd3d4bcb5070c47116f75b",
              "f4b6a035314eb57b5e571ce37abc18bc",
              "7730010dabae07853d0c874ec8dae532",
              "82484835ea09cddd76374eb1c21489c0",
              "87360c2d7aad6055326c822a81eb5f11",
              "aa7a5d180e9fa5ec8db0abdcb608e0db",
              "aaaa73383204c4f6fd48ead5bce52c45",
              "1e3927982a491f23eaa7c93be06716e4",
              "4a0e38e4a4f1111b4f43b5f3023a1196",
              "3e7f1738b0ee6b1c709206e9afc14135",
              "0b7f2a5c390c3e89565b9eae391ad462",
              "927ffe02e5366a337947478fc280cde3",
              "c9d7a2e09ea5d98b9523d6d8c63018be",
              "1a89b3293ceb214b9c3c56987e522a75",
              "0ef3a4f4877316a42645b41156f7ba0f",
              "7a490e2bcc26e1ca8966f12d42d1a5e9",
              "297a81069094d00a052733d3a0537d18",
              "4c2049dad5c78893481fc831c6338274",
              "39f029a883aec35cdac4c92d128b32c1",
              "62962daa1b19bbcc2db10b7bfd531ea6",
              "31bb581c9472cb009efe1b732d63b09a",
              "733d62fe6095560a356ce43ddff49169",
              "2bc1ec49979842cac97e7127e246dc27",
              "e5ae5cc4947c5673e19b23644b294ff5",
              "f0bd99d8934dd6c3a66ecc514db52526",
              "b55993cb73060a58d829dc134ca2be09",
              "28e958945b7b6fd5a757abee2a9f8baa",
              "1a93df3517a444cf8ceb59f3640d0224",
              "53f80a90b30f477d3a50c23d37458769",
              "9d1ead73e678fa2f51a70a933b0bf017",
              "ecdb3f00d157764c1d42fbd0e561ce1b",
              "382ab522931673c11e398ead1b7b1678",
              "14a214753f9ba15f42c5e32787fc8251",
              "de5d371c9b4af6ff13cad790505469c6",
              "39260fe1c99d991ffd4ed5e33411d4a9",
              "eb05d8d73b5b13d8d84308a4751ece96",
              "4c891d1fe72461f3d81856722f0dc806",
              "b3f06c8ecaa04de0bcf39b6814492e86",
              "2d5d31ab5717e976a301c2b678578a94",
              "0a07dcf6ead480a3b2c4a9ff095101f3",
              "65144d3f977f76227bc360430e50a929",
              "a4cf016eab71d5d71a162820bd751bf2",
              "997ef43d01ca5d161e22d6475fc98815",
              "6b774f15b254a3d1548db63b6f411150",
              "124bf4d1a7db31dd60d4642dce268035",
              "cc9285bf64e3b0fb1d521bf6bde6418f",
              "fb81549ee2896513a1ed5714b1b1a0f0",
              "302e74f93481e4a7c43e503b29a88d45"
            ],
            "cookie_keys": [],
            "request_authorization": [],
            "request_cookies": [],
            "request_header": [
              "host",
              "user-agent",
              "accept-encoding",
              "accept",
              "accept-language",
              "connection",
              "content-type",
              "content-length",
              "authorization",
              "referer",
              "cache-control"
            ],
            "method": [
              "GET",
              "POST"
            ],
            "path": [
              "/sitemap.xml",
              "/",
              "/robots.txt",
              "/config.json",
              "/favicon.ico",
              "/static/favicons/favicon-192px-e00de0.png",
              "/static/scripts/bundle-17a365.js",
              "/info",
              "/version",
              "/containers/json",
              "/json_rpc",
              "/repositories",
              "/query",
              "/images/weblogin.png",
              "/images/login1.png",
              "/images/login2.png",
              "/images/login1.jpg",
              "/weblogin.htm",
              "/images/login3.png",
              "/mobile/",
              "/home.asp",
              "/images/favicon.ico",
              "/login.htm",
              "/login",
              "/login.action;jsessionid=node0mf8245bd20c3141827o4hz1pf6404.node0",
              "/WebInterface/login.html",
              "/logon/LogonPoint/receiver/images/common/icon_vpn.ico",
              "/logon/LogonPoint/index.html",
              "/luci-static/bootstrap/favicon.ico",
              "/cgi-bin/admin_console.cgi",
              "/cgi-bin/luci",
              "/messages/",
              "/sse",
              "/wsman",
              "/WebInterface/Resources/js/jquery-migrate-1.2.1.min.js",
              "/WebInterface/Resources/js/login.js",
              "/WebInterface/jQuery/js/jquery.blockUI.js",
              "/WebInterface/jQuery/js/jquery-ui-1.8.2.custom.min.js",
              "/WebInterface/Resources/js/jquery-1.9.1.js",
              "/login/cwp_theme/original/js/plugins/iCheck/icheck.min.js",
              "/login/cwp_theme/original/js/plugins/gritter/jquery.gritter.min.js",
              "/login/cwp_theme/original/img/ico/favicon.ico",
              "/login/cwp_theme/original/js/popper.min.js",
              "/login/cwp_theme/original/js/jquery-3.1.1.min.js",
              "/login/cwp_theme/original/js/bootstrap.js",
              "/login/cwp_theme/original/js/plugins/toastr/toastr.min.js"
            ],
            "request_origin": [],
            "useragent": [
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<IP> Safari/537.36 Edg/<IP>",
              "Go-http-client/1.1",
              "python-requests/2.32.4",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
            ]
          },
          "source": {
            "bytes": 37398405
          },
          "tls": {
            "cipher": [
              "TLS_AES_256_GCM_SHA384",
              "TLS_CHACHA20_POLY1305_SHA256",
              "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
              "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
              "TLS_RSA_WITH_AES_256_GCM_SHA384",
              "TLS_AES_128_GCM_SHA256",
              "0x8f58",
              "0xc9a4"
            ],
            "ja4": [
              "t10i1107h2_644766ff55e7_583ba773bd60",
              "t11d6911h9_ea0618708e31_52c4d8bb91c9",
              "t11i1107h2_644766ff55e7_583ba773bd60",
              "t12d3411h9_a634f799a498_52c4d8bb91c9",
              "t12d3511h9_66c735deec94_52c4d8bb91c9",
              "t12d6911hq_ea0618708e31_52c4d8bb91c9",
              "t12d6912h9_ea0618708e31_1da015a32102",
              "t12d6912hq_ea0618708e31_1da015a32102",
              "t12i2308h2_31bea9ec6298_ac0d2f4ec206",
              "t13d6412h9_0f757fa8abd0_1da015a32102",
              "t13d6912h9_ea0618708e31_1da015a32102",
              "t13d6912hq_ea0618708e31_1da015a32102",
              "t13i2609h2_3309cf098094_97f8aa674fd9",
              "t13i130900_f57a46bbacb6_e7c285222651",
              "t13i1811h1_85036bcba153_b26ce05bbdd6"
            ]
          },
          "ssh": {
            "key": []
          }
        },
        "last_seen_timestamp": "2025-09-19 16:56:37"
      }
    }
  ],
  "request_metadata": {
    "restricted_fields": [],
    "scroll": "FGluY2x1ZGVfY29udGV4dF91dWlkDnF1ZXJ5VGhlbkZldGNoAhZ4bk5Za0lQQVF2ZVBGU0djY3JXckxBAAAAAAVXGiYWRzhQSjdSLS1Sa2U3c3poVndHd2tqdxZpdUFkYmlxNVJWQ0otbG5hR1Q5NjBBAAAAAAcB1KwWUHFxZDZVbHJSb2VLTE05eWdFSFV4QQ==",
    "message": "",
    "query": "tags:\"MCP and SSE endpoint scanning\" classification:malicious",
    "complete": false,
    "count": 147,
    "adjusted_query": "(tags:\"MCP and SSE endpoint scanning\" classification:malicious) last_seen:90d"
  }
}
```

# GNQL V3 Metadata Query

GreyNoise Query Language Metadata Endpoint This endpoint provides the same functionality as the main GNQL endpoint but with additional field filtering capabilities. It automatically excludes raw data from responses and allows you to specify additional fields to exclude.

The metadata endpoint is designed for use cases where you need to retrieve IP intelligence data without the raw scan data, making it more efficient for metadata-focused queries.

Query params:

- `query`: string; GNQL query string (required)
- `size`: integer; The number of results provided per page for paginating through all results of a query; 1 to 10000 (Defaults to 10000)
- `scroll`: string;  Scroll token to paginate through results
- `quick`: boolean; If `true`, the response will only include the IP address and the classification or trust level. (Defaults to false)
- `exclude`: string; Comma-separated list of fields to exclude from the response. The `raw_data` field is automatically excluded and cannot be included.

## Quick

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v3/gnql/metadata?query=tags%3A%22MCP%20and%20SSE%20endpoint%20scanning%22%20classification%3Amalicious&size=3&quick=true' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

```json
{
  "data": [
    {
      "ip": "152.32.206.64",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    },
    {
      "ip": "118.193.64.186",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    },
    {
      "ip": "128.14.237.130",
      "business_service_intelligence": {
        "found": false,
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "found": true,
        "classification": "malicious"
      }
    }
  ],
  "request_metadata": {
    "restricted_fields": [],
    "scroll": "FGluY2x1ZGVfY29udGV4dF91dWlkDnF1ZXJ5VGhlbkZldGNoAhZYVFhsVGFCYVQ0ZTZOMmdkMW91Tl9nAAAAAABKGH8WZXA1ak9Yc1NUMXFIWmJlTEI5WGpCURZ3SXE5a1ZtRFJheTJqQ3psS0pSYm53AAAAAAd_5qQWcElNWXYtVlhRYzJzU0tGaUNSSnFOdw==",
    "message": "",
    "query": "tags:\"MCP and SSE endpoint scanning\" classification:malicious",
    "complete": false,
    "count": 147,
    "adjusted_query": "(tags:\"MCP and SSE endpoint scanning\" classification:malicious) last_seen:90d"
  }
}
```

## Normal

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v3/gnql/metadata?query=tags%3A%22MCP%20and%20SSE%20endpoint%20scanning%22%20classification%3Amalicious&size=2&quick=false' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

```json
{
  "data": [
    {
      "ip": "128.14.237.130",
      "business_service_intelligence": {
        "found": false,
        "category": "",
        "name": "",
        "description": "",
        "explanation": "",
        "last_updated": "",
        "reference": "",
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "first_seen": "2023-08-31",
        "last_seen": "2025-09-19",
        "found": true,
        "tags": [
          {
            "id": "1a2da3d3-57d6-4030-b686-a1fbdafa5987",
            "slug": "azure-omi-rce-check",
            "name": "Azure OMI RCE Check",
            "description": "IP addresses with this tag have been observed scanning the internet for WSMan Powershell providers without an Authorization header, but has not provided a valid SOAP XML Envelope payload.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38649",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38645",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38648",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38647",
              "https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38647",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38648",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38645",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38649"
            ],
            "cves": [
              "CVE-2021-38647"
            ],
            "recommend_block": false,
            "created": "2021-09-16",
            "updated_at": "2025-09-19T18:04:51.765218Z"
          },
          {
            "id": "feb92353-4264-44ce-8f7d-8ddae93719da",
            "slug": "cgi-script-scanner",
            "name": "CGI Script Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for CGI scripts.",
            "category": "activity",
            "intention": "malicious",
            "references": [
              "https://en.wikipedia.org/wiki/Common_Gateway_Interface"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:29.842167Z"
          },
          {
            "id": "79f609f0-4d07-455d-b9b1-56ff7c1a77a9",
            "slug": "carries-http-referer-scanner",
            "name": "Carries HTTP Referer",
            "description": "IP addresses with this tag have been observed scanning the internet with an HTTP client that includes the Referer header in their requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-19",
            "updated_at": "2025-09-19T18:04:29.690369Z"
          },
          {
            "id": "8cdc09c8-15b3-40b2-8eb7-96acdf89c323",
            "slug": "cisco-smart-install-endpoint-scanner",
            "name": "Cisco Smart Install Endpoint Scanner",
            "description": "IP addresses with this tag have been observed scanning for exposed Cisco Smart Install Protocol ports.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.rapid7.com/db/modules/auxiliary/scanner/misc/cisco_smart_install",
              "https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/misc/cisco_smart_install.rb",
              "https://github.com/frostbits-security/SIET/blob/master/cisco-siet.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:30.229608Z"
          },
          {
            "id": "cf2b9808-8f8b-480e-94eb-7a8b5c168398",
            "slug": "citrix-adc-gateway-login-panel-crawler",
            "name": "Citrix ADC Gateway Login Panel Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover Internet-facing Citrix ADC Gateway login pages.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.netscaler.com/en-us/citrix-adc.html",
              "https://github.com/adysec/nuclei_poc/blob/main/poc/detect/citrix-adc-gateway-detect.yaml"
            ],
            "cves": [],
            "recommend_block": true,
            "created": "2025-08-15",
            "updated_at": "2025-09-19T18:04:30.271816Z"
          },
          {
            "id": "f97736ef-88b7-45bb-83b8-2b69b765e57a",
            "slug": "codesys-scanner",
            "name": "Codesys Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over Codesys programming interface.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/CODESYS",
              "https://www.codesys.com/products/codesys-communication/standard-ethernet.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-15",
            "updated_at": "2025-09-19T18:04:30.565508Z"
          },
          {
            "id": "9fa91f79-14be-4a68-aee1-1e830ab62243",
            "slug": "crimson-v3-scanner",
            "name": "Crimson v3 Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover HMI devices that respond via Red Lion Controls Crimson v3 programming interface.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.redlion.net/red-lion-software/crimson/crimson-30",
              "https://github.com/internetofallthethings/cr3-nmap/blob/master/cr3-fingerprint.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-26",
            "updated_at": "2025-09-19T18:04:30.791238Z"
          },
          {
            "id": "29036263-e7ab-411a-984d-bbb15f0dea1c",
            "slug": "crushftp-scanner",
            "name": "CrushFTP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover publicly accessible CrushFTP web interfaces.  This scanning could be related to CVE-2024-4040.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.crushftp.com/index.html",
              "http://web.archive.org/web/20241215003801/https://attackerkb.com/topics/20oYjlmfXa/cve-2024-4040/rapid7-analysis"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-04-22",
            "updated_at": "2025-09-19T18:04:30.815636Z"
          },
          {
            "id": "389ee453-fdac-4a23-aad5-e9daded96543",
            "slug": "cryptocurrency-node-scanner",
            "name": "Cryptocurrency Node Scanner",
            "description": "IP addresses with this tag have been observed attempting to locate cryptocurrency nodes using JSON-RPC.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/ethereum/wiki/wiki/JSON-RPC",
              "https://en.bitcoin.it/wiki/API_reference_(JSON-RPC)"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:30.860457Z"
          },
          {
            "id": "88c01626-5fc9-4f0a-b39f-b57331ded73e",
            "slug": "ehlo-scanner",
            "name": "EHLO Crawler",
            "description": "IP addresses with this tag have been observed scanning the Internet for services that respond to a generic EHLO request.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-11-30",
            "updated_at": "2025-09-19T18:04:31.749023Z"
          },
          {
            "id": "208534a2-274c-4ccf-9fa8-30a61e5c5696",
            "slug": "erlang-port-mapper-daemon-crawler",
            "name": "Erlang Port Mapper Daemon Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover hosts involved in distributed Erlang computations.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://svn.nmap.org/nmap/scripts/epmd-info.nse",
              "http://web.archive.org/web/20240419152645/https://www.erlang.org/doc/man/epmd.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-09-06",
            "updated_at": "2025-09-19T18:04:31.932267Z"
          },
          {
            "id": "1552ec97-eb19-421e-b772-847d7f2d310c",
            "slug": "ethernet-ip-scanner",
            "name": "EtherNet/IP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over EtherNet/IP protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/EtherNet/IP",
              "https://literature.rockwellautomation.com/idc/groups/literature/documents/wp/enet-wp001_-en-p.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T18:04:32.025972Z"
          },
          {
            "id": "cca2496c-fa04-48cb-afaa-c0a76a613619",
            "slug": "favicon-scanner",
            "name": "Favicon Scanner",
            "description": "IP addresses with this tag have been observed checking for the existence of a 'favicon' file on the web server.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://en.wikipedia.org/wiki/Favicon",
              "https://www.w3schools.com/html/html_favicon.asp",
              "https://www.securityhq.com/blog/using-favicon-hashes-to-spot-vulnerabilities/",
              "https://www.ndss-symposium.org/wp-content/uploads/madweb2021_23009_paper.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-11-11",
            "updated_at": "2025-09-19T18:04:32.370278Z"
          },
          {
            "id": "ae5f3238-716b-4a8c-8841-d5a0bf24c73a",
            "slug": "firebirdsql-scanner",
            "name": "FirebirdSQL Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet and attempting to discover FirebirdSQL instances.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/misc/fb_cnct_group.rb",
              "https://svn.nmap.org/nmap/nmap-service-probes"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-06",
            "updated_at": "2025-09-19T18:04:32.474264Z"
          },
          {
            "id": "3d144850-efcc-436a-9008-c5d28ac581ae",
            "slug": "go-http-client-scanner",
            "name": "Go HTTP Client",
            "description": "IP addresses with this tag have been observed scanning the Internet using the Golang HTTP Client.",
            "category": "tool",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:33.434559Z"
          },
          {
            "id": "7ad1354b-800a-4c8d-9f35-b7fc4720c870",
            "slug": "ibm-tn-3270-mainframe-scanner",
            "name": "IBM TN-3270 Mainframe Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet for IBM TN-3270 Mainframes.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/IBM_3270"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:34.541393Z"
          },
          {
            "id": "c849922e-bb9c-412e-a819-6999ab8ad862",
            "slug": "jrmi-scanner",
            "name": "JRMI Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for exposed Java Remote Method Invocation (JRMI) endpoints.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.oracle.com/javase/tutorial/rmi/index.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:35.90074Z"
          },
          {
            "id": "fe34d80c-4d62-4b39-afa4-469494292c7f",
            "slug": "mcp-and-sse-endpoint-scanning",
            "name": "MCP and SSE endpoint scanning",
            "description": "IP addresses with this tag have been observed scanning for Model Context Protocol (MCP) and Server-Sent Events (SSE).",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://hexdocs.pm/mcp_sse/readme.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-06-04",
            "updated_at": "2025-09-19T18:04:36.901739Z"
          },
          {
            "id": "8c5ec3d6-ed9b-4463-a3b3-f358d1fa1c57",
            "slug": "melsec-q-scanner",
            "name": "MELSEC-Q Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover Mitsubishi Electric ICS devices that respond over MELSEC-Q protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.mitsubishielectric.com/fa/products/cnt/plcq/items/index.html",
              "http://web.archive.org/web/20220525232903/http://dl.mitsubishielectric.com/dl/fa/document/manual/school_text/sh080618eng/sh080618enga.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T18:04:36.92832Z"
          },
          {
            "id": "169ff7a3-aab6-4242-a88c-290246f99fae",
            "slug": "mqtt-protocol-scanner",
            "name": "MQTT Protocol Scanner",
            "description": "IP addresses with this tag have been observed scanning the internet for responses used by the MQTT protocol for Internet of Things devices.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20230101140347/https://openlabpro.com/guide/mqtt-packet-format/"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-03-10",
            "updated_at": "2025-09-19T18:04:37.799572Z"
          },
          {
            "id": "fddc4698-fb29-4fd6-946f-5598100fe716",
            "slug": "mssql-login-attempt",
            "name": "MSSQL Login Attempt",
            "description": "IP addresses with this tag have been observed attempting to perform a Microsoft SQL (MSSQL) login.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/7af53667-1b72-4703-8258-7984e838f746",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/ce5ad23f-6bf8-4fa5-9426-6b0d36e14da2"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-10-28",
            "updated_at": "2025-09-19T18:04:37.849633Z"
          },
          {
            "id": "9eacd23a-33c1-410d-86a7-0560c4e9d942",
            "slug": "microsoft-message-queuing-msmq-crawler",
            "name": "Microsoft Message Queuing (MSMQ) Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover Internet-facing Microsoft Windows devices that respond over Microsoft Message Queuing (MSMQ) binary protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Microsoft_Message_Queuing",
              "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/058cdeb4-7a3c-405b-989c-d32b9d6bddae"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-04-12",
            "updated_at": "2025-09-19T18:04:37.13395Z"
          },
          {
            "id": "72077e4d-2a5f-4a86-b2c1-6fdb19bc3645",
            "slug": "modbus-tcp-scanner",
            "name": "Modbus TCP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over Modbus TCP protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Modbus",
              "https://www.fernhillsoftware.com/help/drivers/modbus/modbus-protocol.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-15",
            "updated_at": "2025-09-19T18:04:37.67019Z"
          },
          {
            "id": "66edd69b-50b8-46de-b03c-b596a3d469ef",
            "slug": "pcworx-scanner",
            "name": "PCWorx Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over PCWorx protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://svn.nmap.org/nmap/scripts/pcworx-info.nse",
              "https://web.archive.org/web/20220421135319/https://sergiusechel.medium.com/misconfiguration-in-ilc-gsm-gprs-devices-leaves-over-1-200-ics-devices-vulnerable-to-attacks-over-82c2d4a91561"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T18:04:39.359457Z"
          },
          {
            "id": "8503c116-536a-4a12-bb77-c8250b6acf76",
            "slug": "phoenix-contact-plc-scanner",
            "name": "Phoenix Contact PLC Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet looking for Phoenix Contact PLCs.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20220415164534/http://select.phoenixcontact.com/phoenix/dwld/fl_il_24_bk_pac_um_e_6156_en_05.pdf?asid2=7757471351375"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:39.434342Z"
          },
          {
            "id": "affb73e2-5eb7-4528-99b8-6742a70a109f",
            "slug": "proconos-scanner",
            "name": "ProConOS Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that use ProConOS runtime system.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20220621165517/https://www.phoenixcontact.com/assets/downloads_ed/global/web_dwl_technical_info/db_en_proconos_embedded_clr_106495_en_01.pdf",
              "https://github.com/digitalbond/Redpoint/blob/master/proconos-info.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T18:04:40.283862Z"
          },
          {
            "id": "788eb4be-0ffc-438d-92d6-d700df4fef72",
            "slug": "python-requests-client-scanner",
            "name": "Python Requests Client",
            "description": "IP addresses with this tag have been observed scanning the Internet with a client that uses the Python Requests library.",
            "category": "tool",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:40.470457Z"
          },
          {
            "id": "222cf79e-08a2-400a-a0b8-1c716aa43ec4",
            "slug": "rdp-crawler",
            "name": "RDP Crawler",
            "description": "IP addresses with this tag have been observed crawling the internet for Remote Desktop Protocol (RDP) by intiating a connection request.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-02",
            "updated_at": "2025-09-19T18:04:40.710457Z"
          },
          {
            "id": "e23d491c-6abf-477b-9073-dd9879f46a98",
            "slug": "radmin-scanner",
            "name": "Radmin Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet to identify devices using the Radmin protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:40.629256Z"
          },
          {
            "id": "77069c85-09a3-4322-bbf3-aefda8d46ae7",
            "slug": "sip-options-scanner",
            "name": "SIP OPTIONS Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for SIP devices using OPTIONS requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://tools.ietf.org/html/rfc3261#section-11.1"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:41.798534Z"
          },
          {
            "id": "5b840bfd-4377-4b9d-b2a2-beb8ddedc823",
            "slug": "smbv1-scanner",
            "name": "SMBv1 Crawler",
            "description": "IP addresses with this tag have been observed crawling the internet for SMBv1.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-04-02",
            "updated_at": "2025-09-19T18:04:41.949705Z"
          },
          {
            "id": "e3539e1d-46eb-4c4d-b708-e99c3487d804",
            "slug": "spdy-alpn-negotiation-attempt",
            "name": "SPDY ALPN Negotiation Attempt",
            "description": "IP addresses with this tag have been observed using Application-Layer Protocol Negotiation (ALPN) in the attempt to establish SPDY connections.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://en.wikipedia.org/wiki/SPDY",
              "https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-08-08",
            "updated_at": "2025-09-19T18:04:42.411345Z"
          },
          {
            "id": "b1859b91-92d5-48d2-b43d-bbfd09db964d",
            "slug": "ssh-alternative-port-scanner",
            "name": "SSH Alternative Port Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet for SSH servers running on ports other than 22/TCP.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:42.640042Z"
          },
          {
            "id": "537cee16-c4a9-45cd-baf1-75963ab7bdd2",
            "slug": "ssh-connection-attempt",
            "name": "SSH Connection Attempt",
            "description": "IP addresses with this tag have been observed attempting to negotiate an SSH session.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Secure_Shell"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-09-30",
            "updated_at": "2025-09-19T18:04:42.684493Z"
          },
          {
            "id": "393fed60-f1eb-4376-af03-f92d966a54d6",
            "slug": "sitemap-crawler",
            "name": "Sitemap Crawler",
            "description": "IP addresses with this tag have been observed crawling for sitemap files.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://www.sitemaps.org/protocol.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-01-28",
            "updated_at": "2025-09-19T18:04:41.861502Z"
          },
          {
            "id": "567fdc14-d3ca-481e-9679-8c017dea4665",
            "slug": "t3-rmi-protocol-and-weblogic-version-check",
            "name": "T3 RMI Protocol and Weblogic Version Check",
            "description": "IP addresses with this tag have been observed checking for the T3 RMI protocol and Weblogic version.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/christophetd/nmap-nse-info/blob/master/test/data/weblogic-t3-info.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-05-11",
            "updated_at": "2025-09-19T18:04:42.86112Z"
          },
          {
            "id": "ac32bdeb-b49d-4079-9e6b-8fbca5e0addf",
            "slug": "tls-ssl-scanner",
            "name": "TLS/SSL Crawler",
            "description": "IP addresses with this tag have been observed attempting to opportunistically crawl the Internet and establish TLS/SSL connections.",
            "category": "activity",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:43.187243Z"
          },
          {
            "id": "869feaa1-dc77-4037-aee2-247b7a39cf7d",
            "slug": "web-scanner",
            "name": "Web Crawler",
            "description": "IP addresses with this tag have been seen crawling HTTP(S) servers around the Internet.",
            "category": "activity",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:44.706943Z"
          },
          {
            "id": "6c79246a-c56e-4dfa-85a8-b5239ade7f02",
            "slug": "x-server-connection-attempt",
            "name": "X Server CVE-1999-0526 Connection Attempt",
            "description": "IP addresses with this tag have been observed scanning the Internet for X11 servers with access control disabled, which allows for unauthenticated connections.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-1999-0526",
              "https://www.cvedetails.com/cve/CVE-1999-0526/"
            ],
            "cves": [
              "CVE-1999-0526"
            ],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:05:30.324225Z"
          },
          {
            "id": "eae8d97d-08c6-4d03-9405-8099cf85af56",
            "slug": "iscsi-scanner",
            "name": "iSCSI Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet and attempting to discover hosts that respond to iSCSI login requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.rfc-editor.org/rfc/rfc7143.html#section-11.2",
              "https://book.hacktricks.xyz/pentesting/3260-pentesting-iscsi"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-01-12",
            "updated_at": "2025-09-19T18:04:35.113556Z"
          },
          {
            "id": "215d03ae-6899-49dd-9167-4c22fe1e832d",
            "slug": "robots-txt-scanner",
            "name": "robots.txt Scanner",
            "description": "IP addresses with this tag have been observed checking for the existence of a 'robots.txt' file on the web server.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://datatracker.ietf.org/doc/html/rfc9309",
              "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
              "https://www.robotstxt.org/",
              "https://www.cloudflare.com/learning/bots/what-is-robots-txt/"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-10-05",
            "updated_at": "2025-09-19T18:04:40.835001Z"
          },
          {
            "id": "783551ed-1915-4771-8a4c-1c858dc02a6b",
            "slug": "sitemap-xml-crawler",
            "name": "sitemap.xml Crawler",
            "description": "IP addresses with this tag have been observed attempting to fetch a sitemap.xml file, which is a very common file used by search engines and crawlers.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://www.xml-sitemaps.com/",
              "https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-08-19",
            "updated_at": "2025-09-19T18:04:41.882573Z"
          }
        ],
        "actor": "unknown",
        "spoofable": false,
        "classification": "malicious",
        "cves": [
          "CVE-1999-0526",
          "CVE-2021-38647"
        ],
        "bot": false,
        "vpn": false,
        "vpn_service": "",
        "tor": false,
        "metadata": {
          "asn": "AS135377",
          "source_country": "Taiwan",
          "source_country_code": "TW",
          "source_city": "Taoyuan City",
          "domain": "ucloud.cn",
          "rdns_parent": "",
          "rdns_validated": false,
          "organization": "UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED",
          "category": "hosting",
          "rdns": "",
          "os": "",
          "sensor_count": 2762,
          "sensor_hits": 471289,
          "region": "Taiwan",
          "mobile": false,
          "single_destination": false,
          "destination_countries": [
            "United States",
            "Germany",
            "Spain",
            "Brazil",
            "Japan",
            "South Korea",
            "India",
            "United Kingdom",
            "Canada",
            "Australia",
            "Indonesia",
            "Singapore",
            "France",
            "Hong Kong",
            "Mexico",
            "Netherlands",
            "Switzerland",
            "Belgium",
            "Israel",
            "Taiwan",
            "United Arab Emirates",
            "Finland",
            "Ireland",
            "South Africa",
            "Malaysia",
            "Peru",
            "Ukraine",
            "Greece",
            "Pakistan",
            "Luxembourg",
            "Thailand",
            "Hungary",
            "Romania",
            "Latvia",
            "Chile",
            "New Zealand",
            "Bahrain",
            "Croatia",
            "Italy",
            "Poland",
            "Turkey",
            "Austria",
            "Norway",
            "Belarus",
            "Portugal",
            "Russia",
            "Bulgaria",
            "Ecuador",
            "Slovakia",
            "Czech Republic",
            "Qatar",
            "Kuwait",
            "Denmark",
            "Estonia",
            "Moldova",
            "Iraq",
            "Sweden",
            "Kazakhstan",
            "Kenya",
            "Saudi Arabia",
            "Lithuania",
            "Ghana",
            "Iceland",
            "Colombia",
            "Georgia",
            "Oman",
            "Cambodia",
            "Serbia",
            "Slovenia"
          ],
          "destination_country_codes": [
            "US",
            "DE",
            "ES",
            "BR",
            "JP",
            "KR",
            "IN",
            "GB",
            "CA",
            "AU",
            "ID",
            "SG",
            "FR",
            "HK",
            "MX",
            "CH",
            "NL",
            "BE",
            "IL",
            "AE",
            "TW",
            "FI",
            "IE",
            "ZA",
            "MY",
            "PE",
            "UA",
            "GR",
            "PK",
            "LU",
            "TH",
            "HU",
            "RO",
            "LV",
            "CL",
            "NZ",
            "BH",
            "HR",
            "IT",
            "PL",
            "TR",
            "AT",
            "NO",
            "BY",
            "PT",
            "RU",
            "BG",
            "EC",
            "SK",
            "CZ",
            "QA",
            "KW",
            "DK",
            "EE",
            "MD",
            "IQ",
            "SE",
            "KE",
            "KZ",
            "SA",
            "LT",
            "GH",
            "IS",
            "CO",
            "GE",
            "OM",
            "KH",
            "RS",
            "SI"
          ],
          "destination_asns": [
            "AS396982",
            "AS16509",
            "AS14061",
            "AS20473",
            "AS8075",
            "AS174",
            "AS63949",
            "AS45102",
            "AS6939",
            "AS44477",
            "AS138915",
            "AS35487",
            "AS14618",
            "AS209847",
            "AS206804",
            "AS61138",
            "AS44709",
            "AS62005",
            "AS50979",
            "AS57695",
            "AS204932",
            "AS202422",
            "AS210772",
            "AS15626",
            "AS16276",
            "AS57169",
            "AS7195",
            "AS56740",
            "AS57578",
            "AS7590",
            "AS49720",
            "AS204957",
            "AS61317",
            "AS136258",
            "AS1257",
            "AS50837",
            "AS327813",
            "AS59729",
            "AS9678",
            "AS23966",
            "AS57814"
          ],
          "destination_cities": [
            "Washington",
            "Frankfurt am Main",
            "Federal Way",
            "Englewood",
            "San Sebastián de los Reyes",
            "New Orleans",
            "São Paulo",
            "Columbus",
            "London",
            "Seoul",
            "Mumbai",
            "Salt Lake City",
            "Los Angeles",
            "Jakarta",
            "Singapore",
            "North Charleston",
            "Santa Clara",
            "Sydney",
            "Paris",
            "Hong Kong",
            "Ashburn",
            "Council Bluffs",
            "Indianapolis",
            "General Lázaro Cárdenas",
            "North Bergen",
            "Las Vegas",
            "Tokyo",
            "The Dalles",
            "Zürich",
            "Toronto",
            "Montréal",
            "Atlanta",
            "New York City",
            "Osaka",
            "Brussels",
            "Incheon",
            "Virginia Beach",
            "Taipei",
            "Boardman",
            "Dallas",
            "San Antonio",
            "San Jose",
            "Bāshettihalli",
            "Pune",
            "Dubai",
            "Dublin",
            "Chicago",
            "Elk Grove Village",
            "Cheyenne",
            "Kuala Lumpur",
            "Lima",
            "Amsterdam",
            "Kyiv",
            "Lappeenranta",
            "Piscataway",
            "Tel Aviv",
            "Luxembourg",
            "Petaẖ Tiqva",
            "Nashville",
            "Kent",
            "Newark",
            "St. Louis",
            "Bangkok",
            "Budapest",
            "Bucharest",
            "Miami",
            "Ōi",
            "Groningen",
            "Riga",
            "Santiago de Querétaro",
            "Santiago",
            "Cape Town",
            "Melbourne",
            "Mount Eden",
            "Cedar Knolls",
            "Karachi",
            "Dār Kulayb",
            "Zagreb",
            "Athens",
            "Fremont",
            "Milan",
            "Warsaw",
            "Haarlem",
            "Al Fujairah City",
            "Rawalpindi",
            "Istanbul",
            "Volos",
            "Oslo",
            "Braga",
            "Johannesburg",
            "Minsk",
            "Richardson",
            "Bratislava",
            "Quito",
            "Sofia",
            "Prague",
            "Saint Petersburg",
            "Aubervilliers",
            "Doha",
            "Rosh Ha‘Ayin",
            "Kuwait City",
            "Copenhagen",
            "Málaga",
            "Chisinau",
            "Tallinn",
            "Baghdad",
            "Stockholm",
            "Almaty",
            "Kansas City",
            "Nairobi",
            "Riyadh",
            "Graz",
            "Vilnius",
            "Accra",
            "Helsinki",
            "Meppel",
            "Vienna",
            "Chennai",
            "Mexico City",
            "Reykjavík",
            "Barrio San Luis",
            "Haifa",
            "Leesburg",
            "Tbilisi",
            "Bexley",
            "Muscat",
            "Belgrade",
            "Lake Ridge",
            "Ljubljana",
            "Minneapolis",
            "Phnom Penh",
            "Moscow",
            "Calais",
            "Osasco"
          ],
          "carrier": "",
          "datacenter": "",
          "longitude": 121.297,
          "latitude": 24.9937
        },
        "raw_data": {
          "scan": [],
          "ja3": [],
          "hassh": [],
          "http": {
            "md5": [],
            "cookie_keys": [],
            "request_authorization": [],
            "request_cookies": [],
            "request_header": [],
            "method": [],
            "path": [],
            "request_origin": [],
            "useragent": []
          },
          "source": {
            "bytes": 0
          },
          "tls": {
            "cipher": [],
            "ja4": []
          },
          "ssh": {
            "key": []
          }
        },
        "last_seen_timestamp": "2025-09-19 16:56:37"
      }
    },
    {
      "ip": "152.32.206.64",
      "business_service_intelligence": {
        "found": false,
        "category": "",
        "name": "",
        "description": "",
        "explanation": "",
        "last_updated": "",
        "reference": "",
        "trust_level": ""
      },
      "internet_scanner_intelligence": {
        "first_seen": "2023-08-31",
        "last_seen": "2025-09-19",
        "found": true,
        "tags": [
          {
            "id": "80ee6ce9-04ae-46bc-ae52-ded2eadfeec8",
            "slug": "arucer-scanner",
            "name": "Arucer Crawler",
            "description": "IP addresses with this tag have been observed scanning the Internet for hosts infected with the Arucer trojan.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2010-0103",
              "https://kb.cert.org/vuls/id/154421",
              "https://medium.com/ce-malware-analysis/battery-powered-trojan-part-3-abda2cb83256"
            ],
            "cves": [
              "CVE-2010-0103"
            ],
            "recommend_block": false,
            "created": "2020-11-30",
            "updated_at": "2025-09-19T18:04:50.678652Z"
          },
          {
            "id": "1a2da3d3-57d6-4030-b686-a1fbdafa5987",
            "slug": "azure-omi-rce-check",
            "name": "Azure OMI RCE Check",
            "description": "IP addresses with this tag have been observed scanning the internet for WSMan Powershell providers without an Authorization header, but has not provided a valid SOAP XML Envelope payload.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38649",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38645",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38648",
              "https://nvd.nist.gov/vuln/detail/CVE-2021-38647",
              "https://www.wiz.io/blog/secret-agent-exposes-azure-customers-to-unauthorized-code-execution",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38647",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38648",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38645",
              "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38649"
            ],
            "cves": [
              "CVE-2021-38647"
            ],
            "recommend_block": false,
            "created": "2021-09-16",
            "updated_at": "2025-09-19T18:04:51.765218Z"
          },
          {
            "id": "79f609f0-4d07-455d-b9b1-56ff7c1a77a9",
            "slug": "carries-http-referer-scanner",
            "name": "Carries HTTP Referer",
            "description": "IP addresses with this tag have been observed scanning the internet with an HTTP client that includes the Referer header in their requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-19",
            "updated_at": "2025-09-19T18:04:29.690369Z"
          },
          {
            "id": "8cdc09c8-15b3-40b2-8eb7-96acdf89c323",
            "slug": "cisco-smart-install-endpoint-scanner",
            "name": "Cisco Smart Install Endpoint Scanner",
            "description": "IP addresses with this tag have been observed scanning for exposed Cisco Smart Install Protocol ports.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.rapid7.com/db/modules/auxiliary/scanner/misc/cisco_smart_install",
              "https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/misc/cisco_smart_install.rb",
              "https://github.com/frostbits-security/SIET/blob/master/cisco-siet.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:30.229608Z"
          },
          {
            "id": "f97736ef-88b7-45bb-83b8-2b69b765e57a",
            "slug": "codesys-scanner",
            "name": "Codesys Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over Codesys programming interface.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/CODESYS",
              "https://www.codesys.com/products/codesys-communication/standard-ethernet.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-15",
            "updated_at": "2025-09-19T18:04:30.565508Z"
          },
          {
            "id": "1f9ede00-dd3a-45e0-aab6-5fd8f55079ac",
            "slug": "couchdb-scanner",
            "name": "CouchDB Scanner",
            "description": "IP addresses with this tag have been seen scanning the Internet for CouchDB instances and attempting to enumerate databases.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20191002071606/http://docs.couchdb.org:80/en/2.2.0/config/http-handlers.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-07-28",
            "updated_at": "2025-09-19T18:04:30.747522Z"
          },
          {
            "id": "9fa91f79-14be-4a68-aee1-1e830ab62243",
            "slug": "crimson-v3-scanner",
            "name": "Crimson v3 Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover HMI devices that respond via Red Lion Controls Crimson v3 programming interface.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.redlion.net/red-lion-software/crimson/crimson-30",
              "https://github.com/internetofallthethings/cr3-nmap/blob/master/cr3-fingerprint.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-26",
            "updated_at": "2025-09-19T18:04:30.791238Z"
          },
          {
            "id": "389ee453-fdac-4a23-aad5-e9daded96543",
            "slug": "cryptocurrency-node-scanner",
            "name": "Cryptocurrency Node Scanner",
            "description": "IP addresses with this tag have been observed attempting to locate cryptocurrency nodes using JSON-RPC.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/ethereum/wiki/wiki/JSON-RPC",
              "https://en.bitcoin.it/wiki/API_reference_(JSON-RPC)"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:30.860457Z"
          },
          {
            "id": "75f31e50-191f-4f43-8d5a-421acb6be92f",
            "slug": "distccd-vuln-check",
            "name": "DistCCD Vuln Check",
            "description": "IP addresses with this tag have been observed scanning the Internet for devices vulnerable to CVE-2004-2687, a remote code execution vulnerability in DistCCD.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [
              "CVE-2004-2687"
            ],
            "recommend_block": false,
            "created": "2020-11-30",
            "updated_at": "2025-09-19T18:04:56.83022Z"
          },
          {
            "id": "88c01626-5fc9-4f0a-b39f-b57331ded73e",
            "slug": "ehlo-scanner",
            "name": "EHLO Crawler",
            "description": "IP addresses with this tag have been observed scanning the Internet for services that respond to a generic EHLO request.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-11-30",
            "updated_at": "2025-09-19T18:04:31.749023Z"
          },
          {
            "id": "8aa02829-5b0c-4446-b599-81d61400a22c",
            "slug": "elasticsearch-information-disclosure-attempt",
            "name": "ElasticSearch Information Disclosure Attempt",
            "description": "IP addresses with this tag have been observed attempting to exploit an information disclosure vulnerability in ElasticSearch.",
            "category": "activity",
            "intention": "malicious",
            "references": [
              "https://www.elastic.co/elasticsearch",
              "https://hogarth45.medium.com/elasticsearch-smash-grab-99cf36cdefbb",
              "https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch",
              "https://github.com/projectdiscovery/nuclei-templates/blob/37cb7a57f8521350b96a4accfcb87513dbb1ff1b/http/misconfiguration/elasticsearch.yaml#L18"
            ],
            "cves": [],
            "recommend_block": true,
            "created": "2024-09-17",
            "updated_at": "2025-09-19T18:04:31.777187Z"
          },
          {
            "id": "208534a2-274c-4ccf-9fa8-30a61e5c5696",
            "slug": "erlang-port-mapper-daemon-crawler",
            "name": "Erlang Port Mapper Daemon Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover hosts involved in distributed Erlang computations.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://svn.nmap.org/nmap/scripts/epmd-info.nse",
              "http://web.archive.org/web/20240419152645/https://www.erlang.org/doc/man/epmd.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-09-06",
            "updated_at": "2025-09-19T18:04:31.932267Z"
          },
          {
            "id": "1552ec97-eb19-421e-b772-847d7f2d310c",
            "slug": "ethernet-ip-scanner",
            "name": "EtherNet/IP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over EtherNet/IP protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/EtherNet/IP",
              "https://literature.rockwellautomation.com/idc/groups/literature/documents/wp/enet-wp001_-en-p.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T18:04:32.025972Z"
          },
          {
            "id": "cca2496c-fa04-48cb-afaa-c0a76a613619",
            "slug": "favicon-scanner",
            "name": "Favicon Scanner",
            "description": "IP addresses with this tag have been observed checking for the existence of a 'favicon' file on the web server.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://en.wikipedia.org/wiki/Favicon",
              "https://www.w3schools.com/html/html_favicon.asp",
              "https://www.securityhq.com/blog/using-favicon-hashes-to-spot-vulnerabilities/",
              "https://www.ndss-symposium.org/wp-content/uploads/madweb2021_23009_paper.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-11-11",
            "updated_at": "2025-09-19T18:04:32.370278Z"
          },
          {
            "id": "ae5f3238-716b-4a8c-8841-d5a0bf24c73a",
            "slug": "firebirdsql-scanner",
            "name": "FirebirdSQL Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet and attempting to discover FirebirdSQL instances.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/misc/fb_cnct_group.rb",
              "https://svn.nmap.org/nmap/nmap-service-probes"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-06",
            "updated_at": "2025-09-19T18:04:32.474264Z"
          },
          {
            "id": "3d144850-efcc-436a-9008-c5d28ac581ae",
            "slug": "go-http-client-scanner",
            "name": "Go HTTP Client",
            "description": "IP addresses with this tag have been observed scanning the Internet using the Golang HTTP Client.",
            "category": "tool",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:33.434559Z"
          },
          {
            "id": "7ad1354b-800a-4c8d-9f35-b7fc4720c870",
            "slug": "ibm-tn-3270-mainframe-scanner",
            "name": "IBM TN-3270 Mainframe Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet for IBM TN-3270 Mainframes.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/IBM_3270"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:34.541393Z"
          },
          {
            "id": "c849922e-bb9c-412e-a819-6999ab8ad862",
            "slug": "jrmi-scanner",
            "name": "JRMI Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for exposed Java Remote Method Invocation (JRMI) endpoints.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.oracle.com/javase/tutorial/rmi/index.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:35.90074Z"
          },
          {
            "id": "fe34d80c-4d62-4b39-afa4-469494292c7f",
            "slug": "mcp-and-sse-endpoint-scanning",
            "name": "MCP and SSE endpoint scanning",
            "description": "IP addresses with this tag have been observed scanning for Model Context Protocol (MCP) and Server-Sent Events (SSE).",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://hexdocs.pm/mcp_sse/readme.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-06-04",
            "updated_at": "2025-09-19T18:04:36.901739Z"
          },
          {
            "id": "8c5ec3d6-ed9b-4463-a3b3-f358d1fa1c57",
            "slug": "melsec-q-scanner",
            "name": "MELSEC-Q Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover Mitsubishi Electric ICS devices that respond over MELSEC-Q protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.mitsubishielectric.com/fa/products/cnt/plcq/items/index.html",
              "http://web.archive.org/web/20220525232903/http://dl.mitsubishielectric.com/dl/fa/document/manual/school_text/sh080618eng/sh080618enga.pdf"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T18:04:36.92832Z"
          },
          {
            "id": "169ff7a3-aab6-4242-a88c-290246f99fae",
            "slug": "mqtt-protocol-scanner",
            "name": "MQTT Protocol Scanner",
            "description": "IP addresses with this tag have been observed scanning the internet for responses used by the MQTT protocol for Internet of Things devices.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20230101140347/https://openlabpro.com/guide/mqtt-packet-format/"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-03-10",
            "updated_at": "2025-09-19T18:04:37.799572Z"
          },
          {
            "id": "fddc4698-fb29-4fd6-946f-5598100fe716",
            "slug": "mssql-login-attempt",
            "name": "MSSQL Login Attempt",
            "description": "IP addresses with this tag have been observed attempting to perform a Microsoft SQL (MSSQL) login.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/7af53667-1b72-4703-8258-7984e838f746",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/ce5ad23f-6bf8-4fa5-9426-6b0d36e14da2"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-10-28",
            "updated_at": "2025-09-19T18:04:37.849633Z"
          },
          {
            "id": "9eacd23a-33c1-410d-86a7-0560c4e9d942",
            "slug": "microsoft-message-queuing-msmq-crawler",
            "name": "Microsoft Message Queuing (MSMQ) Crawler",
            "description": "IP addresses with this tag have been observed attempting to discover Internet-facing Microsoft Windows devices that respond over Microsoft Message Queuing (MSMQ) binary protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Microsoft_Message_Queuing",
              "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/058cdeb4-7a3c-405b-989c-d32b9d6bddae"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-04-12",
            "updated_at": "2025-09-19T18:04:37.13395Z"
          },
          {
            "id": "72077e4d-2a5f-4a86-b2c1-6fdb19bc3645",
            "slug": "modbus-tcp-scanner",
            "name": "Modbus TCP Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over Modbus TCP protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Modbus",
              "https://www.fernhillsoftware.com/help/drivers/modbus/modbus-protocol.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-15",
            "updated_at": "2025-09-19T18:04:37.67019Z"
          },
          {
            "id": "307a6975-c706-4341-b6b0-0d15353224ac",
            "slug": "opc-ua-scanner",
            "name": "OPC UA Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that support OPC Unified Architecture standard.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/OPC_Unified_Architecture",
              "https://github.com/COMSYS/msf-opcua"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-25",
            "updated_at": "2025-09-19T18:04:38.626373Z"
          },
          {
            "id": "decddac5-1408-417f-8044-bee392cf9572",
            "slug": "oracle-weblogic-rce-cve-2018-2628-rce-attempt",
            "name": "Oracle Weblogic RCE CVE-2018-2628",
            "description": "IP addresses with this tag have been observed attempting to exploit CVE-2018-2628, a remote code execution vulnerability through Java deserialization in Oracle Weblogic Server.",
            "category": "activity",
            "intention": "malicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-2018-2628",
              "https://www.exploit-db.com/exploits/44553"
            ],
            "cves": [
              "CVE-2018-2628"
            ],
            "recommend_block": true,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:05:13.816011Z"
          },
          {
            "id": "66edd69b-50b8-46de-b03c-b596a3d469ef",
            "slug": "pcworx-scanner",
            "name": "PCWorx Scanner",
            "description": "IP addresses with this tag have been observed attempting to discover ICS devices that respond over PCWorx protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://svn.nmap.org/nmap/scripts/pcworx-info.nse",
              "https://web.archive.org/web/20220421135319/https://sergiusechel.medium.com/misconfiguration-in-ilc-gsm-gprs-devices-leaves-over-1-200-ics-devices-vulnerable-to-attacks-over-82c2d4a91561"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-04-21",
            "updated_at": "2025-09-19T18:04:39.359457Z"
          },
          {
            "id": "8503c116-536a-4a12-bb77-c8250b6acf76",
            "slug": "phoenix-contact-plc-scanner",
            "name": "Phoenix Contact PLC Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet looking for Phoenix Contact PLCs.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "http://web.archive.org/web/20220415164534/http://select.phoenixcontact.com/phoenix/dwld/fl_il_24_bk_pac_um_e_6156_en_05.pdf?asid2=7757471351375"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:39.434342Z"
          },
          {
            "id": "788eb4be-0ffc-438d-92d6-d700df4fef72",
            "slug": "python-requests-client-scanner",
            "name": "Python Requests Client",
            "description": "IP addresses with this tag have been observed scanning the Internet with a client that uses the Python Requests library.",
            "category": "tool",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:40.470457Z"
          },
          {
            "id": "222cf79e-08a2-400a-a0b8-1c716aa43ec4",
            "slug": "rdp-crawler",
            "name": "RDP Crawler",
            "description": "IP addresses with this tag have been observed crawling the internet for Remote Desktop Protocol (RDP) by intiating a connection request.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee",
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-08-02",
            "updated_at": "2025-09-19T18:04:40.710457Z"
          },
          {
            "id": "e23d491c-6abf-477b-9073-dd9879f46a98",
            "slug": "radmin-scanner",
            "name": "Radmin Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet to identify devices using the Radmin protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:40.629256Z"
          },
          {
            "id": "77069c85-09a3-4322-bbf3-aefda8d46ae7",
            "slug": "sip-options-scanner",
            "name": "SIP OPTIONS Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for SIP devices using OPTIONS requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://tools.ietf.org/html/rfc3261#section-11.1"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:41.798534Z"
          },
          {
            "id": "5b840bfd-4377-4b9d-b2a2-beb8ddedc823",
            "slug": "smbv1-scanner",
            "name": "SMBv1 Crawler",
            "description": "IP addresses with this tag have been observed crawling the internet for SMBv1.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2021-04-02",
            "updated_at": "2025-09-19T18:04:41.949705Z"
          },
          {
            "id": "e3539e1d-46eb-4c4d-b708-e99c3487d804",
            "slug": "spdy-alpn-negotiation-attempt",
            "name": "SPDY ALPN Negotiation Attempt",
            "description": "IP addresses with this tag have been observed using Application-Layer Protocol Negotiation (ALPN) in the attempt to establish SPDY connections.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://en.wikipedia.org/wiki/SPDY",
              "https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-08-08",
            "updated_at": "2025-09-19T18:04:42.411345Z"
          },
          {
            "id": "b1859b91-92d5-48d2-b43d-bbfd09db964d",
            "slug": "ssh-alternative-port-scanner",
            "name": "SSH Alternative Port Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet for SSH servers running on ports other than 22/TCP.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:42.640042Z"
          },
          {
            "id": "537cee16-c4a9-45cd-baf1-75963ab7bdd2",
            "slug": "ssh-connection-attempt",
            "name": "SSH Connection Attempt",
            "description": "IP addresses with this tag have been observed attempting to negotiate an SSH session.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://en.wikipedia.org/wiki/Secure_Shell"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2024-09-30",
            "updated_at": "2025-09-19T18:04:42.684493Z"
          },
          {
            "id": "393fed60-f1eb-4376-af03-f92d966a54d6",
            "slug": "sitemap-crawler",
            "name": "Sitemap Crawler",
            "description": "IP addresses with this tag have been observed crawling for sitemap files.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://www.sitemaps.org/protocol.html"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-01-28",
            "updated_at": "2025-09-19T18:04:41.861502Z"
          },
          {
            "id": "567fdc14-d3ca-481e-9679-8c017dea4665",
            "slug": "t3-rmi-protocol-and-weblogic-version-check",
            "name": "T3 RMI Protocol and Weblogic Version Check",
            "description": "IP addresses with this tag have been observed checking for the T3 RMI protocol and Weblogic version.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://github.com/christophetd/nmap-nse-info/blob/master/test/data/weblogic-t3-info.nse"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-05-11",
            "updated_at": "2025-09-19T18:04:42.86112Z"
          },
          {
            "id": "ac32bdeb-b49d-4079-9e6b-8fbca5e0addf",
            "slug": "tls-ssl-scanner",
            "name": "TLS/SSL Crawler",
            "description": "IP addresses with this tag have been observed attempting to opportunistically crawl the Internet and establish TLS/SSL connections.",
            "category": "activity",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:43.187243Z"
          },
          {
            "id": "5aef9881-1b86-46fd-bad7-a794e90c6ab1",
            "slug": "tridium-niagraax-fox-ics-scanner",
            "name": "Tridium Niagara AX Fox ICS Scanner",
            "description": "IP addresses with this tag have been observed scanning the Internet for servers that communicate via the Fox ICS protocol.",
            "category": "activity",
            "intention": "suspicious",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-12-03",
            "updated_at": "2025-09-19T18:04:32.698006Z"
          },
          {
            "id": "869feaa1-dc77-4037-aee2-247b7a39cf7d",
            "slug": "web-scanner",
            "name": "Web Crawler",
            "description": "IP addresses with this tag have been seen crawling HTTP(S) servers around the Internet.",
            "category": "activity",
            "intention": "unknown",
            "references": [],
            "cves": [],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:04:44.706943Z"
          },
          {
            "id": "6c79246a-c56e-4dfa-85a8-b5239ade7f02",
            "slug": "x-server-connection-attempt",
            "name": "X Server CVE-1999-0526 Connection Attempt",
            "description": "IP addresses with this tag have been observed scanning the Internet for X11 servers with access control disabled, which allows for unauthenticated connections.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://nvd.nist.gov/vuln/detail/CVE-1999-0526",
              "https://www.cvedetails.com/cve/CVE-1999-0526/"
            ],
            "cves": [
              "CVE-1999-0526"
            ],
            "recommend_block": false,
            "created": "2020-04-07",
            "updated_at": "2025-09-19T18:05:30.324225Z"
          },
          {
            "id": "eae8d97d-08c6-4d03-9405-8099cf85af56",
            "slug": "iscsi-scanner",
            "name": "iSCSI Crawler",
            "description": "IP addresses with this tag have been observed crawling the Internet and attempting to discover hosts that respond to iSCSI login requests.",
            "category": "activity",
            "intention": "suspicious",
            "references": [
              "https://www.rfc-editor.org/rfc/rfc7143.html#section-11.2",
              "https://book.hacktricks.xyz/pentesting/3260-pentesting-iscsi"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2022-01-12",
            "updated_at": "2025-09-19T18:04:35.113556Z"
          },
          {
            "id": "215d03ae-6899-49dd-9167-4c22fe1e832d",
            "slug": "robots-txt-scanner",
            "name": "robots.txt Scanner",
            "description": "IP addresses with this tag have been observed checking for the existence of a 'robots.txt' file on the web server.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://datatracker.ietf.org/doc/html/rfc9309",
              "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
              "https://www.robotstxt.org/",
              "https://www.cloudflare.com/learning/bots/what-is-robots-txt/"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2023-10-05",
            "updated_at": "2025-09-19T18:04:40.835001Z"
          },
          {
            "id": "783551ed-1915-4771-8a4c-1c858dc02a6b",
            "slug": "sitemap-xml-crawler",
            "name": "sitemap.xml Crawler",
            "description": "IP addresses with this tag have been observed attempting to fetch a sitemap.xml file, which is a very common file used by search engines and crawlers.",
            "category": "activity",
            "intention": "unknown",
            "references": [
              "https://www.xml-sitemaps.com/",
              "https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap"
            ],
            "cves": [],
            "recommend_block": false,
            "created": "2025-08-19",
            "updated_at": "2025-09-19T18:04:41.882573Z"
          }
        ],
        "actor": "unknown",
        "spoofable": false,
        "classification": "malicious",
        "cves": [
          "CVE-1999-0526",
          "CVE-2021-38647",
          "CVE-2004-2687",
          "CVE-2010-0103",
          "CVE-2018-2628"
        ],
        "bot": false,
        "vpn": false,
        "vpn_service": "",
        "tor": false,
        "metadata": {
          "asn": "AS135377",
          "source_country": "United States",
          "source_country_code": "US",
          "source_city": "Reston",
          "domain": "ucloud.cn",
          "rdns_parent": "",
          "rdns_validated": false,
          "organization": "UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED",
          "category": "hosting",
          "rdns": "",
          "os": "",
          "sensor_count": 2764,
          "sensor_hits": 413129,
          "region": "Virginia",
          "mobile": false,
          "single_destination": false,
          "destination_countries": [
            "United States",
            "Germany",
            "Japan",
            "Spain",
            "Brazil",
            "India",
            "United Kingdom",
            "South Korea",
            "Singapore",
            "Indonesia",
            "Canada",
            "Hong Kong",
            "France",
            "Australia",
            "Mexico",
            "Netherlands",
            "Switzerland",
            "Finland",
            "Belgium",
            "Israel",
            "Taiwan",
            "Malaysia",
            "South Africa",
            "United Arab Emirates",
            "Pakistan",
            "Ireland",
            "Peru",
            "Ukraine",
            "Italy",
            "Thailand",
            "New Zealand",
            "Poland",
            "Hungary",
            "Russia",
            "Greece",
            "Belarus",
            "Bulgaria",
            "Luxembourg",
            "Romania",
            "Norway",
            "Turkey",
            "Austria",
            "Estonia",
            "Slovakia",
            "Sweden",
            "Bahrain",
            "Croatia",
            "Kuwait",
            "Chile",
            "Kazakhstan",
            "Saudi Arabia",
            "Ghana",
            "Latvia",
            "Iceland",
            "Czech Republic",
            "Denmark",
            "Ecuador",
            "Portugal",
            "Qatar",
            "Moldova",
            "Iraq",
            "Georgia",
            "Kenya",
            "Lithuania",
            "Slovenia",
            "Colombia",
            "Cambodia",
            "Serbia"
          ],
          "destination_country_codes": [
            "US",
            "DE",
            "ES",
            "JP",
            "BR",
            "IN",
            "GB",
            "KR",
            "SG",
            "ID",
            "CA",
            "HK",
            "FR",
            "AU",
            "MX",
            "NL",
            "CH",
            "FI",
            "BE",
            "IL",
            "TW",
            "MY",
            "ZA",
            "AE",
            "PK",
            "IE",
            "PE",
            "UA",
            "IT",
            "TH",
            "NZ",
            "PL",
            "HU",
            "RU",
            "GR",
            "BY",
            "BG",
            "LU",
            "RO",
            "NO",
            "TR",
            "AT",
            "EE",
            "SK",
            "SE",
            "BH",
            "HR",
            "KW",
            "CL",
            "KZ",
            "SA",
            "GH",
            "LV",
            "IS",
            "CZ",
            "DK",
            "EC",
            "PT",
            "QA",
            "MD",
            "IQ",
            "GE",
            "KE",
            "LT",
            "SI",
            "CO",
            "KH",
            "RS"
          ],
          "destination_asns": [
            "AS396982",
            "AS16509",
            "AS14061",
            "AS20473",
            "AS8075",
            "AS174",
            "AS63949",
            "AS45102",
            "AS6939",
            "AS44477",
            "AS138915",
            "AS14618",
            "AS35487",
            "AS209847",
            "AS206804",
            "AS61138",
            "AS44709",
            "AS16276",
            "AS49720",
            "AS57695",
            "AS56740",
            "AS57578",
            "AS57169",
            "AS1257",
            "AS61317",
            "AS62005",
            "AS210772",
            "AS50837",
            "AS327813",
            "AS7195",
            "AS136258",
            "AS202422",
            "AS204932",
            "AS50979",
            "AS7590",
            "AS204957",
            "AS59729",
            "AS15626",
            "AS23966",
            "AS57814",
            "AS44812",
            "AS9678"
          ],
          "destination_cities": [
            "Washington",
            "Frankfurt am Main",
            "Englewood",
            "New Orleans",
            "Federal Way",
            "São Paulo",
            "San Sebastián de los Reyes",
            "London",
            "Columbus",
            "Singapore",
            "Mumbai",
            "North Charleston",
            "Jakarta",
            "Santa Clara",
            "North Bergen",
            "Seoul",
            "Salt Lake City",
            "Indianapolis",
            "Hong Kong",
            "Los Angeles",
            "Council Bluffs",
            "Ashburn",
            "Las Vegas",
            "Tokyo",
            "Paris",
            "General Lázaro Cárdenas",
            "Boardman",
            "Sydney",
            "The Dalles",
            "Toronto",
            "Montréal",
            "Zürich",
            "Incheon",
            "Atlanta",
            "Osaka",
            "Virginia Beach",
            "New York City",
            "Brussels",
            "Lappeenranta",
            "San Jose",
            "Taipei",
            "Bāshettihalli",
            "Kuala Lumpur",
            "San Antonio",
            "Cheyenne",
            "Dallas",
            "Dublin",
            "Ōi",
            "Dubai",
            "Lima",
            "Amsterdam",
            "Elk Grove Village",
            "Kyiv",
            "Fremont",
            "Groningen",
            "Pune",
            "St. Louis",
            "Chicago",
            "Milan",
            "Tel Aviv",
            "Cape Town",
            "Cedar Knolls",
            "Karachi",
            "Kent",
            "Piscataway",
            "Newark",
            "Bangkok",
            "Petaẖ Tiqva",
            "Mount Eden",
            "Warsaw",
            "Nashville",
            "Budapest",
            "Miami",
            "Santiago de Querétaro",
            "Melbourne",
            "Minsk",
            "Bucharest",
            "Luxembourg",
            "Sofia",
            "Haarlem",
            "Istanbul",
            "Oslo",
            "Johannesburg",
            "Rawalpindi",
            "Saint Petersburg",
            "Aubervilliers",
            "Bratislava",
            "Tallinn",
            "Richardson",
            "Stockholm",
            "Dār Kulayb",
            "Kuwait City",
            "Zagreb",
            "Almaty",
            "Santiago",
            "Riyadh",
            "Accra",
            "Athens",
            "Rosh Ha‘Ayin",
            "Chennai",
            "Málaga",
            "Riga",
            "Volos",
            "Graz",
            "Reykjavík",
            "Braga",
            "Copenhagen",
            "Doha",
            "Prague",
            "Quito",
            "Al Fujairah City",
            "Vienna",
            "Chisinau",
            "Baghdad",
            "Helsinki",
            "Mexico City",
            "Nairobi",
            "Tbilisi",
            "Vilnius",
            "Kansas City",
            "Osasco",
            "Bexley",
            "Haifa",
            "Ljubljana",
            "Moscow",
            "Barrio San Luis",
            "Belgrade",
            "Lake Ridge",
            "Meppel",
            "Phnom Penh",
            "Leesburg",
            "Minneapolis",
            "Calais"
          ],
          "carrier": "",
          "datacenter": "",
          "longitude": -77.3411,
          "latitude": 38.9687
        },
        "raw_data": {
          "scan": [],
          "ja3": [],
          "hassh": [],
          "http": {
            "md5": [],
            "cookie_keys": [],
            "request_authorization": [],
            "request_cookies": [],
            "request_header": [],
            "method": [],
            "path": [],
            "request_origin": [],
            "useragent": []
          },
          "source": {
            "bytes": 0
          },
          "tls": {
            "cipher": [],
            "ja4": []
          },
          "ssh": {
            "key": []
          }
        },
        "last_seen_timestamp": "2025-09-19 16:56:03"
      }
    }
  ],
  "request_metadata": {
    "restricted_fields": [],
    "scroll": "FGluY2x1ZGVfY29udGV4dF91dWlkDnF1ZXJ5VGhlbkZldGNoAhZZTHg2X2Z4OVJzLWVCcm13R1JreWZBAAAAAAZX1wAWT2hKVjdSZ2dTMzJhMzFPWHJuWl9vdxZ3SXE5a1ZtRFJheTJqQ3psS0pSYm53AAAAAAd_5xQWcElNWXYtVlhRYzJzU0tGaUNSSnFOdw==",
    "message": "",
    "query": "tags:\"MCP and SSE endpoint scanning\" classification:malicious",
    "complete": false,
    "count": 147,
    "adjusted_query": "(tags:\"MCP and SSE endpoint scanning\" classification:malicious) last_seen:90d"
  }
}
```

# IP Timeline

Retrieve an IP address' summary of noise activity for a specific field.

Query params:

- `days`: string; Number of days to show data for (Defaults to 1)
- `field`: string/enum; Field over which to show activity breakdown (Defaults to `classification`; required)
    - classification
    - destination_port
    - http_path
    - http_user_agent
    - source_asn
    - source_org
    - source_rdns
    - tag_ids
    - classification
- `granularity`: string; Granularity of activity date ranges. This can be in hours (e.g. Xh) or days (Xd). Valid hours are between 1 and 24. Valid days are between 1 and 90. (Defaults to 1d)

Request:

```bash
curl --request GET \
     --url 'https://api.greynoise.io/v3/noise/ips/45.141.86.201/timeline?days=30&field=source_asn' \
     --header 'accept: application/json' \
     --header 'key: GREYNOISE_API_KEY'
```

Response:

```json
{
  "metadata": {
    "ip": "45.141.86.201",
    "field": "source_asn",
    "first_seen": "2024-10-14",
    "start": "2025-08-20T18:20:26.099130849Z",
    "end": "2025-09-19T18:20:26.099130849Z",
    "granularity": "1d",
    "metric": "count"
  },
  "results": [
    {
      "data": 1,
      "label": "AS206728",
      "timestamp": "2025-09-19T00:00:00Z"
    },
    {
      "data": 1,
      "label": "AS206728",
      "timestamp": "2025-09-18T00:00:00Z"
    },
    {
      "data": 1,
      "label": "AS206728",
      "timestamp": "2025-09-17T00:00:00Z"
    },
    {
      "data": 1,
      "label": "AS206728",
      "timestamp": "2025-09-16T00:00:00Z"
    },
    {
      "data": 1,
      "label": "AS206728",
      "timestamp": "2025-09-15T00:00:00Z"
    },
    {
      "data": 1,
      "label": "AS206728",
      "timestamp": "2025-09-14T00:00:00Z"
    },
    {
      "data": 1,
      "label": "AS206728",
      "timestamp": "2025-08-28T00:00:00Z"
    }
  ]
}
```
