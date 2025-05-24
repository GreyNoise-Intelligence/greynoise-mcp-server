import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GnqlStatsResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatGnqlStats } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerGnqlStatsTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "gnql-stats",
    `
Get aggregate statistics for results matching a GreyNoise GNQL query.

GNQL (GreyNoise Query Language) is a domain-specific query language that uses Lucene deep under the hood.

Facets:

- "ip" - The IP address of the scanning device IP
- "classification" - Whether the device has been categorized as unknown, benign, or malicious
- "first_seen" - The date the device was first observed by GreyNoise
- "last_seen" - The date the device was most recently observed by GreyNoise
- "actor" - The benign actor the device has been associated with, such as Shodan, Censys, GoogleBot, etc
- "tags" - A list of the tags the device has been assigned over the past 90 days
- "spoofable" - This IP address has been opportunistically scanning the Internet, however has failed to complete a full TCP connection. Any reported activity could be spoofed.
- "vpn" - This IP is associated with a VPN service. Activity, malicious or otherwise, should not be attributed to the VPN service provider.
- "vpn_service" - The VPN service the IP is associated with
- "cve" - A list of CVEs that the device has been associated with
- "bot" - If the IP is known to belong to a known BOT
- "single_destination" - A boolean parameter that filters source country IPs that have only been observed in a single destination country
- "metadata.category" - Whether the device belongs to a business, isp, hosting, education, or mobile network
- "metadata.country" - The full name of the country the device is geographically located in (This is the same data as "metadata.source_country". "metadata.source_country" is preferred)
- "metadata.country_code" - The two-character country code of the country the device is geographically located in (This is the same data as "metadata.source_country_code". "metadata.source_country_code" is preferred)
- "metadata.sensor_hits" - The amount of unique data that has been recorded by the sensor
- "metadata.sensor_count" - The number of sensors the IP Address has been observed on
- "metadata.city" - The city the device is geographically located in
- "metadata.region" - The region the device is geographically located in
- "metadata.organization" - The organization that owns the network that the IP address belongs to
- "metadata.rdns" - The reverse DNS pointer of the IP
- "metadata.asn" - The autonomous system the IP address belongs to
- "metadata.tor" - Whether or not the device is a known Tor exit node
- "metadata.destination_country" - The full name where the GreyNoise sensor is physically located
- "metadata.destination_country_code" - The country code where GreyNoise sensor is physically located
- "metadata.source_country_code" - The two-character country code of the country the device is geographically located in
- "metadata.source_country" - The full name of the country the device is geographically located in
- "raw_data.scan.port" - The port number(s) the devices has been observed scanning
- "raw_data.scan.protocol" - The protocol of the port the device has been observed scanning
- "raw_data.web.paths" - Any HTTP paths the device has been observed crawling the Internet for
- "raw_data.web.useragents" - Any HTTP user-agents the device has been observed using while crawling the Internet
- "raw_data.ja3.fingerprint" - The JA3 TLS/SSL fingerprint
- "raw_data.ja3.port" - The corresponding TCP port for the given JA3 fingerprint
- "raw_data.hassh.fingerprint" - The HASSH fingerprint
- "raw_data.hassh.port" - The corresponding TCP port for the given HASSH fingerprint

Behavior:

- You can subtract facets by prefacing the query with a minus character
- The data that this endpoint queries refreshes once per hour

Shortcuts:

- You can find interesting hosts by using the GNQL query term "interesting"
- You can use the keyword "today" in the "first_seen" and "last_seen" parameters: "last_seen:today" or "first_seen:today"

Examples:

- "last_seen:today" - Returns all IPs scanning/crawling the Internet today
- "tags:Mirai" - Returns all devices with the "Mirai" tag
- "tags:"RDP Scanner"" - Returns all devices with the "RDP Scanner" tag
- "classification:malicious metadata.country:Belgium" — Returns all compromised devices located in Belgium
- "classification:malicious metadata.rdns:*.gov*" - Returns all compromised devices that include .gov in their reverse DNS records
- "metadata.organization:Microsoft classification:malicious" — Returns all compromised devices that belong to Microsoft
- "(raw_data.scan.port:445 and raw_data.scan.protocol:TCP) metadata.os:Windows*" - Return all devices scanning the Internet for port 445/TCP running Windows operating systems (Conficker/EternalBlue/WannaCry)
- "raw_data.scan.port:554" - Returns all devices scanning the Internet for port 554
- "-metadata.organization:Google raw_data.web.useragents:GoogleBot" — Returns all devices crawling the Internet with "GoogleBot" in their useragent from a network that does NOT belong to Google
- "tags:"Siemens PLC Scanner" -classification:benign" - Returns all devices scanning the Internet for SCADA devices who ARE NOT tagged by GreyNoise as "benign" (Shodan/Project Sonar/Censys/Google/Bing/etc)
- "classification:benign" - Returns all "good guys" scanning the Internet
- "raw_data.ja3.fingerprint:795bc7ce13f60d61e9ac03611dd36d90" — Returns all devices crawling the Internet with a matching client JA3 TLS/SSL fingerprint
- "raw_data.hassh.fingerprint:51cba57125523ce4b9db67714a90bf6e" — Returns all devices crawling the Internet with a matching client HASSH fingerprint
- "raw_data.web.paths:"/HNAP1/"" -Returns all devices crawling the Internet for the HTTP path "/HNAP1/"
- "8.0.0.0/8" - Returns all devices scanning the Internet from the CIDR block 8.0.0.0/8
- "cve:CVE-2021-30461" - Returns all devices associated with the supplied CVE
- "source_country:Iran" - Returns all results originating from Iran
- "destination_country:Ukraine single_destination:true" — Returns all results scanning in only Ukraine
`,
    {
      query: z.string().describe("GNQL query string (e.g., 'classification:malicious last_seen:30d')"),
      count: z.number().min(1).max(10000).default(10).describe("Number of top aggregate results to return (1-10000)"),
    },
    async ({ query, count }) => {
      try {
        // Get API key from context or fallback function
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        // Encode the GNQL query for URL
        const encodedQuery = encodeURIComponent(query);

        // Get statistics for the query
        const statsData = await fetchGreyNoise<GnqlStatsResponse>(
          `v2/experimental/gnql/stats?query=${encodedQuery}&count=${count}`,
          apiBase,
          apiKey,
          {},
        );

        // Format a readable response
        const formattedResponse = formatGnqlStats(statsData);

        return {
          content: [
            {
              type: "text",
              text: formattedResponse,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error querying GNQL stats: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
