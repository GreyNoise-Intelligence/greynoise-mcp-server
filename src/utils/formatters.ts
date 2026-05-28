import {
  GnqlStatsResponse,
  IPContextResponse,
  IPQuickCheckV3Response,
  MultiIPV3Response,
  GnqlQueryResponse,
  GnqlMetadataQueryResponse,
  GnqlTimeseriesResponse,
  GnqlTimeseriesStatsResponse,
  CVEDetailsResponse,
  SessionResponse,
} from "../types/greynoise-response.js";

/**
 * Formats a GNQL stats response into a detailed Markdown string with full breakdown of all statistics.
 *
 * @param {GnqlStatsResponse} data - The GNQL stats response data from the GreyNoise API
 * @returns {string} A formatted Markdown string containing the detailed breakdown of GNQL stats
 *
 * @example
 * const formattedStats = formatGnqlStats(gnqlStatsResponse);
 * console.log(formattedStats); // Prints detailed Markdown with all available stats
 */
export function formatGnqlStats(data: GnqlStatsResponse): string {
  let response = `# GNQL Stats Results\n\n`;
  response += `Query: \`${data.query}\`\n\n`;
  if (data.adjusted_query) {
    response += `Adjusted Query: \`${data.adjusted_query}\`\n\n`;
  }
  response += `Found ${data.count.toLocaleString()} matching IPs.\n\n`;

  // Add classification breakdown
  if (data.stats.classifications && data.stats.classifications.length > 0) {
    response += `## Classification Breakdown\n\n`;
    for (const item of data.stats.classifications) {
      response += `- **${item.classification}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add spoofable breakdown
  if (data.stats.spoofable && data.stats.spoofable.length > 0) {
    response += `## Spoofable Status\n\n`;
    for (const item of data.stats.spoofable) {
      response += `- **${item.spoofable ? "Spoofable" : "Not Spoofable"}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add organization breakdown
  if (data.stats.organizations && data.stats.organizations.length > 0) {
    response += `## Top Organizations\n\n`;
    for (const item of data.stats.organizations) {
      response += `- **${item.organization}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add actors breakdown if available
  if (data.stats.actors && data.stats.actors.length > 0) {
    response += `## Actors\n\n`;
    for (const item of data.stats.actors) {
      response += `- **${item.actor}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add countries breakdown
  if (data.stats.countries && data.stats.countries.length > 0) {
    response += `## Top Countries\n\n`;
    for (const item of data.stats.countries) {
      response += `- **${item.country}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add source countries breakdown
  if (data.stats.source_countries && data.stats.source_countries.length > 0) {
    response += `## Top Source Countries\n\n`;
    for (const item of data.stats.source_countries) {
      response += `- **${item.country}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add destination countries breakdown
  if (data.stats.destination_countries && data.stats.destination_countries.length > 0) {
    response += `## Top Destination Countries\n\n`;
    for (const item of data.stats.destination_countries) {
      response += `- **${item.country}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add tag breakdown
  if (data.stats.tags && data.stats.tags.length > 0) {
    response += `## Top Tags\n\n`;
    for (const item of data.stats.tags) {
      response += `- **${item.tag}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add operating systems breakdown if available
  if (data.stats.operating_systems && data.stats.operating_systems.length > 0) {
    response += `## Operating Systems\n\n`;
    for (const item of data.stats.operating_systems) {
      response += `- **${item.operating_system}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add categories breakdown if available
  if (data.stats.categories && data.stats.categories.length > 0) {
    response += `## Categories\n\n`;
    for (const item of data.stats.categories) {
      response += `- **${item.category}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add ASNs breakdown if available
  if (data.stats.asns && data.stats.asns.length > 0) {
    response += `## Top ASNs\n\n`;
    for (const item of data.stats.asns) {
      response += `- **${item.asn}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  return response;
}

/**
 * Formats CVE details into a readable Markdown string.
 *
 * @param {CVEDetailsResponse} data - The CVE details response from the GreyNoise API
 * @returns {string} A formatted Markdown string containing detailed information about the CVE
 *
 * @example
 * const formattedCVE = formatCVEDetails(cveResponse);
 * console.log(formattedCVE); // Prints detailed Markdown about the CVE
 */
export function formatCVEDetails(data: CVEDetailsResponse): string {
  let response = `# CVE Details: ${data.id}\n\n`;

  // Basic vulnerability info
  response += `## Vulnerability Information\n\n`;
  response += `**Name**: ${data.details.vulnerability_name}\n`;
  response += `**Description**: ${data.details.vulnerability_description}\n`;
  response += `**CVSS Score**: ${data.details.cve_cvss_score}\n`;
  response += `**Product**: ${data.details.product}\n`;
  response += `**Vendor**: ${data.details.vendor}\n`;
  response += `**Published to NIST NVD**: ${data.details.published_to_nist_nvd ? "Yes" : "No"}\n\n`;

  // Timeline
  response += `## Timeline\n\n`;
  response += `**Published Date**: ${new Date(data.timeline.cve_published_date).toLocaleString()}\n`;
  response += `**Last Updated**: ${new Date(data.timeline.cve_last_updated_date).toLocaleString()}\n`;
  response += `**First Known Publication**: ${new Date(data.timeline.first_known_published_date).toLocaleString()}\n`;
  if (data.timeline.cisa_kev_date_added) {
    response += `**Added to CISA KEV**: ${new Date(data.timeline.cisa_kev_date_added).toLocaleString()}\n`;
  }
  response += `\n`;

  // Exploitation details
  response += `## Exploitation Details\n\n`;
  response += `**Attack Vector**: ${data.exploitation_details.attack_vector}\n`;
  response += `**Exploit Found**: ${data.exploitation_details.exploit_found ? "Yes" : "No"}\n`;
  response += `**In CISA Known Exploited Vulnerabilities Catalog**: ${data.exploitation_details.exploitation_registered_in_kev ? "Yes" : "No"}\n`;
  response += `**EPSS Score**: ${(data.exploitation_details.epss_score * 100).toFixed(2)}% (probability of exploitation)\n\n`;

  // Exploitation stats
  response += `## Exploitation Statistics\n\n`;
  response += `**Available Exploits**: ${data.exploitation_stats.number_of_available_exploits}\n`;
  response += `**Threat Actors Exploiting**: ${data.exploitation_stats.number_of_threat_actors_exploiting_vulnerability}\n`;
  response += `**Botnets Exploiting**: ${data.exploitation_stats.number_of_botnets_exploiting_vulnerability}\n\n`;

  // Activity observed
  response += `## Observed Activity\n\n`;
  response += `**Activity Seen by GreyNoise**: ${data.exploitation_activity.activity_seen ? "Yes" : "No"}\n\n`;

  if (data.exploitation_activity.activity_seen) {
    response += `### Benign IP Counts\n`;
    response += `- **Last 24 hours**: ${data.exploitation_activity.benign_ip_count_1d}\n`;
    response += `- **Last 10 days**: ${data.exploitation_activity.benign_ip_count_10d}\n`;
    response += `- **Last 30 days**: ${data.exploitation_activity.benign_ip_count_30d}\n\n`;

    response += `### Malicious IP Counts\n`;
    response += `- **Last 24 hours**: ${data.exploitation_activity.threat_ip_count_1d}\n`;
    response += `- **Last 10 days**: ${data.exploitation_activity.threat_ip_count_10d}\n`;
    response += `- **Last 30 days**: ${data.exploitation_activity.threat_ip_count_30d}\n`;
  }

  return response;
}

/**
 * Formats trending vulnerability tags into a readable Markdown string.
 *
 * @param {Object} data - The trending tags response data
 * @param {number} data.count - The number of trending tags
 * @param {Array<any>} data.tags - Array of trending tag objects
 * @returns {string} A formatted Markdown string containing information about trending vulnerability tags
 *
 * @example
 * const formattedTrends = formatTrendingTags(trendingTagsResponse);
 * console.log(formattedTrends); // Prints Markdown with trending vulnerability information
 */
export function formatTrendingTags(data: { count: number; tags: any[] }): string {
  let response = `# GreyNoise Vulnerability Tags

`;
  if (data.count === 0) {
    return response + "No vulnerability tags found.";
  }

  response += `Found ${data.count} vulnerability tags:\n\n`;
  data.tags.forEach((tag, index) => {
    response += `## ${index + 1}. ${tag.name}`;
    
    // Add source (trending or anomalies) if available
    if (tag.source) {
      response += ` (${tag.source.charAt(0).toUpperCase() + tag.source.slice(1)})`;
    }
    
    response += `\n\n`;
    response += `- **Category**: ${tag.category}\n`;
    response += `- **Intention**: ${tag.intention}\n`;
    response += `- **Created**: ${tag.created_at}\n`;
    response += `- **Trend Score**: ${tag.score.toFixed(2)}\n`;
    if (tag.cves && tag.cves.length > 0) {
      response += `- **CVEs**: ${tag.cves.join(", ")}\n`;
    }
    response += "\n";
  });

  return response;
}

// ─── v3 Session Formatter ─────────────────────────────────────────────────────

function formatTimestamp(value: any): string {
  if (value === undefined || value === null) return "N/A";
  if (typeof value === "number") return new Date(value).toISOString();
  return String(value);
}

// Fields promoted into structured sections (excluded from "Additional")
const SESSION_PROMOTED_FIELDS = new Set([
  "_id", "id",
  "firstPacket", "lastPacket",
  "source", "destination",
  "source.ip", "source.port", "source.bytes", "source.packets",
  "destination.ip", "destination.port", "destination.bytes", "destination.packets",
  "classification",
]);

export function formatSession(data: SessionResponse): string {
  const id = data._id ?? data["id"] ?? "unknown";
  // API returns source/destination as nested objects OR flat dot-notation keys
  const src = data.source as Record<string, any> | undefined;
  const dst = data.destination as Record<string, any> | undefined;
  const srcIp = src?.ip ?? data["source.ip"] ?? "N/A";
  const srcPort = src?.port ?? data["source.port"] ?? "N/A";
  const dstIp = dst?.ip ?? data["destination.ip"] ?? "N/A";
  const dstPort = dst?.port ?? data["destination.port"] ?? "N/A";
  const srcBytes = src?.bytes ?? data["source.bytes"] ?? 0;
  const srcPackets = src?.packets ?? data["source.packets"] ?? 0;
  const dstBytes = dst?.bytes ?? data["destination.bytes"] ?? 0;
  const dstPackets = dst?.packets ?? data["destination.packets"] ?? 0;
  const classification = data.classification;
  const firstPacket = data.firstPacket;
  const lastPacket = data.lastPacket;

  let response = `# Session: ${id}\n\n`;

  response += `## Connection\n\n`;
  response += `**Source**: ${srcIp}:${srcPort}\n`;
  response += `**Destination**: ${dstIp}:${dstPort}\n`;
  if (classification) response += `**Classification**: ${classification}\n`;
  response += `\n`;

  response += `## Timing\n\n`;
  response += `**First Packet**: ${formatTimestamp(firstPacket)}\n`;
  response += `**Last Packet**: ${formatTimestamp(lastPacket)}\n\n`;

  response += `## Traffic\n\n`;
  response += `| Direction | Bytes | Packets |\n`;
  response += `|--|--|--|\n`;
  response += `| Source | ${Number(srcBytes).toLocaleString()} | ${Number(srcPackets).toLocaleString()} |\n`;
  response += `| Destination | ${Number(dstBytes).toLocaleString()} | ${Number(dstPackets).toLocaleString()} |\n\n`;

  // Append any additional dynamic fields
  const extraFields = Object.entries(data).filter(([key]) => !SESSION_PROMOTED_FIELDS.has(key));
  if (extraFields.length > 0) {
    response += `## Additional Fields\n\n`;
    for (const [key, value] of extraFields) {
      const displayValue = typeof value === "object" ? JSON.stringify(value) : String(value);
      response += `**${key}**: ${displayValue}\n`;
    }
    response += `\n`;
  }

  return response;
}

// ─── Helper ──────────────────────────────────────────────────────────────────

function truncateList(items: string[], max: number): string {
  if (items.length <= max) return items.join(", ");
  return items.slice(0, max).join(", ") + ` (and ${items.length - max} more)`;
}

// ─── v3 IP Context Formatter ─────────────────────────────────────────────────

export function formatIPContext(data: IPContextResponse): string {
  if (!data || data.ip === undefined) {
    return "# IP Not Found\n\nThis IP address was not found in the GreyNoise database.";
  }

  const isi = data.internet_scanner_intelligence;
  const bsi = data.business_service_intelligence;
  const meta = isi?.metadata;
  const raw = isi?.raw_data;

  let response = `# GreyNoise IP Context: ${data.ip}\n\n`;

  // Status & classification
  response += `**Classification**: ${isi?.classification ? isi.classification.toUpperCase() : 'NOT FOUND'}\n`;
  response += `**Scanner Found**: ${isi?.found ? "Yes" : "No"}\n`;
  response += `**BSI Found**: ${bsi?.found ? "Yes" : "No"}\n`;
  if (isi?.first_seen) response += `**First Seen**: ${isi.first_seen}\n`;
  if (isi?.last_seen) response += `**Last Seen**: ${isi.last_seen}\n`;
  response += `\n`;

  // Business Service Intelligence
  if (bsi?.found) {
    response += `## Business Service Intelligence\n\n`;
    if (bsi.name) response += `**Name**: ${bsi.name}\n`;
    if (bsi.category) response += `**Category**: ${bsi.category}\n`;
    if (bsi.description) response += `**Description**: ${bsi.description}\n`;
    if (bsi.trust_level) response += `**Trust Level**: ${bsi.trust_level}\n`;
    if (bsi.reference) response += `**Reference**: ${bsi.reference}\n`;
    if (bsi.last_updated) response += `**Last Updated**: ${bsi.last_updated}\n`;
    response += `\n`;
  }

  // Organization details
  response += `## Organization Details\n\n`;
  response += `**Organization**: ${meta?.organization || 'Unknown'}\n`;
  response += `**Category**: ${meta?.category || 'Unknown'}\n`;
  response += `**ASN**: ${meta?.asn || 'Unknown'}\n`;
  response += `**Actor**: ${isi?.actor && isi.actor !== "unknown" ? isi.actor : "Unknown"}\n`;
  if (meta?.domain) response += `**Domain**: ${meta.domain}\n`;
  if (meta?.datacenter) response += `**Datacenter**: ${meta.datacenter}\n`;
  if (meta?.carrier) response += `**Carrier**: ${meta.carrier}\n`;
  if (meta?.mobile) response += `**Mobile**: Yes\n`;
  response += `\n`;

  // Location information
  response += `## Location Information\n\n`;
  response += `**Country**: ${meta?.source_country || 'Unknown'} ${meta?.source_country_code ? `(${meta.source_country_code})` : ''}\n`;
  if (meta?.source_city) response += `**City**: ${meta.source_city}\n`;
  if (meta?.region) response += `**Region**: ${meta.region}\n`;
  if (meta?.rdns) response += `**Reverse DNS**: ${meta.rdns}\n`;
  if (meta?.rdns_parent) response += `**rDNS Parent**: ${meta.rdns_parent}\n`;
  if (meta?.rdns_validated !== undefined) response += `**rDNS Validated**: ${meta.rdns_validated ? "Yes" : "No"}\n`;
  if (meta?.latitude !== undefined && meta?.longitude !== undefined) {
    response += `**Coordinates**: ${meta.latitude}, ${meta.longitude}\n`;
  }
  response += `**Operating System**: ${meta?.os && meta.os !== "unknown" ? meta.os : "Unknown"}\n\n`;

  // Activity details
  response += `## Activity Details\n\n`;
  if (isi?.tags && isi.tags.length > 0) {
    const tagList = isi.tags.map(t => `${t.name} (${t.intention})`);
    response += `**Tags**: ${truncateList(tagList, 15)}\n`;
    const blockTags = isi.tags.filter(t => t.recommend_block);
    if (blockTags.length > 0) {
      response += `**Recommend Block**: ${blockTags.map(t => t.name).join(", ")}\n`;
    }
  } else {
    response += `**Tags**: None\n`;
  }
  if (isi?.cves && isi.cves.length > 0) response += `**CVEs**: ${truncateList(isi.cves, 10)}\n`;
  response += `**Sensor Hits**: ${meta?.sensor_hits || 0} hits across ${meta?.sensor_count || 0} sensors\n`;

  // Flags
  response += `**Bot**: ${isi?.bot ? "Yes" : "No"}\n`;
  response += `**Tor Exit Node**: ${isi?.tor ? "Yes" : "No"}\n`;
  response += `**VPN**: ${isi?.vpn ? "Yes" : "No"}\n`;
  if (isi?.vpn && isi?.vpn_service) response += `**VPN Service**: ${isi.vpn_service}\n`;
  response += `**Spoofable**: ${isi?.spoofable ? "Yes" : "No"}\n\n`;

  // Scanning activity
  if (raw?.scan && raw.scan.length > 0) {
    const scanPorts = raw.scan.map((s) => `${s.port}/${s.protocol}`);
    response += `## Scanning Activity\n\n`;
    response += `**Scanned Ports**: ${truncateList(scanPorts, 20)}\n\n`;
  }

  // Destination countries
  if (meta?.destination_countries && meta.destination_countries.length > 0) {
    response += `## Target Countries\n\n`;
    response += `**Targeting**: ${truncateList(meta.destination_countries, 10)}\n`;
    if (meta.single_destination) response += `**Single Destination**: Yes\n`;
    response += `\n`;
  }

  // HTTP Activity
  if (raw?.http) {
    const h = raw.http;
    const hasContent = h.path?.length || h.useragent?.length || h.method?.length || h.host?.length;
    if (hasContent) {
      response += `## HTTP Activity\n\n`;
      if (h.method?.length) response += `**Methods**: ${truncateList(h.method, 10)}\n`;
      if (h.path?.length) response += `**Paths**: ${truncateList(h.path, 10)}\n`;
      if (h.useragent?.length) response += `**User Agents**: ${truncateList(h.useragent, 5)}\n`;
      if (h.host?.length) response += `**Hosts**: ${truncateList(h.host, 10)}\n`;
      if (h.ja4h?.length) response += `**JA4H**: ${truncateList(h.ja4h, 5)}\n`;
      response += `\n`;
    }
  }

  // TLS/SSL fingerprints
  const hasJa3 = raw?.ja3 && raw.ja3.length > 0;
  const hasJa4 = raw?.tls?.ja4 && raw.tls.ja4.length > 0;
  if (hasJa3 || hasJa4 || raw?.tls?.cipher) {
    response += `## TLS/SSL Fingerprints\n\n`;
    if (raw?.tls?.cipher) response += `**Cipher**: ${raw.tls.cipher}\n`;
    if (hasJa3) {
      const fps = [...new Set(raw!.ja3!.map((j) => j.fingerprint))];
      response += `**JA3**: ${truncateList(fps, 5)}\n`;
    }
    if (hasJa4) {
      response += `**JA4**: ${truncateList(raw!.tls!.ja4!, 5)}\n`;
    }
    response += `\n`;
  }

  // SSH fingerprints
  const hasHashh = raw?.hassh && raw.hassh.length > 0;
  const hasSsh = raw?.ssh;
  if (hasHashh || hasSsh?.ja4ssh?.length || hasSsh?.key?.length) {
    response += `## SSH Fingerprints\n\n`;
    if (hasHashh) {
      const fps = [...new Set(raw!.hassh!.map((h) => h.fingerprint))];
      response += `**HASSH**: ${truncateList(fps, 5)}\n`;
    }
    if (hasSsh?.ja4ssh?.length) response += `**JA4SSH**: ${truncateList(hasSsh.ja4ssh, 5)}\n`;
    if (hasSsh?.key?.length) response += `**Keys**: ${truncateList(hasSsh.key, 3)}\n`;
    response += `\n`;
  }

  // TCP fingerprints
  if (raw?.tcp?.ja4t?.length || raw?.tcp?.ja4l) {
    response += `## TCP Fingerprints\n\n`;
    if (raw.tcp.ja4t?.length) response += `**JA4T**: ${truncateList(raw.tcp.ja4t, 5)}\n`;
    if (raw.tcp.ja4l) response += `**JA4L**: ${raw.tcp.ja4l}\n`;
    response += `\n`;
  }

  // Source bytes
  if (raw?.source?.bytes) {
    response += `**Source Bytes**: ${raw.source.bytes.toLocaleString()}\n\n`;
  }

  // Restricted fields note
  if (data.request_metadata?.restricted_fields && data.request_metadata.restricted_fields.length > 0) {
    response += `---\n**Note:** Some fields are restricted by your API plan: ${data.request_metadata.restricted_fields.join(", ")}\n`;
  }

  return response;
}

// ─── v3 Quick Check Formatter ────────────────────────────────────────────────

export function formatQuickCheckV3(data: IPQuickCheckV3Response): string {
  let response = `## IP Quick Check: ${data.ip}\n\n`;

  const isi = data.internet_scanner_intelligence;
  const bsi = data.business_service_intelligence;

  response += `**Scanner Intelligence**: ${isi.found ? `Found - ${isi.classification?.toUpperCase() || "UNKNOWN"}` : "Not found"}\n`;
  response += `**Business Service**: ${bsi.found ? `Found${bsi.trust_level ? ` - Trust: ${bsi.trust_level}` : ""}` : "Not found"}\n`;

  return response;
}

// ─── v3 Multi-IP Formatter ───────────────────────────────────────────────────

export function formatMultiIPV3(data: MultiIPV3Response): string {
  const results = data.data;
  let response = `## Multi IP Check Results\n\n`;

  // Summary counts
  const total = results.length;
  const classificationCounts: Record<string, number> = {};
  let bsiCount = 0;
  for (const r of results) {
    const cls = r.internet_scanner_intelligence?.classification || "unknown";
    classificationCounts[cls] = (classificationCounts[cls] || 0) + 1;
    if (r.business_service_intelligence?.found) bsiCount++;
  }
  response += `**Total**: ${total} IPs\n`;
  for (const [cls, count] of Object.entries(classificationCounts)) {
    response += `**${cls}**: ${count}\n`;
  }
  response += `**BSI Matches**: ${bsiCount}\n\n`;

  // Table (cap at 50)
  const displayResults = results.slice(0, 50);
  response += `| IP | Classification | BSI Found | Trust Level |\n`;
  response += `|--|--|--|--|\n`;
  for (const r of displayResults) {
    const cls = r.internet_scanner_intelligence?.classification || "unknown";
    const bsiFound = r.business_service_intelligence?.found ? "Yes" : "No";
    const trust = r.business_service_intelligence?.trust_level || "-";
    response += `| ${r.ip} | ${cls} | ${bsiFound} | ${trust} |\n`;
  }

  if (results.length > 50) {
    response += `\n*Showing 50 of ${results.length} results.*\n`;
  }

  // IPs not found
  if (data.request_metadata?.ips_not_found && data.request_metadata.ips_not_found.length > 0) {
    response += `\n**IPs not found**: ${truncateList(data.request_metadata.ips_not_found, 20)}\n`;
  }

  // Restricted fields
  if (data.request_metadata?.restricted_fields && data.request_metadata.restricted_fields.length > 0) {
    response += `\n---\n**Note:** Some fields are restricted by your API plan: ${data.request_metadata.restricted_fields.join(", ")}\n`;
  }

  return response;
}

// ─── v3 GNQL Query Results Formatter ─────────────────────────────────────────

export function formatGnqlQueryResults(data: GnqlQueryResponse | GnqlMetadataQueryResponse): string {
  const meta = data.request_metadata;
  const results = data.data;

  let response = `# GNQL Query Results\n\n`;
  response += `**Query**: \`${meta.query}\`\n`;
  if (meta.adjusted_query && meta.adjusted_query !== meta.query) {
    response += `**Adjusted Query**: \`${meta.adjusted_query}\`\n`;
  }
  response += `**Results on page**: ${results.length}\n`;
  response += `**Complete**: ${meta.complete ? "Yes" : "No"}\n\n`;

  // Summary from this page
  if (results.length > 0) {
    const classificationCounts: Record<string, number> = {};
    const tagCounts: Record<string, number> = {};
    const orgCounts: Record<string, number> = {};
    const countryCounts: Record<string, number> = {};

    for (const r of results) {
      const cls = r.internet_scanner_intelligence?.classification || "unknown";
      classificationCounts[cls] = (classificationCounts[cls] || 0) + 1;

      const org = r.internet_scanner_intelligence?.metadata?.organization;
      if (org) orgCounts[org] = (orgCounts[org] || 0) + 1;

      const country = r.internet_scanner_intelligence?.metadata?.source_country;
      if (country) countryCounts[country] = (countryCounts[country] || 0) + 1;

      for (const tag of r.internet_scanner_intelligence?.tags || []) {
        tagCounts[tag.name] = (tagCounts[tag.name] || 0) + 1;
      }
    }

    response += `## Page Summary\n\n`;
    response += `**Classification**: ${Object.entries(classificationCounts).map(([k, v]) => `${k}: ${v}`).join(", ")}\n`;

    const topTags = Object.entries(tagCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (topTags.length > 0) {
      response += `**Top Tags**: ${topTags.map(([k, v]) => `${k} (${v})`).join(", ")}\n`;
    }
    const topOrgs = Object.entries(orgCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (topOrgs.length > 0) {
      response += `**Top Organizations**: ${topOrgs.map(([k, v]) => `${k} (${v})`).join(", ")}\n`;
    }
    const topCountries = Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    if (topCountries.length > 0) {
      response += `**Top Countries**: ${topCountries.map(([k, v]) => `${k} (${v})`).join(", ")}\n`;
    }
    response += `\n`;

    // Detailed results
    response += `## Results\n\n`;
    for (const r of results) {
      const isi = r.internet_scanner_intelligence;
      const bsi = r.business_service_intelligence;
      response += `### ${r.ip}\n`;
      response += `- **Classification**: ${isi?.classification || "unknown"}`;
      if (isi?.actor && isi.actor !== "unknown") response += ` | **Actor**: ${isi.actor}`;
      response += `\n`;
      if (bsi?.found) response += `- **BSI**: ${bsi.name || "Known service"} (${bsi.trust_level || "N/A"})\n`;
      if (isi?.tags && isi.tags.length > 0) {
        const tagNames = isi.tags.map(t => `${t.name} (${t.intention})`);
        response += `- **Tags**: ${truncateList(tagNames, 5)}\n`;
      }
      if (isi?.metadata?.organization) response += `- **Org**: ${isi.metadata.organization}\n`;
      if (isi?.metadata?.source_country) response += `- **Country**: ${isi.metadata.source_country}\n`;
      const scan = isi?.raw_data?.scan;
      if (scan && scan.length > 0) {
        const ports = scan.map(s => `${s.port}/${s.protocol}`);
        response += `- **Ports**: ${truncateList(ports, 10)}\n`;
      }
      response += `\n`;
    }
  }

  // Pagination
  if (!meta.complete && meta.scroll) {
    response += `---\n**More results available.** Pass scroll token to retrieve next page: \`${meta.scroll}\`\n`;
  }

  // Restricted fields
  if (meta.restricted_fields && meta.restricted_fields.length > 0) {
    response += `\n**Note:** Some fields are restricted by your API plan: ${meta.restricted_fields.join(", ")}\n`;
  }

  return response;
}

// ─── v3 GNQL Timeseries Formatter ────────────────────────────────────────────

export function formatGnqlTimeseries(data: GnqlTimeseriesResponse): string {
  const timestamps = Object.keys(data).sort();

  let response = `# GNQL Timeseries Results\n\n`;
  response += `**Time buckets**: ${timestamps.length}\n\n`;

  if (timestamps.length === 0) {
    return response + "No timeseries data found.\n";
  }

  // Summary
  let totalRecords = 0;
  const ipSet = new Set<string>();
  for (const ts of timestamps) {
    const records = data[ts];
    if (Array.isArray(records)) {
      totalRecords += records.length;
      for (const r of records) {
        if (r.ip) ipSet.add(r.ip);
      }
    }
  }
  response += `**Total records**: ${totalRecords}\n`;
  response += `**Unique IPs**: ${ipSet.size}\n`;
  response += `**Time range**: ${timestamps[0]} to ${timestamps[timestamps.length - 1]}\n\n`;

  // Show per-bucket counts (cap at 50 rows)
  response += `| Time Bucket | Records |\n`;
  response += `|--|--|\n`;
  const displayTs = timestamps.slice(0, 50);
  for (const ts of displayTs) {
    const records = data[ts];
    const count = Array.isArray(records) ? records.length : 0;
    response += `| ${ts} | ${count} |\n`;
  }
  if (timestamps.length > 50) {
    response += `\n*Showing 50 of ${timestamps.length} time buckets.*\n`;
  }

  // Show details for first bucket as sample
  const firstTs = timestamps[0];
  const firstRecords = data[firstTs];
  if (Array.isArray(firstRecords) && firstRecords.length > 0) {
    response += `\n## Sample (${firstTs})\n\n`;
    const sample = firstRecords.slice(0, 5);
    for (const r of sample) {
      const isi = r.internet_scanner_intelligence;
      response += `- **${r.ip}**: ${isi?.classification || "unknown"}`;
      if (isi?.tags && isi.tags.length > 0) {
        response += ` | Tags: ${truncateList(isi.tags, 5)}`;
      }
      response += `\n`;
    }
    if (firstRecords.length > 5) {
      response += `- *and ${firstRecords.length - 5} more in this bucket*\n`;
    }
  }

  return response;
}

// ─── v3 GNQL Timeseries Stats Formatter ──────────────────────────────────────

export function formatGnqlTimeseriesStats(data: GnqlTimeseriesStatsResponse): string {
  let response = `# GNQL Timeseries Stats\n\n`;
  response += `**Total unique IPs**: ${data.count.toLocaleString()}\n`;
  response += `**Max in period**: ${data.max.toLocaleString()}\n`;
  response += `**Min in period**: ${data.min.toLocaleString()}\n`;
  response += `**Data points**: ${data.data.length}\n\n`;

  if (data.data.length > 0) {
    response += `| Date | Unique IPs |\n`;
    response += `|--|--|\n`;
    for (const bucket of data.data) {
      response += `| ${bucket.date} | ${bucket.count.toLocaleString()} |\n`;
    }
    response += `\n`;
  }

  return response;
}
