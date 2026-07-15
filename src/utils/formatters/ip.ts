import type { IPContext, IPQuickCheck, MultiIP } from "../../greynoise/schemas.js";
import { truncateList } from "../format-helpers.js";

export function formatIPContext(data: IPContext): string {
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

export function formatQuickCheckV3(data: IPQuickCheck): string {
  let response = `## IP Quick Check: ${data.ip}\n\n`;

  const isi = data.internet_scanner_intelligence;
  const bsi = data.business_service_intelligence;

  response += `**Scanner Intelligence**: ${isi.found ? `Found - ${isi.classification?.toUpperCase() || "UNKNOWN"}` : "Not found"}\n`;
  response += `**Business Service**: ${bsi.found ? `Found${bsi.trust_level ? ` - Trust: ${bsi.trust_level}` : ""}` : "Not found"}\n`;

  return response;
}

// ─── v3 Multi-IP Formatter ───────────────────────────────────────────────────

export function formatMultiIPV3(data: MultiIP): string {
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
