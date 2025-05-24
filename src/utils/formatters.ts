import { GnqlStatsResponse, IPContextResponse, CVEDetailsResponse } from "../types/greynoise-response.js";

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
      response += `- **${item.os}**: ${item.count.toLocaleString()} IPs\n`;
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
 * Formats a GNQL stats response into a summarized Markdown string with the most important information.
 * Includes the original query, translated GNQL, and top entries from each category.
 *
 * @param {string} originalQuery - The original user query
 * @param {string} gnqlQuery - The translated GNQL query
 * @param {GnqlStatsResponse} data - The GNQL stats response data from the GreyNoise API
 * @returns {string} A formatted Markdown string containing a summary of the GNQL stats
 *
 * @example
 * const formattedSummary = formatGnqlStatsResponse(
 *   "show me malicious IPs from China",
 *   "classification:malicious metadata.country:China",
 *   gnqlStatsResponse
 * );
 */
export function formatGnqlStatsResponse(originalQuery: string, gnqlQuery: string, data: GnqlStatsResponse): string {
  let response = `# GreyNoise Query Results\n\n`;
  response += `Your query: "${originalQuery}"\n\n`;
  response += `Translated GNQL: \`${gnqlQuery}\`\n\n`;
  response += `Found ${data.count.toLocaleString()} matching IPs over the specified time period.\n\n`;

  // Add classification breakdown
  if (data.stats.classifications && data.stats.classifications.length > 0) {
    response += `## Classification Breakdown\n\n`;
    for (const item of data.stats.classifications) {
      response += `- **${item.classification}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add organization breakdown (top 5)
  if (data.stats.organizations && data.stats.organizations.length > 0) {
    response += `## Top Organizations\n\n`;
    for (const item of data.stats.organizations.slice(0, 5)) {
      response += `- **${item.organization}**: ${item.count.toLocaleString()} IPs\n`;
    }
    if (data.stats.organizations.length > 5) {
      response += `- *and ${data.stats.organizations.length - 5} more organizations*\n`;
    }
    response += `\n`;
  }

  // Add country breakdown (top 5)
  if (data.stats.countries && data.stats.countries.length > 0) {
    response += `## Top Countries\n\n`;
    for (const item of data.stats.countries.slice(0, 5)) {
      response += `- **${item.country}**: ${item.count.toLocaleString()} IPs\n`;
    }
    if (data.stats.countries.length > 5) {
      response += `- *and ${data.stats.countries.length - 5} more countries*\n`;
    }
    response += `\n`;
  }

  // Add actor breakdown if available
  if (data.stats.actors && data.stats.actors.length > 0) {
    response += `## Actors\n\n`;
    for (const item of data.stats.actors) {
      response += `- **${item.actor}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  // Add tag breakdown (top 10)
  if (data.stats.tags && data.stats.tags.length > 0) {
    response += `## Top Tags\n\n`;
    for (const item of data.stats.tags.slice(0, 10)) {
      response += `- **${item.tag}**: ${item.count.toLocaleString()} IPs\n`;
    }
    if (data.stats.tags.length > 10) {
      response += `- *and ${data.stats.tags.length - 10} more tags*\n`;
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

/**
 * Formats IP context data into a readable Markdown string.
 *
 * @param {IPContextResponse} data - The IP context response from the GreyNoise API
 * @returns {string} A formatted Markdown string containing detailed information about the IP address
 *
 * @example
 * const formattedIPContext = formatIPContext(ipContextResponse);
 * console.log(formattedIPContext); // Prints detailed Markdown about the IP address
 */
export function formatIPContext(data: IPContextResponse): string {
  // Check if the IP was not found
  if (!data || data.ip === undefined) {
    return "# IP Not Found\n\nThis IP address was not found in the GreyNoise database.";
  }
  
  let response = `# GreyNoise IP Context: ${data.ip}\n\n`;

  // Status & classification
  response += `**Classification**: ${data.classification ? data.classification.toUpperCase() : 'NOT FOUND'}\n`;
  response += `**Status**: ${data.seen ? "Active" : "Inactive"}\n`;
  response += `**First Seen**: ${data.first_seen || 'N/A'}\n`;
  response += `**Last Seen**: ${data.last_seen || 'N/A'}\n\n`;

  // Organization details
  response += `## Organization Details\n\n`;
  response += `**Organization**: ${data.metadata?.organization || 'Unknown'}\n`;
  response += `**Category**: ${data.metadata?.category || 'Unknown'}\n`;
  response += `**ASN**: ${data.metadata?.asn || 'Unknown'}\n`;
  response += `**Actor**: ${data.actor && data.actor !== "unknown" ? data.actor : "Unknown"}\n\n`;

  // Location information
  response += `## Location Information\n\n`;
  response += `**Country**: ${data.metadata?.country || 'Unknown'} ${data.metadata?.country_code ? `(${data.metadata.country_code})` : ''}\n`;
  if (data.metadata?.city) response += `**City**: ${data.metadata.city}\n`;
  if (data.metadata?.region) response += `**Region**: ${data.metadata.region}\n`;
  if (data.metadata?.rdns) response += `**Reverse DNS**: ${data.metadata.rdns}\n`;
  response += `**Operating System**: ${data.metadata?.os && data.metadata.os !== "unknown" ? data.metadata.os : "Unknown"}\n\n`;

  // Activity details
  response += `## Activity Details\n\n`;
  response += `**Tags**: ${data.tags && data.tags.length > 0 ? data.tags.join(", ") : 'None'}\n`;
  if (data.cve && data.cve.length > 0) response += `**CVEs**: ${data.cve.join(", ")}\n`;
  response += `**Sensor Hits**: ${data.metadata?.sensor_hits || 0} hits across ${data.metadata?.sensor_count || 0} sensors\n`;

  // Additional properties
  response += `**Bot**: ${data.bot ? "Yes" : "No"}\n`;
  response += `**Tor Exit Node**: ${data.metadata?.tor ? "Yes" : "No"}\n`;
  response += `**VPN**: ${data.vpn ? "Yes" : "No"}\n`;
  if (data.vpn && data.vpn_service) response += `**VPN Service**: ${data.vpn_service}\n`;
  response += `**Spoofable**: ${data.spoofable ? "Yes" : "No"}\n\n`;

  // Scanning activity
  if (data.raw_data?.scan && data.raw_data.scan.length > 0) {
    const scanPorts = data.raw_data.scan.map((s) => `${s.port}/${s.protocol}`);
    if (scanPorts.length > 0) {
      response += `## Scanning Activity\n\n`;
      response += `**Scanned Ports**: ${
        scanPorts.length > 20
          ? scanPorts.slice(0, 20).join(", ") + ` (and ${scanPorts.length - 20} more)`
          : scanPorts.join(", ")
      }\n\n`;
    }
  }

  // Destination countries
  if (data.metadata?.destination_countries && data.metadata.destination_countries.length > 0) {
    response += `## Target Countries\n\n`;
    const countries = data.metadata.destination_countries;
    response += `**Targeting**: ${
      countries.length > 10
        ? countries.slice(0, 10).join(", ") + ` (and ${countries.length - 10} more)`
        : countries.join(", ")
    }\n\n`;
  }

  // TLS/SSL fingerprints if available
  if (data.raw_data?.ja3 && data.raw_data.ja3.length > 0) {
    response += `## TLS/SSL Fingerprints\n\n`;
    const uniqueFingerprints = [...new Set(data.raw_data.ja3.map((j) => j.fingerprint))];
    response += `**JA3 Fingerprints**: ${
      uniqueFingerprints.length > 5
        ? uniqueFingerprints.slice(0, 5).join(", ") + ` (and ${uniqueFingerprints.length - 5} more)`
        : uniqueFingerprints.join(", ")
    }\n\n`;
  }

  return response;
}