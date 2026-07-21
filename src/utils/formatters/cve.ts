import type { CVEDetails, TrendingTagsSummary } from "../../greynoise/schemas/cve.js";

function utc(value: string): string {
  const d = new Date(value);
  return isNaN(d.getTime()) ? value : `${d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "")} UTC`;
}

export function formatCVEDetails(data: CVEDetails, tagActivityIPs = 0): string {
  let response = `# CVE Details: ${data.id}\n\n`;

  response += `## Vulnerability Information\n\n`;
  response += `**Name**: ${data.details.vulnerability_name}\n`;
  response += `**Description**: ${data.details.vulnerability_description}\n`;
  response += `**CVSS Score**: ${data.details.cve_cvss_score}\n`;
  response += `**Product**: ${data.details.product}\n`;
  response += `**Vendor**: ${data.details.vendor}\n`;
  response += `**Published to NIST NVD**: ${data.details.published_to_nist_nvd ? "Yes" : "No"}\n\n`;

  response += `## Timeline\n\n`;
  response += `**Published Date**: ${utc(data.timeline.cve_published_date)}\n`;
  response += `**Last Updated**: ${utc(data.timeline.cve_last_updated_date)}\n`;
  response += `**First Known Publication**: ${utc(data.timeline.first_known_published_date)}\n`;
  if (data.timeline.cisa_kev_date_added) {
    response += `**Added to CISA KEV**: ${utc(data.timeline.cisa_kev_date_added)}\n`;
  }
  response += `\n`;

  response += `## Exploitation Details\n\n`;
  response += `**Attack Vector**: ${data.exploitation_details.attack_vector}\n`;
  response += `**Exploit Found**: ${data.exploitation_details.exploit_found ? "Yes" : "No"}\n`;
  response += `**In CISA Known Exploited Vulnerabilities Catalog**: ${data.exploitation_details.exploitation_registered_in_kev ? "Yes" : "No"}\n`;
  response += `**EPSS Score**: ${(data.exploitation_details.epss_score * 100).toFixed(2)}% (probability of exploitation)\n\n`;

  if (data.exploitation_stats) {
    response += `## Exploitation Statistics\n\n`;
    response += `**Available Exploits**: ${data.exploitation_stats.number_of_available_exploits}\n`;
    response += `**Threat Actors Exploiting**: ${data.exploitation_stats.number_of_threat_actors_exploiting_vulnerability}\n`;
    response += `**Botnets Exploiting**: ${data.exploitation_stats.number_of_botnets_exploiting_vulnerability}\n\n`;
  }

  response += `## Observed Activity\n\n`;
  if (!data.exploitation_activity.activity_seen && tagActivityIPs > 0) {
    response += `**Activity Seen by GreyNoise**: Yes — ${tagActivityIPs} IPs in the last 30d, from the associated tag timeline\n`;
    response += `> The CVE record reports no activity, but the associated tag timeline shows ${tagActivityIPs} IPs. The CVE rollup lags backfilled tag hits; use get-tag-activity for exploitation timing.\n\n`;
  } else {
    response += `**Activity Seen by GreyNoise**: ${data.exploitation_activity.activity_seen ? "Yes" : "No"}\n\n`;
  }

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
  }

  if (!data.exploitation_stats && !data.exploitation_activity) {
    response += `## Exploitation Statistics & Observed Activity\n\n`;
    response += `Not included in this API key's plan. Their absence here is an access limitation, not evidence that no exploitation exists.\n`;
  }

  return response;
}

export function formatTrendingTags(data: TrendingTagsSummary): string {
  let response = `# GreyNoise Vulnerability Tags\n\n`;
  if (data.count === 0) {
    return response + "No vulnerability tags found.";
  }

  response += `Found ${data.count} vulnerability tags:\n\n`;
  data.tags.forEach((tag, index) => {
    response += `## ${index + 1}. ${tag.name}`;
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
