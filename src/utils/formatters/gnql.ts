import type { GnqlQuery, GnqlStats, GnqlTimeseries, GnqlTimeseriesStats } from "../../greynoise/schemas/gnql.js";
import { truncateList, toCsv } from "../format-helpers.js";

const CSV_HEADERS = [
  "ip",
  "classification",
  "actor",
  "organization",
  "source_country",
  "tags",
  "ports",
  "bsi_found",
  "bsi_name",
  "bsi_trust_level",
];

export function formatGnqlMetadataCsv(data: GnqlQuery): string {
  const rows = data.data.map((item) => {
    const isi = item.internet_scanner_intelligence;
    const bsi = item.business_service_intelligence;
    return [
      item.ip,
      isi?.classification ?? "",
      isi?.actor ?? "",
      isi?.metadata?.organization ?? "",
      isi?.metadata?.source_country ?? "",
      (isi?.tags ?? []).map((tag) => tag.name).join("; "),
      (isi?.raw_data?.scan ?? []).map((scan) => `${scan.port}/${scan.protocol}`).join("; "),
      bsi?.found == null ? "" : bsi.found ? "true" : "false",
      bsi?.name ?? "",
      bsi?.trust_level ?? "",
    ];
  });
  return toCsv(CSV_HEADERS, rows);
}

export function formatGnqlStats(data: GnqlStats): string {
  let response = `# GNQL Stats Results\n\n`;
  response += `Query: \`${data.query}\`\n\n`;
  if (data.adjusted_query) {
    response += `Adjusted Query: \`${data.adjusted_query}\`\n\n`;
  }
  response += `Found ${data.count.toLocaleString()} matching IPs.\n\n`;

  const stats = data.stats;

  if (stats.classifications && stats.classifications.length > 0) {
    response += `## Classification Breakdown\n\n`;
    for (const item of stats.classifications) {
      response += `- **${item.classification}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.spoofable && stats.spoofable.length > 0) {
    response += `## Spoofable Status\n\n`;
    for (const item of stats.spoofable) {
      response += `- **${item.spoofable ? "Spoofable" : "Not Spoofable"}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.organizations && stats.organizations.length > 0) {
    response += `## Top Organizations\n\n`;
    for (const item of stats.organizations) {
      response += `- **${item.organization}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.actors && stats.actors.length > 0) {
    response += `## Actors\n\n`;
    for (const item of stats.actors) {
      response += `- **${item.actor}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.countries && stats.countries.length > 0) {
    response += `## Top Countries\n\n`;
    for (const item of stats.countries) {
      response += `- **${item.country}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.source_countries && stats.source_countries.length > 0) {
    response += `## Top Source Countries\n\n`;
    for (const item of stats.source_countries) {
      response += `- **${item.country}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.destination_countries && stats.destination_countries.length > 0) {
    response += `## Top Destination Countries\n\n`;
    for (const item of stats.destination_countries) {
      response += `- **${item.country}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.tags && stats.tags.length > 0) {
    response += `## Top Tags\n\n`;
    for (const item of stats.tags) {
      response += `- **${item.tag}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.operating_systems && stats.operating_systems.length > 0) {
    response += `## Operating Systems\n\n`;
    for (const item of stats.operating_systems) {
      response += `- **${item.operating_system}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.categories && stats.categories.length > 0) {
    response += `## Categories\n\n`;
    for (const item of stats.categories) {
      response += `- **${item.category}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  if (stats.asns && stats.asns.length > 0) {
    response += `## Top ASNs\n\n`;
    for (const item of stats.asns) {
      response += `- **${item.asn}**: ${item.count.toLocaleString()} IPs\n`;
    }
    response += `\n`;
  }

  return response;
}

export function formatGnqlQueryResults(data: GnqlQuery): string {
  const meta = data.request_metadata;
  const results = data.data;

  let response = `# GNQL Query Results\n\n`;
  response += `**Query**: \`${meta.query}\`\n`;
  if (meta.adjusted_query && meta.adjusted_query !== meta.query) {
    response += `**Adjusted Query**: \`${meta.adjusted_query}\`\n`;
  }
  response += `**Results on page**: ${results.length}\n`;
  response += `**Complete**: ${meta.complete ? "Yes" : "No"}\n\n`;

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
        const tagNames = isi.tags.map((t) => `${t.name} (${t.intention})`);
        response += `- **Tags**: ${truncateList(tagNames, 5)}\n`;
      }
      if (isi?.metadata?.organization) response += `- **Org**: ${isi.metadata.organization}\n`;
      if (isi?.metadata?.source_country) response += `- **Country**: ${isi.metadata.source_country}\n`;
      const scan = isi?.raw_data?.scan;
      if (scan && scan.length > 0) {
        const ports = scan.map((s) => `${s.port}/${s.protocol}`);
        response += `- **Ports**: ${truncateList(ports, 10)}\n`;
      }
      response += `\n`;
    }
  }

  if (!meta.complete && meta.scroll) {
    response += `---\n**More results available.** Pass scroll token to retrieve next page: \`${meta.scroll}\`\n`;
  }

  if (meta.restricted_fields && meta.restricted_fields.length > 0) {
    response += `\n**Note:** Some fields are restricted by your API plan: ${meta.restricted_fields.join(", ")}\n`;
  }

  return response;
}

export function formatGnqlTimeseries(data: GnqlTimeseries): string {
  const timestamps = Object.keys(data).sort();

  let response = `# GNQL Timeseries Results\n\n`;
  response += `**Time buckets**: ${timestamps.length}\n\n`;

  if (timestamps.length === 0) {
    return response + "No timeseries data found.\n";
  }

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

export function formatGnqlTimeseriesStats(data: GnqlTimeseriesStats): string {
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
