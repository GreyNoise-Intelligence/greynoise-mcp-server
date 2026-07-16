import type { CallbackIPDetail, CallbackListIPs, CallbackOverview } from "../../greynoise/schemas/callback.js";
import { truncateList, formatTimestamp, escapeMarkdownTableCell as esc } from "../format-helpers.js";

function stage(is1?: boolean, is2?: boolean): string {
  if (is2) return "Stage 2 (suspected C2)";
  if (is1) return "Stage 1 (payload delivery)";
  return "Unconfirmed";
}

export function formatCallbackIPDetail(data: CallbackIPDetail): string {
  if (!data || data.ip === undefined) return "# Callback IP Not Found\n\nThis IP was not found in the callback dataset.";

  let out = `# Callback IP: ${data.ip}\n\n`;
  out += `**Stage**: ${stage(data.is_stage_1, data.is_stage_2)}\n`;
  if (data.is_riot) out += `**RIOT**: Yes (trust level ${data.riot_trust_level ?? "?"})\n`;
  if (data.first_seen) out += `**First Seen**: ${formatTimestamp(data.first_seen)}\n`;
  if (data.last_seen) out += `**Last Seen**: ${formatTimestamp(data.last_seen)}\n`;
  if (data.source_workspaces?.length) out += `**Sources**: ${data.source_workspaces.join(", ")}\n`;
  out += `**Scanners**: ${data.scanner_count ?? data.scanner_ips?.length ?? 0}\n`;
  out += `**Files**: ${data.file_count ?? data.active_files?.length ?? 0}\n`;

  const e = data.enrichment;
  if (e) {
    out += `\n## Enrichment\n\n`;
    if (e.org) out += `**Org**: ${e.org}\n`;
    if (e.asn) out += `**ASN**: ${e.asn}\n`;
    const loc = [e.city, e.region, e.country].filter(Boolean).join(", ");
    if (loc) out += `**Location**: ${loc}\n`;
    if (e.route) out += `**Route**: ${e.route}\n`;
    if (e.domain) out += `**Domain**: ${e.domain}\n`;
    if (e.rdns) out += `**rDNS**: ${e.rdns}\n`;
    if (e.is_tor) out += `**Tor**: Yes\n`;
  }

  if (data.scanner_ips?.length) out += `\n**Scanner IPs**: ${truncateList(data.scanner_ips, 15)}\n`;

  if (data.active_files?.length) {
    out += `\n## Malware Files\n\n| SHA256 | Threat | VT | Type |\n|--|--|--|--|\n`;
    for (const f of data.active_files.slice(0, 25)) {
      const vt = f.vt_detection_count !== undefined ? `${f.vt_detection_count}/${f.vt_engine_count ?? "?"}` : "-";
      out += `| ${esc(f.sha256 ?? "-")} | ${esc(f.threat_name ?? "-")} | ${vt} | ${esc(f.type ?? "-")} |\n`;
    }
    if (data.active_files.length > 25) out += `\n*Showing 25 of ${data.active_files.length} files.*\n`;
  }
  return out;
}

export function formatCallbackList(data: CallbackListIPs): string {
  const items = data.items ?? [];
  let out = `# Callback IPs\n\n`;
  out += `**Total**: ${data.total ?? items.length} | **Page**: ${data.page ?? 0} | **Page Size**: ${data.page_size ?? items.length}\n\n`;
  if (!items.length) return out + "No callback IPs matched the filters.\n";

  out += `| IP | Stage | RIOT | Scanners | Files | Org |\n|--|--|--|--|--|--|\n`;
  for (const it of items.slice(0, 50)) {
    out += `| ${esc(it.ip ?? "-")} | ${stage(it.is_stage_1, it.is_stage_2)} | ${it.is_riot ? "Yes" : "No"} | ${it.scanner_count ?? 0} | ${it.file_count ?? 0} | ${esc(it.enrichment?.org ?? "-")} |\n`;
  }
  if (items.length > 50) out += `\n*Showing 50 of ${items.length} listed.*\n`;
  return out;
}

export function formatCallbackOverview(data: CallbackOverview): string {
  let out = `# Callback Overview\n\n`;
  out += `**Total IPs**: ${data.total_ips ?? 0}\n`;
  out += `**Stage 1 / Stage 2 / Unconfirmed**: ${data.stage_1_ips ?? 0} / ${data.stage_2_ips ?? 0} / ${data.unconfirmed_ips ?? 0}\n`;
  out += `**RIOT (L1/L2/L3/none)**: ${data.riot_level_1_ips ?? 0} / ${data.riot_level_2_ips ?? 0} / ${data.riot_level_3_ips ?? 0} / ${data.not_riot_ips ?? 0}\n`;
  out += `**Files**: ${data.total_files ?? 0} (VT ${data.files_with_vt ?? 0}, pending ${data.files_without_vt ?? 0})\n`;
  out += `**IPs with/without files**: ${data.ips_with_files ?? 0} / ${data.ips_without_files ?? 0}\n`;
  out += `**IPs with/without scanners**: ${data.ips_with_scanners ?? 0} / ${data.ips_without_scanners ?? 0}\n`;
  out += `**Distinct scanners**: ${data.distinct_scanners ?? 0}\n`;

  if (data.top_threat_names?.length) {
    out += `\n## Top Threat Names\n\n| Threat | Files | IPs |\n|--|--|--|\n`;
    for (const t of data.top_threat_names.slice(0, 20)) {
      out += `| ${esc(t.threat_name ?? "-")} | ${t.file_count ?? 0} | ${t.ip_count ?? 0} |\n`;
    }
  }
  return out;
}
