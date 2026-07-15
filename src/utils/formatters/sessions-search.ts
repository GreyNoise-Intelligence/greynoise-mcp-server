import type {
  SessionsResponse,
  SessionFieldsResponse,
  SessionCountsResponse,
  SessionConnectionsResponse,
  SessionTimeseriesResponse,
  SessionUniqueValues,
} from "../../greynoise/schemas/sessions-search.js";
import { truncateList, formatTimestamp } from "../format-helpers.js";

const str = (v: unknown): string => (v === undefined || v === null ? "-" : String(v));

export function formatSessionsSearch(data: SessionsResponse): string {
  const sessions = data.sessions ?? [];
  let text = `# Sessions\n\n**Total matching**: ${data.total ?? sessions.length}\n`;
  if (data.pagination) {
    text += `**Page**: ${str(data.pagination.page)} (size ${str(data.pagination.page_size)})\n`;
  }
  text += `\n`;
  if (sessions.length === 0) return text + "No sessions matched the query.\n";

  text += `| ID | Source | Destination | Class | Last Packet |\n|--|--|--|--|--|\n`;
  for (const s of sessions.slice(0, 50)) {
    const r = s as Record<string, unknown>;
    const src = `${str(r["source.ip"])}:${str(r["source.port"])}`;
    const dst = `${str(r["destination.ip"])}:${str(r["destination.port"])}`;
    text += `| ${str(r._id)} | ${src} | ${dst} | ${str(r.classification)} | ${formatTimestamp(r.lastPacket)} |\n`;
  }
  if (sessions.length > 50) text += `\n*Showing 50 of ${sessions.length} returned.*\n`;
  return text;
}

export function formatSessionFields(data: SessionFieldsResponse): string {
  const fields = data.fields ?? [];
  let text = `# Session Fields (${fields.length})\n\n| Field | Type | Group | Sortable |\n|--|--|--|--|\n`;
  for (const f of fields) {
    text += `| ${str(f.value)} | ${str(f.type)} | ${str(f.group)} | ${f.sortable ? "yes" : "no"} |\n`;
  }
  return text;
}

export function formatSessionCounts(data: SessionCountsResponse): string {
  const items = data.items ?? [];
  let text = `# Session Counts\n\n**Total**: ${data.total ?? 0}\n\n`;
  const render = (nodes: typeof items, depth: number): void => {
    for (const n of nodes.slice(0, 25)) {
      text += `${"  ".repeat(depth)}- ${str(n.label)}: ${str(n.count)}\n`;
      if (n.children?.length) render(n.children, depth + 1);
    }
  };
  render(items, 0);
  return text;
}

export function formatSessionConnections(data: SessionConnectionsResponse): string {
  const nodes = data.nodes ?? [];
  const links = data.links ?? [];
  let text = `# Session Connections\n\n**Nodes**: ${nodes.length} | **Links**: ${links.length} | **Total connections**: ${data.total ?? 0}\n\n`;
  if (links.length === 0) return text + "No connections matched the query.\n";
  text += `| Source | Target | Connections |\n|--|--|--|\n`;
  for (const l of links.slice(0, 50)) {
    text += `| ${str(l.source)} | ${str(l.target)} | ${str(l.value)} |\n`;
  }
  if (links.length > 50) text += `\n*Showing 50 of ${links.length} links.*\n`;
  return text;
}

export function formatSessionTimeseries(data: SessionTimeseriesResponse): string {
  let text = `# Session Timeseries\n\n**Total**: ${data.total ?? 0}\n\n`;
  if (data.items?.length) {
    for (const item of data.items.slice(0, 20)) {
      text += `- **${str(item.label)}**: ${str(item.count)} sessions\n`;
    }
    return text;
  }
  const points = data.timeseries ?? [];
  if (points.length === 0) return text + "No data points in range.\n";
  text += `| Timestamp | Count |\n|--|--|\n`;
  for (const p of points.slice(0, 100)) {
    text += `| ${formatTimestamp(p.timestamp)} | ${str(p.count)} |\n`;
  }
  return text;
}

export function formatSessionUniqueValues(data: SessionUniqueValues): string {
  let text = `# Unique Values: ${data.field}\n\n**Distinct rows**: ${data.total ?? data.values.length}\n\n`;
  text += truncateList(data.values, 100);
  return text + "\n";
}
