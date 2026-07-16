export function truncateList(items: string[], max: number): string {
  if (items.length <= max) return items.join(", ");
  return items.slice(0, max).join(", ") + ` (and ${items.length - max} more)`;
}

export function formatTimestamp(value: unknown): string {
  if (value === undefined || value === null) return "N/A";
  if (typeof value === "number") return new Date(value).toISOString();
  return String(value);
}

function escapeCsvField(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}

export function toCsv(headers: string[], rows: string[][]): string {
  const lines = [headers, ...rows].map((row) => row.map(escapeCsvField).join(","));
  return lines.join("\r\n");
}

export function escapeMarkdownTableCell(value: unknown): string {
  return String(value).replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
}
