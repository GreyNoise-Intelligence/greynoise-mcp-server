import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { randomUUID } from "crypto";
import { tmpdir } from "os";
import { join } from "path";
import { unlink } from "fs/promises";
import { defineTool } from "./define-tool.js";
import { pcapFileSchema } from "../greynoise/schemas/sessions.js";
import { GreyNoiseApiError } from "../greynoise/errors.js";

const PCAP_HEADER_SIZE = 24;

export function registerGetSessionPcapTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-session-pcap",
    title: "Get Session PCAP",
    description:
      "Download the raw PCAP capture for a single GreyNoise sensor session. Saves the binary PCAP file to a temporary directory and returns the file path. The file can be opened with Wireshark, tshark, or tcpdump.",
    inputSchema: {
      session_id: z.string().min(1).describe("The unique session identifier"),
      scope: z.string().optional().describe("Data scope for the query (default: workspace)"),
    },
    outputSchema: pcapFileSchema,
    annotations: { readOnlyHint: false },
    handler: async ({ session_id, scope }, { client, log }) => {
      const outputPath = join(tmpdir(), `session-${randomUUID()}.pcap`);
      const params: Record<string, unknown> = {};
      if (scope) params.scope = scope;

      await log("info", `Downloading PCAP for session ${session_id}...`);
      let filePath: string, fileSize: number;
      try {
        ({ filePath, fileSize } = await client.getBinary(
          `v3/sessions/${encodeURIComponent(session_id)}/frames`,
          outputPath,
          params,
        ));
      } catch (e) {
        if (e instanceof GreyNoiseApiError && e.status === 404) {
          return { text: `Session ${session_id} not found or has no captured frames.`, structured: { available: false } };
        }
        throw e;
      }

      if (fileSize <= PCAP_HEADER_SIZE) {
        await unlink(filePath).catch(() => {});
        return {
          text: `No packet data available for session ${session_id}. The session has no captured frames.`,
          structured: { available: false },
        };
      }

      const text = `# Session PCAP Downloaded\n\n**Session**: ${session_id}\n**File**: ${filePath}\n**Size**: ${fileSize.toLocaleString()} bytes\n\nOpen with Wireshark, tshark, or tcpdump for analysis.`;
      return { text, structured: { available: true, filePath, fileSize } };
    },
  });
}
