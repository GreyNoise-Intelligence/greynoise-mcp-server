import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { fetchGreyNoiseBinary } from "../utils/fetch.js";
import { getApiKey } from "../utils/api-context.js";
import { tmpdir } from "os";
import { join } from "path";
import { unlink } from "fs/promises";

// PCAP global header is 24 bytes; a file with only the header has no packets
const PCAP_HEADER_SIZE = 24;

export function registerGetSessionPcapTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "get-session-pcap",
    "Download the raw PCAP capture for a single GreyNoise sensor session. Saves the binary PCAP file to a temporary directory and returns the file path. The file can be opened with Wireshark, tshark, or tcpdump.",
    {
      session_id: z.string().min(1).describe("The unique session identifier"),
      scope: z.string().optional().describe("Data scope for the query (default: workspace)"),
    },
    async ({ session_id, scope }) => {
      try {
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();

        const outputPath = join(tmpdir(), `session-${session_id}.pcap`);

        const params: Record<string, string> = {};
        if (scope) params.scope = scope;

        const { filePath, fileSize } = await fetchGreyNoiseBinary(
          `v3/sessions/${session_id}/frames`,
          apiBase,
          apiKey,
          outputPath,
          params,
        );

        // Check for empty PCAP (no packets)
        if (fileSize <= PCAP_HEADER_SIZE) {
          await unlink(filePath).catch(() => {});
          return {
            content: [
              {
                type: "text",
                text: `No packet data available for session ${session_id}. The session has no captured frames.`,
              },
            ],
          };
        }

        return {
          content: [
            {
              type: "text",
              text: `# Session PCAP Downloaded\n\n**Session**: ${session_id}\n**File**: ${filePath}\n**Size**: ${fileSize.toLocaleString()} bytes\n\nOpen with Wireshark, tshark, or tcpdump for analysis.`,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error downloading session PCAP: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
