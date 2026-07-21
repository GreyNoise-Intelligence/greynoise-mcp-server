import { GreyNoiseApiError } from "../greynoise/errors.js";

export function toUserMessage(error: unknown): string {
  if (error instanceof GreyNoiseApiError) {
    switch (error.status) {
      case 401:
        return "Authentication failed (401): the GreyNoise API key is missing, invalid, or expired. Check the GREYNOISE_API_KEY.";
      case 403:
        return "Not entitled (403): this GreyNoise API key's plan does not include this capability. This is an access limitation, not evidence that the data is absent.";
      case 404:
        return `Not found (404): ${error.endpoint}.`;
      case 429:
        return "Rate limited (429): too many requests to the GreyNoise API. Wait a moment and retry.";
      default:
        return `GreyNoise API error (${error.status}): ${error.message}`;
    }
  }
  return `Error: ${error instanceof Error ? error.message : String(error)}`;
}
