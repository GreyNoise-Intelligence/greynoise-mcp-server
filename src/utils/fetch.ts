import fetch from "node-fetch";

// Package info for User-Agent
const PACKAGE_NAME = "@greynoise/greynoise-mcp-server";
const PACKAGE_VERSION = "0.2.2";
const USER_AGENT = `${PACKAGE_NAME}/${PACKAGE_VERSION}`;

/**
 * Makes an authenticated GET request to the GreyNoise API.
 *
 * @template T - The expected return type of the API response
 * @param {string} endpoint - The API endpoint to call (without the base URL)
 * @param {string} GREYNOISE_API_BASE - The base URL for the GreyNoise API
 * @param {string} GREYNOISE_API_KEY - The API key for authenticating with GreyNoise
 * @param {Record<string, any>} [params={}] - Optional query parameters to include in the request
 * @returns {Promise<T>} A promise that resolves to the API response data
 * @throws {Error} If the API request fails or returns a non-OK status
 *
 * @example
 * // Get IP context information
 * const ipData = await fetchGreyNoise<IPContextResponse>(
 *   '/v2/noise/context/1.2.3.4',
 *   'https://api.greynoise.io',
 *   'your-api-key'
 * );
 *
 * TODO: Pagination support
 */
export async function fetchGreyNoise<T>(
  endpoint: string,
  GREYNOISE_API_BASE: string,
  GREYNOISE_API_KEY: string,
  params = {},
): Promise<T> {
  const url = new URL(`${GREYNOISE_API_BASE}${endpoint}`);

  // Add query parameters if any
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const response = await fetch(url.toString(), {
      headers: {
        key: GREYNOISE_API_KEY,
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
    });

    if (!response.ok) {
      try {
        const errorText = await response.text();
        throw new Error(`GreyNoise API error: ${response.status} - ${errorText}`);
      } catch (e) {
        throw new Error(`GreyNoise API error: ${response.status} - Could not parse error response`);
      }
    }

    return (await response.json()) as T;
  } catch (error) {
    console.error(`Error fetching from GreyNoise API: ${error instanceof Error ? error.message : String(error)}`);
    console.error(`URL: ${url.toString()}`);
    console.error(`API Key provided: ${GREYNOISE_API_KEY ? "Yes (length: " + GREYNOISE_API_KEY.length + ")" : "No"}`);
    throw error;
  }
}

/**
 * Makes an authenticated POST request to the GreyNoise API.
 *
 * @template T - The expected return type of the API response
 * @param {string} endpoint - The API endpoint to call (without the base URL)
 * @param {string} GREYNOISE_API_BASE - The base URL for the GreyNoise API
 * @param {string} GREYNOISE_API_KEY - The API key for authenticating with GreyNoise
 * @param {any} body - The JSON body to send with the POST request
 * @returns {Promise<T>} A promise that resolves to the API response data
 * @throws {Error} If the API request fails or returns a non-OK status
 *
 * @example
 * // Check multiple IPs
 * const multiIpData = await postToGreyNoise<MultiIPQuickCheckResponse>(
 *   '/v2/noise/multi/quick',
 *   'https://api.greynoise.io',
 *   'your-api-key',
 *   { ips: ['1.2.3.4', '5.6.7.8'] }
 * );
 */
export async function postToGreyNoise<T>(
  endpoint: string,
  GREYNOISE_API_BASE: string,
  GREYNOISE_API_KEY: string,
  body: any,
): Promise<T> {
  const url = new URL(`${GREYNOISE_API_BASE}${endpoint}`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers: {
        key: GREYNOISE_API_KEY,
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      try {
        const errorText = await response.text();
        throw new Error(`GreyNoise API error: ${response.status} - ${errorText}`);
      } catch (e) {
        throw new Error(`GreyNoise API error: ${response.status} - Could not parse error response`);
      }
    }

    return (await response.json()) as T;
  } catch (error) {
    console.error(`Error posting to GreyNoise API: ${error instanceof Error ? error.message : String(error)}`);
    console.error(`URL: ${url.toString()}`);
    console.error(`Body: ${JSON.stringify(body)}`);
    console.error(`API Key provided: ${GREYNOISE_API_KEY ? "Yes (length: " + GREYNOISE_API_KEY.length + ")" : "No"}`);
    throw error;
  }
}
