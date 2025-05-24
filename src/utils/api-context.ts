import { AsyncLocalStorage } from "async_hooks";

// Context to store request-specific data
interface ApiContext {
  apiKey: string;
}

// AsyncLocalStorage for managing request context
const asyncLocalStorage = new AsyncLocalStorage<ApiContext>();

/**
 * Sets the API key for the current request context
 */
export function setApiKey(apiKey: string): void {
  const store = asyncLocalStorage.getStore();
  if (store) {
    store.apiKey = apiKey;
  }
}

/**
 * Gets the API key from the current request context
 */
export function getApiKey(): string {
  const store = asyncLocalStorage.getStore();
  if (store?.apiKey) {
    return store.apiKey;
  }
  throw new Error("No API key found in current context");
}

/**
 * Runs a function within an API context
 */
export function runWithApiContext<T>(apiKey: string, fn: () => T): T {
  return asyncLocalStorage.run({ apiKey }, fn);
}

/**
 * Checks if we're currently in an API context
 */
export function hasApiContext(): boolean {
  const store = asyncLocalStorage.getStore();
  return !!(store?.apiKey);
}