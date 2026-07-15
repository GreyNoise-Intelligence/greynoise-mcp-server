type Level = "debug" | "info" | "warn" | "error";

function emit(level: Level, message: string, fields?: Record<string, unknown>): void {
  const record = { level, message, ...fields, ts: new Date().toISOString() };
  process.stderr.write(JSON.stringify(record) + "\n");
}

export const logger = {
  debug: (message: string, fields?: Record<string, unknown>) => emit("debug", message, fields),
  info: (message: string, fields?: Record<string, unknown>) => emit("info", message, fields),
  warn: (message: string, fields?: Record<string, unknown>) => emit("warn", message, fields),
  error: (message: string, fields?: Record<string, unknown>) => emit("error", message, fields),
};
