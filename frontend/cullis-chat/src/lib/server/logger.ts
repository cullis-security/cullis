/**
 * Logging helpers with header redaction.
 *
 * ADR-019 §6 axis 4 mandates that `Authorization`, `Cookie`, and
 * `Set-Cookie` are filtered from every log line. This module is the
 * choke point — server code writes through here.
 */

const SENSITIVE_HEADERS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-cullis-bearer',
]);

export function redactHeaders(headers: Headers | Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  const entries: Iterable<[string, string]> =
    headers instanceof Headers ? headers.entries() : Object.entries(headers);

  for (const [k, v] of entries) {
    out[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? '<filtered>' : v;
  }
  return out;
}

export function logEvent(event: string, fields: Record<string, unknown> = {}): void {
  if (fields.headers && (fields.headers instanceof Headers || typeof fields.headers === 'object')) {
    fields.headers = redactHeaders(fields.headers as Headers | Record<string, string>);
  }
  // Emit one structured line — JSON keeps grep + jq happy.
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }) + '\n');
}
