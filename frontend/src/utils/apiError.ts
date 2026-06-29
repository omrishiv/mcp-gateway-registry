/**
 * Extract a human-readable message from an axios error.
 *
 * Handles FastAPI's two error-body shapes: a plain `{detail: string}` and a
 * validation `{detail: [{msg, ...}]}` array. Falls back to the provided
 * message. This was duplicated verbatim across the IAM components.
 */
export function extractErrorDetail(err: any, fallback: string): string {
  const detail = err?.response?.data?.detail;
  if (Array.isArray(detail)) {
    return detail.map((d: any) => d?.msg).filter(Boolean).join(', ') || fallback;
  }
  return detail || fallback;
}
