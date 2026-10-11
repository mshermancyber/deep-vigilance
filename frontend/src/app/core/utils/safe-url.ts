import { environment } from '../../../environments/environment';

/**
 * Opens a URL in a new tab only if it is an http(s) URL on a trusted origin
 * (the app's own origin or the configured API origin). Rejects javascript:/data:
 * and cross-origin URLs, which prevents open-redirect / script-execution when a
 * URL originates from a server response. Returns false if the URL was rejected.
 */
export function openSafeDownloadUrl(url: unknown): boolean {
  if (typeof url !== 'string' || url.length === 0) return false;

  let parsed: URL;
  try {
    // Resolve relative URLs against the app origin.
    parsed = new URL(url, window.location.origin);
  } catch {
    return false;
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;

  const allowedOrigins = new Set<string>([window.location.origin]);
  try {
    allowedOrigins.add(new URL(environment.apiUrl).origin);
  } catch {
    /* environment.apiUrl may be relative; app origin already covers that case */
  }
  if (!allowedOrigins.has(parsed.origin)) return false;

  window.open(parsed.href, '_blank', 'noopener,noreferrer');
  return true;
}
