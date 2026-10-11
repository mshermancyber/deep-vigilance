// SSRF guard for protocol/DAST scanners.
//
// Scanners legitimately connect to user-supplied targets, so this is NOT a
// blanket block. Policy:
//   * Cloud metadata + link-local (169.254.0.0/16, fd00:ec2::254, ::ffff:169.254.x)
//     are ALWAYS blocked — they are never a legitimate scan target and are the
//     canonical SSRF exfiltration endpoint.
//   * Other private/loopback ranges are blocked UNLESS the operator opts in with
//     ALLOW_PRIVATE_SCAN_TARGETS=true (self-hosted installs scanning internal apps).
import * as dns from 'node:dns';
import * as net from 'node:net';

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfBlockedError';
  }
}

function allowPrivate(): boolean {
  return process.env.ALLOW_PRIVATE_SCAN_TARGETS === 'true';
}

/** Returns 'metadata' | 'private' | null. 'metadata' is always blocked. */
export function classifyIp(ip: string): 'metadata' | 'private' | null {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    if (p[0] === 169 && p[1] === 254) return 'metadata'; // link-local / cloud metadata
    if (p[0] === 10) return 'private';
    if (p[0] === 172 && p[1]! >= 16 && p[1]! <= 31) return 'private';
    if (p[0] === 192 && p[1] === 168) return 'private';
    if (p[0] === 127) return 'private';
    if (p[0] === 0) return 'private';
    if (p[0]! >= 224) return 'private'; // multicast/reserved
    return null;
  }
  if (net.isIPv6(ip)) {
    const n = ip.toLowerCase();
    if (n.startsWith('fe80')) return 'metadata'; // link-local
    // IPv4-mapped IPv6: handle both dotted (::ffff:1.2.3.4) and hex (::ffff:0102:0304) forms
    const mappedMatch = n.match(/^(?:0{0,4}:){0,4}0{0,4}:ffff:(.+)$/);
    if (mappedMatch) {
      const tail = mappedMatch[1];
      if (net.isIPv4(tail)) return classifyIp(tail);
      // Hex pair form: ::ffff:AABB:CCDD → A.B.C.D
      const hexParts = tail.split(':');
      if (hexParts.length === 2 && /^[0-9a-f]{1,4}$/.test(hexParts[0]) && /^[0-9a-f]{1,4}$/.test(hexParts[1])) {
        const hi = parseInt(hexParts[0], 16);
        const lo = parseInt(hexParts[1], 16);
        const mapped = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return classifyIp(mapped);
      }
    }
    if (n === '::1' || n === '::') return 'private';
    if (n.startsWith('fc') || n.startsWith('fd')) return 'private'; // ULA
    if (n.startsWith('ff')) return 'private'; // multicast
    return null;
  }
  return null;
}

function assertIpAllowed(ip: string, host: string): void {
  const cls = classifyIp(ip);
  if (cls === 'metadata') {
    throw new SsrfBlockedError(`Target ${host} resolves to a blocked metadata/link-local address (${ip})`);
  }
  if (cls === 'private' && !allowPrivate()) {
    throw new SsrfBlockedError(
      `Target ${host} resolves to a private address (${ip}); set ALLOW_PRIVATE_SCAN_TARGETS=true to scan internal hosts`,
    );
  }
}

/** Validate a hostname (resolving DNS) before connecting. */
export async function assertScannableHost(host: string): Promise<void> {
  if (!host) throw new SsrfBlockedError('Empty target host');
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (net.isIP(bare)) {
    assertIpAllowed(bare, host);
    return;
  }
  let resolved;
  try {
    resolved = await dns.promises.lookup(bare, { all: true });
  } catch {
    throw new SsrfBlockedError(`Unable to resolve target host: ${host}`);
  }
  if (resolved.length === 0) throw new SsrfBlockedError(`Target host did not resolve: ${host}`);
  for (const r of resolved) assertIpAllowed(r.address, host);
}

/** Validate a full URL (http/https/ws/wss) before connecting. */
export async function assertScannableUrl(rawUrl: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SsrfBlockedError(`Invalid target URL: ${rawUrl}`);
  }
  const proto = parsed.protocol;
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(proto)) {
    throw new SsrfBlockedError(`Unsupported/blocked URL scheme: ${proto}`);
  }
  await assertScannableHost(parsed.hostname);
}

/** Extract the host from a gRPC-style `host:port` / `dns:///host:port` target. */
export async function assertScannableGrpcTarget(target: string): Promise<void> {
  let t = target.trim();
  const schemeIdx = t.indexOf('://');
  if (schemeIdx !== -1) t = t.slice(schemeIdx + 3);
  t = t.split('/')[0]!; // drop any path
  let host: string;
  if (t.startsWith('[')) {
    host = t.slice(1, t.indexOf(']')); // [ipv6]:port
  } else {
    const lastColon = t.lastIndexOf(':');
    host = lastColon > 0 ? t.slice(0, lastColon) : t;
  }
  await assertScannableHost(host);
}
