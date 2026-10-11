import crypto from 'crypto';

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(encoded: string): Buffer {
  const stripped = encoded.replace(/[=\s]/g, '').toUpperCase();
  const bits: number[] = [];
  for (const ch of stripped) {
    const val = BASE32_CHARS.indexOf(ch);
    if (val === -1) throw new Error('Invalid base32 character');
    bits.push(val);
  }
  const bytes: number[] = [];
  let buffer = 0;
  let bitsInBuffer = 0;
  for (const val of bits) {
    buffer = (buffer << 5) | val;
    bitsInBuffer += 5;
    if (bitsInBuffer >= 8) {
      bitsInBuffer -= 8;
      bytes.push((buffer >> bitsInBuffer) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

function generateTOTP(secret: Buffer, counter: bigint): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(counter);
  const hmac = crypto.createHmac('sha1', secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  return (code % 1_000_000).toString().padStart(6, '0');
}

export function verifyTOTP(secret: string, code: string, window = 1): boolean {
  if (!/^\d{6}$/.test(code)) return false;
  const key = base32Decode(secret);
  const now = BigInt(Math.floor(Date.now() / 30_000));
  for (let i = -window; i <= window; i++) {
    if (crypto.timingSafeEqual(Buffer.from(generateTOTP(key, now + BigInt(i))), Buffer.from(code))) {
      return true;
    }
  }
  return false;
}

export function verifyBackupCode(provided: string, storedCodes: string[]): number {
  const normalized = Buffer.from(provided.trim().toLowerCase());
  for (let i = 0; i < storedCodes.length; i++) {
    const stored = Buffer.from((storedCodes[i] || '').trim().toLowerCase());
    if (stored.length === normalized.length && crypto.timingSafeEqual(normalized, stored)) {
      return i;
    }
  }
  return -1;
}
