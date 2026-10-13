import { Injectable } from '@nestjs/common';
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from 'crypto';
import { env } from '../config/env';

@Injectable()
export class CryptoService {
  private readonly key = Buffer.from(env.MFA_ENC_KEY, 'base64');

  /** AES-256-GCM. Output: v1.<iv>.<tag>.<ciphertext> (base64url). */
  encrypt(plain: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return ['v1', iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join('.');
  }

  decrypt(payload: string): string {
    const [v, iv, tag, ct] = payload.split('.');
    if (v !== 'v1' || !iv || !tag || !ct) throw new Error('Bad ciphertext');
    const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]).toString('utf8');
  }

  /** Keyed hash (HMAC-SHA256 with a server-side pepper). Used for OTPs, recovery codes, refresh/reset tokens. */
  hash(value: string): string {
    return createHmac('sha256', env.HASH_PEPPER).update(value).digest('hex');
  }

  safeEqual(a: string, b: string): boolean {
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    return ba.length === bb.length && timingSafeEqual(ba, bb);
  }

  randomToken(bytes = 32): string {
    return randomBytes(bytes).toString('base64url');
  }

  randomDigits(length = 6): string {
    return String(randomInt(0, 10 ** length)).padStart(length, '0');
  }

  recoveryCode(): string {
    const h = randomBytes(6).toString('hex');
    return `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8, 12)}`;
  }
}
