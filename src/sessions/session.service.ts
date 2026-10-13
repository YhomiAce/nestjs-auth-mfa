import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { isUUID } from 'class-validator';
import { and, eq, gt, isNull, or, sql } from 'drizzle-orm';
import Redis from 'ioredis';
import type { ClientInfo } from '../common/types';
import { CryptoService } from '../common/crypto.service';
import { env } from '../config/env';
import { DB, Db } from '../database/database.module';
import { sessions } from '../database/schema';
import { REDIS } from '../redis/redis.module';

/**
 * Refresh tokens are opaque: "<sessionId>.<secret>". Only an HMAC of the secret is stored.
 * Every refresh rotates the secret. Presenting the *previous* secret again means the token
 * was stolen/replayed, so the whole session is revoked.
 */
@Injectable()
export class SessionService {
  constructor(
    @Inject(DB) private readonly db: Db,
    @Inject(REDIS) private readonly redis: Redis,
    private readonly crypto: CryptoService,
  ) {}

  private parse(token: string) {
    const [sid, secret, extra] = token.split('.');
    if (!sid || !secret || extra !== undefined || !isUUID(sid)) return null;
    return { sid, secret };
  }

  async create(userId: string, amr: string[], mfaAt: Date | null, meta: ClientInfo) {
    const secret = this.crypto.randomToken(32);
    const [row] = await this.db
      .insert(sessions)
      .values({
        userId,
        refreshHash: this.crypto.hash(secret),
        amr,
        mfaAt,
        userAgent: meta.userAgent,
        ip: meta.ip,
        expiresAt: new Date(Date.now() + env.REFRESH_TTL_SECONDS * 1000),
      })
      .returning({ id: sessions.id });
    return { sid: row.id, refreshToken: `${row.id}.${secret}` };
  }

  async rotate(refreshToken: string) {
    const parsed = this.parse(refreshToken);
    if (!parsed) throw new UnauthorizedException('Invalid refresh token');

    const presentedHash = this.crypto.hash(parsed.secret);
    const newSecret = this.crypto.randomToken(32);

    // Atomic compare-and-swap: only one concurrent request can win.
    const [row] = await this.db
      .update(sessions)
      .set({
        prevRefreshHash: sql`${sessions.refreshHash}`,
        refreshHash: this.crypto.hash(newSecret),
        lastUsedAt: new Date(),
      })
      .where(
        and(
          eq(sessions.id, parsed.sid),
          eq(sessions.refreshHash, presentedHash),
          isNull(sessions.revokedAt),
          gt(sessions.expiresAt, new Date()),
        ),
      )
      .returning();

    if (!row) {
      const [s] = await this.db.select().from(sessions).where(eq(sessions.id, parsed.sid)).limit(1);
      if (s && !s.revokedAt && s.prevRefreshHash && this.crypto.safeEqual(s.prevRefreshHash, presentedHash)) {
        await this.revoke(s.id); // reuse detected
      }
      throw new UnauthorizedException('Invalid refresh token');
    }
    return { session: row, refreshToken: `${row.id}.${newSecret}` };
  }

  async markMfa(sid: string, at: Date, amr: string[]) {
    await this.db.update(sessions).set({ mfaAt: at, amr }).where(and(eq(sessions.id, sid), isNull(sessions.revokedAt)));
  }

  async revoke(sid: string) {
    await this.db.update(sessions).set({ revokedAt: new Date() }).where(eq(sessions.id, sid));
    await this.redis.set(`auth:revoked:${sid}`, '1', 'EX', env.ACCESS_TTL_SECONDS);
  }

  async revokeByRefreshToken(refreshToken: string) {
    const parsed = this.parse(refreshToken);
    if (!parsed) return;
    const h = this.crypto.hash(parsed.secret);
    const [row] = await this.db
      .select({ id: sessions.id })
      .from(sessions)
      .where(and(eq(sessions.id, parsed.sid), or(eq(sessions.refreshHash, h), eq(sessions.prevRefreshHash, h))))
      .limit(1);
    if (row) await this.revoke(row.id);
  }

  async revokeAllForUser(userId: string, exceptSid?: string) {
    const active = await this.db
      .select({ id: sessions.id })
      .from(sessions)
      .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)));
    const ids = active.map((s) => s.id).filter((id) => id !== exceptSid);
    if (!ids.length) return;
    await this.db
      .update(sessions)
      .set({ revokedAt: new Date() })
      .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt), exceptSid ? sql`${sessions.id} <> ${exceptSid}` : undefined));
    const pipe = this.redis.pipeline();
    ids.forEach((id) => pipe.set(`auth:revoked:${id}`, '1', 'EX', env.ACCESS_TTL_SECONDS));
    await pipe.exec();
  }
}
