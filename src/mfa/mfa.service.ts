import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { and, eq, isNotNull, isNull } from 'drizzle-orm';
import Redis from 'ioredis';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { CryptoService } from '../common/crypto.service';
import { env } from '../config/env';
import { DB, Db } from '../database/database.module';
import { mfaMethods, recoveryCodes, User, users } from '../database/schema';
import { MailService } from '../notifications/mail.service';
import { SmsService } from '../notifications/sms.service';
import { REDIS } from '../redis/redis.module';

authenticator.options = { window: 1 }; // accept previous/next 30s step (clock drift)

export type MfaType = 'totp' | 'email' | 'sms';
export type OtpChannel = 'email' | 'sms';
export type VerifyMethod = MfaType | 'recovery';

type Executor = Pick<Db, 'select' | 'insert' | 'update' | 'delete'>;

const OTP_TTL = 300; // seconds
const OTP_MAX_ATTEMPTS = 5; // per issued code
const OTP_COOLDOWN = 60; // seconds between sends
const OTP_DAILY_CAP = 10; // sends per user per day (SMS pumping / cost protection)
const USER_MAX_FAILS = 10; // failed MFA attempts per user ...
const USER_FAIL_WINDOW = 900; // ... per 15 minutes

@Injectable()
export class MfaService {
  constructor(
    @Inject(DB) private readonly db: Db,
    @Inject(REDIS) private readonly redis: Redis,
    private readonly crypto: CryptoService,
    private readonly mail: MailService,
    private readonly sms: SmsService,
  ) {}

  // ───────────── queries ─────────────
  private async getMethod(userId: string, type: MfaType) {
    const [m] = await this.db
      .select()
      .from(mfaMethods)
      .where(and(eq(mfaMethods.userId, userId), eq(mfaMethods.type, type)))
      .limit(1);
    return m;
  }

  async listMethods(userId: string) {
    const rows = await this.db
      .select()
      .from(mfaMethods)
      .where(and(eq(mfaMethods.userId, userId), isNotNull(mfaMethods.confirmedAt)));
    return rows.map((m) => ({ type: m.type, destination: this.mask(m.type, m.destination), enabledAt: m.confirmedAt }));
  }

  async confirmedTypes(userId: string): Promise<MfaType[]> {
    return (await this.listMethods(userId)).map((m) => m.type);
  }

  private mask(type: MfaType, dest: string | null) {
    if (!dest) return null;
    if (type === 'email') {
      const [l, d] = dest.split('@');
      return `${l.slice(0, 1)}***@${d}`;
    }
    return `${dest.slice(0, 4)}******${dest.slice(-2)}`;
  }

  // ───────────── enrollment: TOTP ─────────────
  async beginTotp(user: User) {
    const existing = await this.getMethod(user.id, 'totp');
    if (existing?.confirmedAt) throw new ConflictException('Authenticator app already enabled');

    const secret = authenticator.generateSecret();
    const secretEnc = this.crypto.encrypt(secret);
    await this.db
      .insert(mfaMethods)
      .values({ userId: user.id, type: 'totp', secretEnc })
      .onConflictDoUpdate({ target: [mfaMethods.userId, mfaMethods.type], set: { secretEnc, confirmedAt: null } });

    const otpauthUrl = authenticator.keyuri(user.email, env.APP_NAME, secret);
    return { secret, otpauthUrl, qrDataUrl: await QRCode.toDataURL(otpauthUrl) };
  }

  async confirmTotp(user: User, code: string) {
    const m = await this.getMethod(user.id, 'totp');
    if (!m || m.confirmedAt || !m.secretEnc) throw new BadRequestException('No pending authenticator setup');
    await this.assertNotLocked(user.id);
    if (!(await this.checkTotp(user.id, m.secretEnc, code))) {
      await this.recordFailure(user.id);
      throw new BadRequestException('Invalid code');
    }
    return this.activate(user.id, 'totp');
  }

  // ───────────── enrollment: email / SMS OTP ─────────────
  async beginOtp(user: User, type: OtpChannel, phone?: string) {
    if (type === 'email' && !user.emailVerifiedAt) throw new ForbiddenException('Verify your email first');
    const existing = await this.getMethod(user.id, type);
    if (existing?.confirmedAt) throw new ConflictException(`${type} MFA already enabled`);

    const destination = type === 'email' ? user.email : phone;
    if (!destination) throw new BadRequestException('Destination required');

    await this.db
      .insert(mfaMethods)
      .values({ userId: user.id, type, destination })
      .onConflictDoUpdate({ target: [mfaMethods.userId, mfaMethods.type], set: { destination, confirmedAt: null } });

    await this.sendOtpTo(user.id, type, destination);
  }

  async confirmOtp(user: User, type: OtpChannel, code: string) {
    const m = await this.getMethod(user.id, type);
    if (!m || m.confirmedAt) throw new BadRequestException('No pending setup for this method');
    await this.assertNotLocked(user.id);
    if (!(await this.checkOtp(user.id, type, code))) {
      await this.recordFailure(user.id);
      throw new BadRequestException('Invalid or expired code');
    }
    return this.activate(user.id, type);
  }

  // ───────────── sending OTPs for login / step-up ─────────────
  async sendOtpForLogin(user: User, type: OtpChannel) {
    const m = await this.getMethod(user.id, type);
    if (!m?.confirmedAt || !m.destination) throw new BadRequestException('Method not enabled');
    await this.sendOtpTo(user.id, type, m.destination);
  }

  private otpKey(userId: string, type: OtpChannel) {
    return `mfa:otp:${userId}:${type}`;
  }

  private otpHash(userId: string, type: OtpChannel, code: string) {
    return this.crypto.hash(`otp:${userId}:${type}:${code}`);
  }

  private async sendOtpTo(userId: string, type: OtpChannel, destination: string) {
    const cooldown = await this.redis.set(`mfa:otp:cd:${userId}:${type}`, '1', 'EX', OTP_COOLDOWN, 'NX');
    if (cooldown !== 'OK') throw new HttpException('Please wait before requesting another code', 429);

    const dayKey = `mfa:otp:day:${userId}`;
    const sent = await this.redis.incr(dayKey);
    if (sent === 1) await this.redis.expire(dayKey, 86400);
    if (sent > OTP_DAILY_CAP) throw new HttpException('Daily code limit reached', 429);

    const code = this.crypto.randomDigits(6);
    const key = this.otpKey(userId, type);
    await this.redis.multi().set(key, this.otpHash(userId, type, code), 'EX', OTP_TTL).del(`${key}:n`).exec();

    try {
      if (type === 'email') await this.mail.sendOtp(destination, code);
      else await this.sms.sendOtp(destination, code);
    } catch {
      await this.redis.del(key, `mfa:otp:cd:${userId}:${type}`);
      throw new ServiceUnavailableException('Could not send the code. Try again shortly.');
    }
  }

  private async checkOtp(userId: string, type: OtpChannel, code: string) {
    if (!/^\d{6}$/.test(code)) return false;
    const key = this.otpKey(userId, type);
    const stored = await this.redis.get(key);
    if (!stored) return false;

    const tries = await this.redis.incr(`${key}:n`);
    if (tries === 1) await this.redis.expire(`${key}:n`, OTP_TTL);
    if (tries > OTP_MAX_ATTEMPTS) {
      await this.redis.del(key, `${key}:n`);
      return false;
    }
    const ok = this.crypto.safeEqual(stored, this.otpHash(userId, type, code));
    if (ok) await this.redis.del(key, `${key}:n`); // single use
    return ok;
  }

  // ───────────── TOTP verification ─────────────
  private async checkTotp(userId: string, secretEnc: string, code: string) {
    if (!/^\d{6}$/.test(code)) return false;
    const secret = this.crypto.decrypt(secretEnc);
    const delta = authenticator.checkDelta(code, secret);
    if (delta === null) return false;
    const step = Math.floor(Date.now() / 1000 / 30) + delta;
    // replay protection: a given time-step's code can be used once
    const fresh = await this.redis.set(`mfa:totp:used:${userId}:${step}`, '1', 'EX', 120, 'NX');
    return fresh === 'OK';
  }

  // ───────────── recovery codes ─────────────
  private normRecovery(code: string) {
    return code.toLowerCase().replace(/[^a-f0-9]/g, '');
  }

  private async issueRecoveryCodes(x: Executor, userId: string) {
    const codes = Array.from({ length: 10 }, () => this.crypto.recoveryCode());
    await x.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
    await x.insert(recoveryCodes).values(
      codes.map((c) => ({ userId, codeHash: this.crypto.hash(`rcv:${userId}:${this.normRecovery(c)}`) })),
    );
    return codes;
  }

  async regenerateRecoveryCodes(user: User) {
    if (!user.mfaEnabled) throw new BadRequestException('Enable MFA first');
    return this.issueRecoveryCodes(this.db, user.id);
  }

  private async checkRecovery(userId: string, code: string) {
    const norm = this.normRecovery(code);
    if (norm.length !== 12) return false;
    const rows = await this.db
      .update(recoveryCodes)
      .set({ usedAt: new Date() })
      .where(
        and(
          eq(recoveryCodes.userId, userId),
          eq(recoveryCodes.codeHash, this.crypto.hash(`rcv:${userId}:${norm}`)),
          isNull(recoveryCodes.usedAt),
        ),
      )
      .returning({ id: recoveryCodes.id });
    return rows.length > 0;
  }

  // ───────────── unified verification (login + step-up) ─────────────
  private failKey(userId: string) {
    return `mfa:fail:${userId}`;
  }

  private async assertNotLocked(userId: string) {
    const fails = Number((await this.redis.get(this.failKey(userId))) ?? 0);
    if (fails >= USER_MAX_FAILS) throw new HttpException('Too many failed attempts. Try again later.', 429);
  }

  private async recordFailure(userId: string) {
    const n = await this.redis.incr(this.failKey(userId));
    if (n === 1) await this.redis.expire(this.failKey(userId), USER_FAIL_WINDOW);
  }

  async verify(user: User, method: VerifyMethod, code: string): Promise<boolean> {
    await this.assertNotLocked(user.id);

    let ok = false;
    if (method === 'recovery') {
      ok = await this.checkRecovery(user.id, code);
    } else {
      const m = await this.getMethod(user.id, method);
      if (m?.confirmedAt) {
        ok =
          method === 'totp'
            ? !!m.secretEnc && (await this.checkTotp(user.id, m.secretEnc, code))
            : await this.checkOtp(user.id, method, code);
      }
    }

    if (ok) await this.redis.del(this.failKey(user.id));
    else await this.recordFailure(user.id);
    return ok;
  }

  // ───────────── activate / disable ─────────────
  private async activate(userId: string, type: MfaType) {
    return this.db.transaction(async (tx) => {
      await tx
        .update(mfaMethods)
        .set({ confirmedAt: new Date() })
        .where(and(eq(mfaMethods.userId, userId), eq(mfaMethods.type, type)));
      await tx.update(users).set({ mfaEnabled: true, updatedAt: new Date() }).where(eq(users.id, userId));

      const [hasCodes] = await tx
        .select({ id: recoveryCodes.id })
        .from(recoveryCodes)
        .where(and(eq(recoveryCodes.userId, userId), isNull(recoveryCodes.usedAt)))
        .limit(1);
      // recovery codes are issued once, when the first method is enabled
      return { enabled: type, recoveryCodes: hasCodes ? undefined : await this.issueRecoveryCodes(tx, userId) };
    });
  }

  async disable(userId: string, type: MfaType) {
    await this.db.transaction(async (tx) => {
      const deleted = await tx
        .delete(mfaMethods)
        .where(and(eq(mfaMethods.userId, userId), eq(mfaMethods.type, type)))
        .returning({ id: mfaMethods.id });
      if (!deleted.length) throw new NotFoundException('Method not found');

      const [left] = await tx
        .select({ id: mfaMethods.id })
        .from(mfaMethods)
        .where(and(eq(mfaMethods.userId, userId), isNotNull(mfaMethods.confirmedAt)))
        .limit(1);
      if (!left) {
        await tx.update(users).set({ mfaEnabled: false, updatedAt: new Date() }).where(eq(users.id, userId));
        await tx.delete(recoveryCodes).where(eq(recoveryCodes.userId, userId));
      }
    });
  }
}
