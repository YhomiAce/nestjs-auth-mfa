import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import Redis from 'ioredis';
import { CryptoService } from '../common/crypto.service';
import type { AuthUser, ClientInfo } from '../common/types';
import { env } from '../config/env';
import { User } from '../database/schema';
import { MfaService, OtpChannel, VerifyMethod } from '../mfa/mfa.service';
import { MailService } from '../notifications/mail.service';
import { REDIS } from '../redis/redis.module';
import { SessionService } from '../sessions/session.service';
import { UsersService } from '../users/users.service';
import { TokenService } from './token.service';

const MAX_CHALLENGE_ATTEMPTS = 5;
const MAX_LOGIN_FAILS = 10;
const LOGIN_FAIL_WINDOW = 900;
const toSec = (d: Date) => Math.floor(d.getTime() / 1000);

@Injectable()
export class AuthService {
  // used to burn equal CPU time when the email doesn't exist (prevents timing-based user enumeration)
  private readonly dummyHash = argon2.hash('not-a-real-password-' + Math.random());

  constructor(
    private readonly users: UsersService,
    private readonly sessions: SessionService,
    private readonly tokens: TokenService,
    private readonly mfa: MfaService,
    private readonly mail: MailService,
    private readonly crypto: CryptoService,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  // ───────────── registration & email verification ─────────────
  async register(email: string, password: string) {
    const existing = await this.users.findByEmail(email);
    if (existing) {
      // Same response either way (no account enumeration); tell the real owner by email.
      await this.mail.send(email, 'Sign-up attempt', 'Someone tried to register with this email. If it was you, log in or reset your password.');
      return;
    }
    let user: User;
    try {
      user = await this.users.create({ email, passwordHash: await argon2.hash(password) });
    } catch (e) {
      const err = e as { code?: string; cause?: { code?: string } };
      if (err.code === '23505' || err.cause?.code === '23505') return; // lost a race on the unique index
      throw e;
    }
    const token = this.crypto.randomToken(32);
    await this.redis.set(`auth:verify:${this.crypto.hash(token)}`, user.id, 'EX', 86400);
    await this.mail.send(user.email, 'Verify your email', `Verify your email: ${env.APP_URL}/verify-email?token=${token}`);
  }

  async verifyEmail(token: string) {
    const userId = await this.redis.getdel(`auth:verify:${this.crypto.hash(token)}`);
    if (!userId) throw new BadRequestException('Invalid or expired token');
    await this.users.markEmailVerified(userId);
  }

  // ───────────── login (step 1: password) ─────────────
  async login(email: string, password: string, meta: ClientInfo) {
    const failKey = `auth:fail:${email}`;
    if (Number((await this.redis.get(failKey)) ?? 0) >= MAX_LOGIN_FAILS) {
      throw new HttpException('Too many failed attempts. Try again later.', 429);
    }

    const user = await this.users.findByEmail(email);
    const ok = await argon2.verify(user?.passwordHash ?? (await this.dummyHash), password).catch(() => false);
    if (!user || !ok) {
      const n = await this.redis.incr(failKey);
      if (n === 1) await this.redis.expire(failKey, LOGIN_FAIL_WINDOW);
      throw new UnauthorizedException('Invalid credentials');
    }
    await this.redis.del(failKey);
    if (!user.emailVerifiedAt) throw new ForbiddenException('Email not verified');

    if (user.mfaEnabled) {
      // No access/refresh token yet — only a short-lived, single-purpose challenge token.
      const methods = await this.mfa.confirmedTypes(user.id);
      const mfaToken = await this.tokens.createChallenge(user.id);
      return { mfaRequired: true as const, mfaToken, methods: [...methods, 'recovery'], expiresIn: env.MFA_CHALLENGE_TTL_SECONDS };
    }
    return this.startSession(user, ['pwd'], meta);
  }

  // ───────────── login (step 2: MFA) ─────────────
  private async loadChallenge(mfaToken: string) {
    let claims: { sub: string; jti: string };
    try {
      claims = await this.tokens.verifyChallenge(mfaToken);
    } catch {
      throw new UnauthorizedException('Invalid or expired MFA session');
    }
    const key = `mfa:ch:${claims.jti}`;
    const userId = await this.redis.get(key);
    if (!userId || userId !== claims.sub) throw new UnauthorizedException('Invalid or expired MFA session');
    const user = await this.users.findById(userId);
    if (!user) throw new UnauthorizedException('Invalid or expired MFA session');
    return { key, user };
  }

  async sendLoginOtp(mfaToken: string, method: OtpChannel) {
    const { user } = await this.loadChallenge(mfaToken);
    await this.mfa.sendOtpForLogin(user, method);
  }

  async verifyLoginMfa(mfaToken: string, method: VerifyMethod, code: string, meta: ClientInfo) {
    const { key, user } = await this.loadChallenge(mfaToken);

    const tries = await this.redis.incr(`${key}:n`);
    if (tries === 1) await this.redis.expire(`${key}:n`, env.MFA_CHALLENGE_TTL_SECONDS);
    if (tries > MAX_CHALLENGE_ATTEMPTS) {
      await this.redis.del(key, `${key}:n`); // burn the challenge; user must log in again
      throw new UnauthorizedException('Too many attempts. Please log in again.');
    }

    if (!(await this.mfa.verify(user, method, code))) throw new UnauthorizedException('Invalid code');

    await this.redis.del(key, `${key}:n`); // single use
    return this.startSession(user, ['pwd', `mfa:${method}`], meta);
  }

  // ───────────── sessions ─────────────
  private async startSession(user: User, amr: string[], meta: ClientInfo) {
    const mfaAt = amr.some((a) => a.startsWith('mfa:')) ? new Date() : null;
    const { sid, refreshToken } = await this.sessions.create(user.id, amr, mfaAt, meta);
    const accessToken = await this.tokens.signAccess({
      sub: user.id,
      sid,
      role: user.role,
      amr,
      mfaAt: mfaAt ? toSec(mfaAt) : undefined,
    });
    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer' as const,
      expiresIn: env.ACCESS_TTL_SECONDS,
      user: { id: user.id, email: user.email, role: user.role },
    };
  }

  async refresh(refreshToken: string) {
    const { session, refreshToken: next } = await this.sessions.rotate(refreshToken);
    const user = await this.users.findById(session.userId);
    if (!user) throw new UnauthorizedException();
    const accessToken = await this.tokens.signAccess({
      sub: user.id,
      sid: session.id,
      role: user.role, // role changes apply on next refresh
      amr: session.amr,
      mfaAt: session.mfaAt ? toSec(session.mfaAt) : undefined,
    });
    return { accessToken, refreshToken: next, tokenType: 'Bearer' as const, expiresIn: env.ACCESS_TTL_SECONDS };
  }

  logout(refreshToken: string) {
    return this.sessions.revokeByRefreshToken(refreshToken);
  }

  logoutAll(userId: string) {
    return this.sessions.revokeAllForUser(userId);
  }

  async me(u: AuthUser) {
    const user = await this.users.findById(u.id);
    if (!user) throw new UnauthorizedException();
    return { id: user.id, email: user.email, role: user.role, mfaEnabled: user.mfaEnabled, amr: u.amr };
  }

  // ───────────── step-up (re-verify MFA inside an authenticated session) ─────────────
  async sendStepUpOtp(u: AuthUser, method: OtpChannel) {
    const user = await this.users.findById(u.id);
    if (!user?.mfaEnabled) throw new ForbiddenException('MFA is not enabled');
    await this.mfa.sendOtpForLogin(user, method);
  }

  async stepUp(u: AuthUser, method: VerifyMethod, code: string) {
    const user = await this.users.findById(u.id);
    if (!user?.mfaEnabled) throw new ForbiddenException('MFA is not enabled');
    if (!(await this.mfa.verify(user, method, code))) throw new UnauthorizedException('Invalid code');

    const now = new Date();
    const amr = Array.from(new Set([...u.amr, `mfa:${method}`]));
    await this.sessions.markMfa(u.sid, now, amr);
    const accessToken = await this.tokens.signAccess({ sub: user.id, sid: u.sid, role: user.role, amr, mfaAt: toSec(now) });
    return { accessToken, tokenType: 'Bearer' as const, expiresIn: env.ACCESS_TTL_SECONDS };
  }

  // ───────────── password reset ─────────────
  async forgotPassword(email: string) {
    const user = await this.users.findByEmail(email);
    if (!user) return; // always respond identically
    const token = this.crypto.randomToken(32);
    await this.redis.set(`auth:reset:${this.crypto.hash(token)}`, user.id, 'EX', 1800);
    await this.mail.send(user.email, 'Reset your password', `Reset your password: ${env.APP_URL}/reset-password?token=${token}\nExpires in 30 minutes.`);
  }

  async resetPassword(token: string, newPassword: string) {
    const userId = await this.redis.getdel(`auth:reset:${this.crypto.hash(token)}`);
    if (!userId) throw new BadRequestException('Invalid or expired token');
    await this.users.setPassword(userId, await argon2.hash(newPassword));
    await this.sessions.revokeAllForUser(userId); // MFA is still required at next login
  }
}
