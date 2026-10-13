import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'crypto';
import Redis from 'ioredis';
import type { Role } from '../common/permissions';
import { env } from '../config/env';
import { REDIS } from '../redis/redis.module';

export interface AccessClaims {
  sub: string;
  sid: string;
  role: Role;
  amr: string[];
  mfaAt?: number;
  scope: 'access';
}

@Injectable()
export class TokenService {
  constructor(private readonly jwt: JwtService, @Inject(REDIS) private readonly redis: Redis) {}

  signAccess(c: Omit<AccessClaims, 'scope'>) {
    return this.jwt.signAsync(
      { ...c, scope: 'access' },
      { secret: env.JWT_ACCESS_SECRET, expiresIn: env.ACCESS_TTL_SECONDS, algorithm: 'HS256' },
    );
  }

  async verifyAccess(token: string): Promise<AccessClaims> {
    const p = await this.jwt.verifyAsync<AccessClaims>(token, { secret: env.JWT_ACCESS_SECRET, algorithms: ['HS256'] });
    if (p.scope !== 'access') throw new Error('wrong token scope');
    return p;
  }

  /**
   * MFA challenge token: signed with a DIFFERENT secret and scope=mfa, so it can never pass
   * the access guard. The jti is also stored in Redis so the challenge is revocable and single-use.
   */
  async createChallenge(userId: string): Promise<string> {
    const jti = randomUUID();
    await this.redis.set(`mfa:ch:${jti}`, userId, 'EX', env.MFA_CHALLENGE_TTL_SECONDS);
    return this.jwt.signAsync(
      { sub: userId, scope: 'mfa' },
      { secret: env.JWT_MFA_SECRET, expiresIn: env.MFA_CHALLENGE_TTL_SECONDS, jwtid: jti, algorithm: 'HS256' },
    );
  }

  async verifyChallenge(token: string) {
    const p = await this.jwt.verifyAsync<{ sub: string; scope: string; jti: string }>(token, {
      secret: env.JWT_MFA_SECRET,
      algorithms: ['HS256'],
    });
    if (p.scope !== 'mfa' || !p.jti) throw new Error('wrong token scope');
    return p;
  }
}
