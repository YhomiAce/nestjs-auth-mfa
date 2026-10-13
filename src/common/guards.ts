import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import Redis from 'ioredis';
import { TokenService } from '../auth/token.service';
import { REDIS } from '../redis/redis.module';
import { IS_PUBLIC_KEY, PERMISSIONS_KEY, RECENT_MFA_KEY, ROLES_KEY } from './decorators';
import { hasPermissions, Permission, Role } from './permissions';
import type { AuthedRequest } from './types';

/** Authentication: validates the access JWT (scope=access) and that the session wasn't revoked. */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [ctx.getHandler(), ctx.getClass()])) return true;

    const req = ctx.switchToHttp().getRequest<AuthedRequest>();
    const [type, token] = req.headers.authorization?.split(' ') ?? [];
    if (type !== 'Bearer' || !token) throw new UnauthorizedException();

    let claims;
    try {
      claims = await this.tokens.verifyAccess(token);
    } catch {
      throw new UnauthorizedException();
    }
    if (await this.redis.exists(`auth:revoked:${claims.sid}`)) throw new UnauthorizedException('Session revoked');

    req.user = { id: claims.sub, sid: claims.sid, role: claims.role, amr: claims.amr, mfaAt: claims.mfaAt };
    return true;
  }
}

/** Authorization: roles, permissions and step-up MFA freshness. */
@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const targets = [ctx.getHandler(), ctx.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets)) return true;

    const user = ctx.switchToHttp().getRequest<AuthedRequest>().user;
    if (!user) throw new UnauthorizedException();

    const roles = this.reflector.getAllAndOverride<Role[] | undefined>(ROLES_KEY, targets);
    if (roles?.length && !roles.includes(user.role)) throw new ForbiddenException('Insufficient role');

    const perms = this.reflector.getAllAndOverride<Permission[] | undefined>(PERMISSIONS_KEY, targets);
    if (perms?.length && !hasPermissions(user.role, perms)) throw new ForbiddenException('Insufficient permissions');

    const maxAge = this.reflector.getAllAndOverride<number | undefined>(RECENT_MFA_KEY, targets);
    if (maxAge !== undefined) {
      const age = user.mfaAt ? Math.floor(Date.now() / 1000) - user.mfaAt : Infinity;
      if (age > maxAge) {
        throw new ForbiddenException({ statusCode: 403, code: 'STEP_UP_REQUIRED', message: 'Recent MFA verification required' });
      }
    }
    return true;
  }
}
