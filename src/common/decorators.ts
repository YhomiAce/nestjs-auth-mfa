import { createParamDecorator, ExecutionContext, SetMetadata } from '@nestjs/common';
import type { Permission, Role } from './permissions';
import type { AuthedRequest, AuthUser, ClientInfo } from './types';

export const IS_PUBLIC_KEY = 'isPublic';
export const ROLES_KEY = 'roles';
export const PERMISSIONS_KEY = 'permissions';
export const RECENT_MFA_KEY = 'recentMfa';

/** Skip authentication for this route. */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
/** Require one of these roles. */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
/** Require all of these permissions (resolved from the user's role). */
export const RequirePermissions = (...p: Permission[]) => SetMetadata(PERMISSIONS_KEY, p);
/** Require an MFA verification within the last N seconds (step-up). */
export const RequireRecentMfa = (maxAgeSeconds = 300) => SetMetadata(RECENT_MFA_KEY, maxAgeSeconds);

export const CurrentUser = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): AuthUser => ctx.switchToHttp().getRequest<AuthedRequest>().user!,
);

export const Client = createParamDecorator((_: unknown, ctx: ExecutionContext): ClientInfo => {
  const req = ctx.switchToHttp().getRequest<AuthedRequest>();
  return { ip: req.ip ?? null, userAgent: req.headers['user-agent']?.slice(0, 255) ?? null };
});
