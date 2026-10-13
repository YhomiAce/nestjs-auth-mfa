import { roleEnum } from '../database/schema';

export type Role = (typeof roleEnum.enumValues)[number];
export type Permission = 'users:read' | 'users:manage';

export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = {
  user: [],
  support: ['users:read'],
  admin: ['users:read', 'users:manage'],
};

export const hasPermissions = (role: Role, required: Permission[]) =>
  required.every((p) => ROLE_PERMISSIONS[role].includes(p));
