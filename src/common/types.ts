import type { Request } from 'express';
import type { Role } from './permissions';

export interface AuthUser {
  id: string;
  sid: string;
  role: Role;
  amr: string[];
  mfaAt?: number; // epoch seconds of last MFA
}

export type AuthedRequest = Request & { user?: AuthUser };

export interface ClientInfo {
  ip: string | null;
  userAgent: string | null;
}
