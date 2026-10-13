# NestJS Auth + MFA (TOTP, Email OTP, SMS OTP)

Stack: NestJS 11, PostgreSQL, Drizzle ORM, Redis (ioredis), JWT, argon2id.

## Run

```bash
cp .env.example .env            # then fill MFA_ENC_KEY (openssl rand -base64 32) and the 3 secrets
docker compose up -d            # postgres, redis, mailpit (emails at http://localhost:8025)
npm install
npm run db:push                 # dev: sync schema.  For real migrations: db:generate then db:migrate
npm run start:dev
```
With no SMTP/Twilio configured outside production, emails and SMS are printed in the server log.

## Login flow (no access token until MFA succeeds)

```
POST /auth/login {email,password}
  ├─ no MFA  -> { accessToken, refreshToken }
  └─ MFA on  -> { mfaRequired:true, mfaToken, methods:[...] }     (mfaToken = 5 min, scope=mfa, own secret, single-use)
       ├─ (email/sms only) POST /auth/mfa/send   {mfaToken, method}
       └─ POST /auth/mfa/verify {mfaToken, method:'totp'|'email'|'sms'|'recovery', code}
            -> { accessToken, refreshToken }
```

## Endpoints

| Route | Auth | Notes |
|---|---|---|
| POST /auth/register, /auth/verify-email | public | enumeration-safe; login requires verified email |
| POST /auth/login, /auth/mfa/send, /auth/mfa/verify | public | 5 req/min/IP + per-account and per-user lockouts |
| POST /auth/refresh, /auth/logout | public | rotating refresh token w/ reuse detection |
| POST /auth/logout-all, GET /auth/me | access | |
| POST /auth/step-up/send, /auth/step-up/verify | access | re-verify MFA -> fresh access token (`mfaAt`) |
| POST /auth/forgot-password, /auth/reset-password | public | reset revokes all sessions; MFA still required after |
| GET /mfa/methods | access | |
| POST /mfa/totp/setup, /confirm | access | returns QR data URL + otpauth URL; recovery codes on first enable |
| POST /mfa/email/setup, /confirm | access | |
| POST /mfa/sms/setup {phone}, /confirm | access | E.164 phone |
| DELETE /mfa/:type, POST /mfa/recovery-codes/regenerate | access + step-up | `@RequireRecentMfa(300)` |
| GET /admin/users | permission `users:read` | support, admin |
| PATCH /admin/users/:id/role | admin + `users:manage` + step-up | revokes target's sessions |

Adding a factor while MFA is already on also requires a fresh MFA check.

## Authorization

`ThrottlerGuard -> JwtAuthGuard -> AuthorizationGuard` are global. Routes are private by default;
use `@Public()`, `@Roles()`, `@RequirePermissions()`, `@RequireRecentMfa(seconds)`.
Role -> permission map lives in `src/common/permissions.ts` (swap for DB tables if you need dynamic roles).
To make the first admin: `UPDATE users SET role='admin' WHERE email='you@example.com';`

## Security notes

- TOTP secrets: AES-256-GCM at rest. Codes: ±1 step window, each time-step usable once (Redis).
- Email/SMS OTP: 6 digits, HMAC-hashed in Redis, 5 min TTL, 5 tries, 60 s resend cooldown, 10 sends/day/user, single use.
- Recovery codes: 10, HMAC-hashed, single use, shown once.
- Refresh tokens: opaque, HMAC-hashed, rotated atomically; replay of the previous token revokes the session.
- Logout revokes the session in Postgres and denylists its `sid` in Redis for the access-token lifetime.
- Lockouts are per account/user (DoS tradeoff: an attacker can temporarily lock a victim; tune limits/windows).
- SMS is the weakest factor (SIM swap). Consider requiring TOTP for admins and offering SMS only as fallback.
- Not included: CORS config, audit log table, WebAuthn/passkeys, CSRF (tokens are in the body/header, not cookies).
