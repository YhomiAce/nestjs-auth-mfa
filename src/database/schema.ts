import {
  boolean,
  index,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

export const roleEnum = pgEnum('role', ['user', 'support', 'admin']);
export const mfaTypeEnum = pgEnum('mfa_type', ['totp', 'email', 'sms']);

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: text('email').notNull(), // always stored lowercase
    passwordHash: text('password_hash').notNull(),
    role: roleEnum('role').notNull().default('user'),
    emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
    mfaEnabled: boolean('mfa_enabled').notNull().default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('users_email_uq').on(t.email)],
);

// One row per (user, method). A row is "pending" until confirmedAt is set.
export const mfaMethods = pgTable(
  'mfa_methods',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    type: mfaTypeEnum('type').notNull(),
    secretEnc: text('secret_enc'), // TOTP secret, AES-256-GCM encrypted
    destination: text('destination'), // email address or E.164 phone number (OTP methods)
    confirmedAt: timestamp('confirmed_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('mfa_methods_user_type_uq').on(t.userId, t.type)],
);

export const recoveryCodes = pgTable(
  'recovery_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: text('code_hash').notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
  },
  (t) => [index('recovery_codes_user_idx').on(t.userId)],
);

// A session = one refresh-token chain (one device/login).
export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(), // also the `sid` claim
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    refreshHash: text('refresh_hash').notNull(),
    prevRefreshHash: text('prev_refresh_hash'), // for refresh-token reuse detection
    amr: text('amr').array().notNull(), // e.g. ['pwd', 'mfa:totp']
    mfaAt: timestamp('mfa_at', { withTimezone: true }), // last successful MFA (step-up)
    userAgent: text('user_agent'),
    ip: text('ip'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
  },
  (t) => [index('sessions_user_idx').on(t.userId)],
);

export type User = typeof users.$inferSelect;
export type MfaMethod = typeof mfaMethods.$inferSelect;
export type Session = typeof sessions.$inferSelect;
