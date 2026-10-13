import 'dotenv/config';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(3000),
  APP_NAME: z.string().default('MyApp'),
  APP_URL: z.string().default('http://localhost:3000'),

  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().default('redis://localhost:6379'),

  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_MFA_SECRET: z.string().min(32),
  HASH_PEPPER: z.string().min(32),
  MFA_ENC_KEY: z
    .string()
    .refine((v) => Buffer.from(v, 'base64').length === 32, 'MFA_ENC_KEY must be 32 bytes, base64-encoded'),

  ACCESS_TTL_SECONDS: z.coerce.number().default(900),
  REFRESH_TTL_SECONDS: z.coerce.number().default(60 * 60 * 24 * 30),
  MFA_CHALLENGE_TTL_SECONDS: z.coerce.number().default(300),

  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().default(587),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  MAIL_FROM: z.string().default('MyApp <no-reply@myapp.local>'),

  TWILIO_ACCOUNT_SID: z.string().optional(),
  TWILIO_AUTH_TOKEN: z.string().optional(),
  TWILIO_FROM: z.string().optional(),
});

export const env = schema.parse(process.env);
