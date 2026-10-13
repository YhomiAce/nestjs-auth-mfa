import { Inject, Injectable } from '@nestjs/common';
import { desc, eq } from 'drizzle-orm';
import type { Role } from '../common/permissions';
import { DB, Db } from '../database/database.module';
import { users } from '../database/schema';

@Injectable()
export class UsersService {
  constructor(@Inject(DB) private readonly db: Db) {}

  async findByEmail(email: string) {
    const [u] = await this.db.select().from(users).where(eq(users.email, email)).limit(1);
    return u;
  }

  async findById(id: string) {
    const [u] = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
    return u;
  }

  async create(v: { email: string; passwordHash: string }) {
    const [u] = await this.db.insert(users).values(v).returning();
    return u;
  }

  async setPassword(id: string, passwordHash: string) {
    await this.db.update(users).set({ passwordHash, updatedAt: new Date() }).where(eq(users.id, id));
  }

  async markEmailVerified(id: string) {
    await this.db.update(users).set({ emailVerifiedAt: new Date(), updatedAt: new Date() }).where(eq(users.id, id));
  }

  async setRole(id: string, role: Role) {
    const [u] = await this.db.update(users).set({ role, updatedAt: new Date() }).where(eq(users.id, id)).returning();
    return u;
  }

  list(limit = 50, offset = 0) {
    return this.db
      .select({ id: users.id, email: users.email, role: users.role, mfaEnabled: users.mfaEnabled, createdAt: users.createdAt })
      .from(users)
      .orderBy(desc(users.createdAt))
      .limit(limit)
      .offset(offset);
  }
}
