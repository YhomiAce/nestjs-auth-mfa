import { Global, Inject, Module, OnApplicationShutdown } from '@nestjs/common';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { env } from '../config/env';
import * as schema from './schema';

export const PG_POOL = Symbol('PG_POOL');
export const DB = Symbol('DB');
export type Db = NodePgDatabase<typeof schema>;

@Global()
@Module({
  providers: [
    { provide: PG_POOL, useFactory: () => new Pool({ connectionString: env.DATABASE_URL, max: 10 }) },
    { provide: DB, inject: [PG_POOL], useFactory: (pool: Pool): Db => drizzle({ client: pool, schema }) },
  ],
  exports: [DB],
})
export class DatabaseModule implements OnApplicationShutdown {
  constructor(@Inject(PG_POOL) private readonly pool: Pool) {}
  async onApplicationShutdown() {
    await this.pool.end();
  }
}
