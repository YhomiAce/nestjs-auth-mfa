import { Global, Inject, Module, OnApplicationShutdown } from '@nestjs/common';
import Redis from 'ioredis';
import { env } from '../config/env';

export const REDIS = Symbol('REDIS');

@Global()
@Module({
  providers: [{ provide: REDIS, useFactory: () => new Redis(env.REDIS_URL, { maxRetriesPerRequest: 3 }) }],
  exports: [REDIS],
})
export class RedisModule implements OnApplicationShutdown {
  constructor(@Inject(REDIS) private readonly redis: Redis) {}
  async onApplicationShutdown() {
    await this.redis.quit();
  }
}
