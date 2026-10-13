import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nest-lab/throttler-storage-redis';
import Redis from 'ioredis';
import { AuthModule } from './auth/auth.module';
import { CommonModule } from './common/common.module';
import { AuthorizationGuard, JwtAuthGuard } from './common/guards';
import { DatabaseModule } from './database/database.module';
import { MfaModule } from './mfa/mfa.module';
import { NotificationsModule } from './notifications/notifications.module';
import { REDIS, RedisModule } from './redis/redis.module';
import { SessionsModule } from './sessions/sessions.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    CommonModule,
    DatabaseModule,
    RedisModule,
    NotificationsModule,
    ThrottlerModule.forRootAsync({
      inject: [REDIS],
      useFactory: (redis: Redis) => ({
        throttlers: [{ ttl: 60_000, limit: 100 }],
        storage: new ThrottlerStorageRedisService(redis), // shared across instances
      }),
    }),
    SessionsModule,
    UsersModule,
    MfaModule,
    AuthModule,
  ],
  providers: [
    // Order matters: rate-limit -> authenticate -> authorize
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: AuthorizationGuard },
  ],
})
export class AppModule {}
