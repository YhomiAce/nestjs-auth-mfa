import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { MfaModule } from '../mfa/mfa.module';
import { SessionsModule } from '../sessions/sessions.module';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { TokenService } from './token.service';

@Module({
  imports: [JwtModule.register({}), UsersModule, MfaModule, SessionsModule],
  controllers: [AuthController],
  providers: [AuthService, TokenService],
  exports: [TokenService], // used by the global JwtAuthGuard
})
export class AuthModule {}
