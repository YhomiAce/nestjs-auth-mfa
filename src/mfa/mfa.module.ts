import { Module } from '@nestjs/common';
import { UsersModule } from '../users/users.module';
import { MfaController } from './mfa.controller';
import { MfaService } from './mfa.service';

@Module({
  imports: [UsersModule],
  controllers: [MfaController],
  providers: [MfaService],
  exports: [MfaService],
})
export class MfaModule {}
