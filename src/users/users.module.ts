import { Module } from '@nestjs/common';
import { SessionsModule } from '../sessions/sessions.module';
import { AdminUsersController } from './admin-users.controller';
import { UsersService } from './users.service';

@Module({
  imports: [SessionsModule],
  controllers: [AdminUsersController],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
