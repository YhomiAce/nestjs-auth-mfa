import { BadRequestException, Body, Controller, Get, NotFoundException, Param, ParseUUIDPipe, Patch, Query } from '@nestjs/common';
import { IsIn } from 'class-validator';
import { CurrentUser, RequirePermissions, RequireRecentMfa, Roles } from '../common/decorators';
import type { Role } from '../common/permissions';
import type { AuthUser } from '../common/types';
import { roleEnum } from '../database/schema';
import { SessionService } from '../sessions/session.service';
import { UsersService } from './users.service';

class UpdateRoleDto {
  @IsIn(roleEnum.enumValues) role: Role;
}

@Controller('admin/users')
export class AdminUsersController {
  constructor(private readonly users: UsersService, private readonly sessions: SessionService) {}

  // support + admin (permission users:read)
  @Get()
  @RequirePermissions('users:read')
  list(@Query('limit') limit?: string, @Query('offset') offset?: string) {
    return this.users.list(Math.min(Number(limit) || 50, 100), Number(offset) || 0);
  }

  // admin only, and the admin must have passed MFA in the last 5 minutes
  @Patch(':id/role')
  @Roles('admin')
  @RequirePermissions('users:manage')
  @RequireRecentMfa(300)
  async updateRole(@Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateRoleDto, @CurrentUser() actor: AuthUser) {
    if (id === actor.id) throw new BadRequestException('You cannot change your own role');
    const updated = await this.users.setRole(id, dto.role);
    if (!updated) throw new NotFoundException();
    await this.sessions.revokeAllForUser(id); // force re-login so the new role takes effect immediately
    return { id: updated.id, role: updated.role };
  }
}
