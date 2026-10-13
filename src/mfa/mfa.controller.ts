import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  HttpCode,
  Param,
  ParseEnumPipe,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { IsString, Matches, MaxLength, MinLength } from 'class-validator';
import { CurrentUser, RequireRecentMfa } from '../common/decorators';
import type { AuthUser } from '../common/types';
import { UsersService } from '../users/users.service';
import { MfaService, MfaType } from './mfa.service';

class CodeDto {
  @IsString() @MinLength(6) @MaxLength(32) code: string;
}
class SmsSetupDto {
  @Matches(/^\+[1-9]\d{7,14}$/, { message: 'phone must be in E.164 format, e.g. +2348012345678' }) phone: string;
}

const MfaTypes = { totp: 'totp', email: 'email', sms: 'sms' } as const;
const STEP_UP_WINDOW = 300;

@Controller('mfa')
export class MfaController {
  constructor(private readonly mfa: MfaService, private readonly users: UsersService) {}

  private async me(u: AuthUser) {
    const user = await this.users.findById(u.id);
    if (!user) throw new UnauthorizedException();
    return user;
  }

  /** If MFA is already on, adding another factor needs a fresh MFA check (stolen-token protection). */
  private async meForEnrollment(u: AuthUser) {
    const user = await this.me(u);
    if (user.mfaEnabled) {
      const age = u.mfaAt ? Math.floor(Date.now() / 1000) - u.mfaAt : Infinity;
      if (age > STEP_UP_WINDOW) {
        throw new ForbiddenException({ statusCode: 403, code: 'STEP_UP_REQUIRED', message: 'Recent MFA verification required' });
      }
    }
    return user;
  }

  @Get('methods')
  methods(@CurrentUser() u: AuthUser) {
    return this.mfa.listMethods(u.id);
  }

  // ── TOTP ──
  @Post('totp/setup')
  async totpSetup(@CurrentUser() u: AuthUser) {
    return this.mfa.beginTotp(await this.meForEnrollment(u));
  }

  @Post('totp/confirm') @HttpCode(200)
  async totpConfirm(@CurrentUser() u: AuthUser, @Body() dto: CodeDto) {
    return this.mfa.confirmTotp(await this.me(u), dto.code);
  }

  // ── Email OTP ──
  @Post('email/setup') @HttpCode(202)
  async emailSetup(@CurrentUser() u: AuthUser) {
    await this.mfa.beginOtp(await this.meForEnrollment(u), 'email');
    return { message: 'Code sent' };
  }

  @Post('email/confirm') @HttpCode(200)
  async emailConfirm(@CurrentUser() u: AuthUser, @Body() dto: CodeDto) {
    return this.mfa.confirmOtp(await this.me(u), 'email', dto.code);
  }

  // ── SMS OTP ──
  @Post('sms/setup') @HttpCode(202)
  async smsSetup(@CurrentUser() u: AuthUser, @Body() dto: SmsSetupDto) {
    await this.mfa.beginOtp(await this.meForEnrollment(u), 'sms', dto.phone);
    return { message: 'Code sent' };
  }

  @Post('sms/confirm') @HttpCode(200)
  async smsConfirm(@CurrentUser() u: AuthUser, @Body() dto: CodeDto) {
    return this.mfa.confirmOtp(await this.me(u), 'sms', dto.code);
  }

  // ── Manage ──
  @Delete(':type') @HttpCode(204) @RequireRecentMfa(STEP_UP_WINDOW)
  async disable(@CurrentUser() u: AuthUser, @Param('type', new ParseEnumPipe(MfaTypes)) type: MfaType) {
    await this.mfa.disable(u.id, type);
  }

  @Post('recovery-codes/regenerate') @RequireRecentMfa(STEP_UP_WINDOW)
  async regenerate(@CurrentUser() u: AuthUser) {
    return { recoveryCodes: await this.mfa.regenerateRecoveryCodes(await this.me(u)) };
  }
}
