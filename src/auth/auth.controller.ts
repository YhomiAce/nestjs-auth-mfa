import { Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { Client, CurrentUser, Public } from '../common/decorators';
import type { AuthUser, ClientInfo } from '../common/types';
import { AuthService } from './auth.service';
import {
  ForgotPasswordDto,
  LoginDto,
  MfaSendDto,
  MfaVerifyDto,
  RefreshDto,
  RegisterDto,
  ResetPasswordDto,
  StepUpSendDto,
  StepUpVerifyDto,
  TokenDto,
} from './dto';

const strict = { default: { limit: 5, ttl: 60_000 } };

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public() @Throttle(strict) @Post('register') @HttpCode(202)
  async register(@Body() dto: RegisterDto) {
    await this.auth.register(dto.email, dto.password);
    return { message: 'If the email can be registered, a verification link has been sent.' };
  }

  @Public() @Throttle(strict) @Post('verify-email') @HttpCode(204)
  async verifyEmail(@Body() dto: TokenDto) {
    await this.auth.verifyEmail(dto.token);
  }

  // Step 1: password. Returns tokens, or { mfaRequired, mfaToken } if the user has MFA.
  @Public() @Throttle(strict) @Post('login') @HttpCode(200)
  login(@Body() dto: LoginDto, @Client() meta: ClientInfo) {
    return this.auth.login(dto.email, dto.password, meta);
  }

  // Step 2a (email/SMS only): ask the server to send an OTP for this challenge.
  @Public() @Throttle(strict) @Post('mfa/send') @HttpCode(202)
  async mfaSend(@Body() dto: MfaSendDto) {
    await this.auth.sendLoginOtp(dto.mfaToken, dto.method);
    return { message: 'Code sent' };
  }

  // Step 2b: verify the code (totp | email | sms | recovery) -> real tokens.
  @Public() @Throttle(strict) @Post('mfa/verify') @HttpCode(200)
  mfaVerify(@Body() dto: MfaVerifyDto, @Client() meta: ClientInfo) {
    return this.auth.verifyLoginMfa(dto.mfaToken, dto.method, dto.code, meta);
  }

  @Public() @Throttle({ default: { limit: 20, ttl: 60_000 } }) @Post('refresh') @HttpCode(200)
  refresh(@Body() dto: RefreshDto) {
    return this.auth.refresh(dto.refreshToken);
  }

  @Public() @Post('logout') @HttpCode(204)
  async logout(@Body() dto: RefreshDto) {
    await this.auth.logout(dto.refreshToken);
  }

  @Post('logout-all') @HttpCode(204)
  async logoutAll(@CurrentUser() u: AuthUser) {
    await this.auth.logoutAll(u.id);
  }

  @Get('me')
  me(@CurrentUser() u: AuthUser) {
    return this.auth.me(u);
  }

  // Step-up: re-verify MFA to unlock sensitive routes (@RequireRecentMfa).
  @Throttle(strict) @Post('step-up/send') @HttpCode(202)
  async stepUpSend(@CurrentUser() u: AuthUser, @Body() dto: StepUpSendDto) {
    await this.auth.sendStepUpOtp(u, dto.method);
    return { message: 'Code sent' };
  }

  @Throttle(strict) @Post('step-up/verify') @HttpCode(200)
  stepUpVerify(@CurrentUser() u: AuthUser, @Body() dto: StepUpVerifyDto) {
    return this.auth.stepUp(u, dto.method, dto.code);
  }

  @Public() @Throttle(strict) @Post('forgot-password') @HttpCode(202)
  async forgot(@Body() dto: ForgotPasswordDto) {
    await this.auth.forgotPassword(dto.email);
    return { message: 'If the account exists, a reset link has been sent.' };
  }

  @Public() @Throttle(strict) @Post('reset-password') @HttpCode(204)
  async reset(@Body() dto: ResetPasswordDto) {
    await this.auth.resetPassword(dto.token, dto.newPassword);
  }
}
