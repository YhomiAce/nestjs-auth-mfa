import { Transform } from 'class-transformer';
import { IsEmail, IsIn, IsString, MaxLength, MinLength } from 'class-validator';

const normEmail = () => Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value));

export class RegisterDto {
  @normEmail() @IsEmail() @MaxLength(254) email: string;
  @IsString() @MinLength(12) @MaxLength(128) password: string;
}
export class LoginDto {
  @normEmail() @IsEmail() email: string;
  @IsString() @MaxLength(128) password: string;
}
export class TokenDto {
  @IsString() @MaxLength(512) token: string;
}
export class RefreshDto {
  @IsString() @MaxLength(512) refreshToken: string;
}
export class ForgotPasswordDto {
  @normEmail() @IsEmail() email: string;
}
export class ResetPasswordDto {
  @IsString() @MaxLength(512) token: string;
  @IsString() @MinLength(12) @MaxLength(128) newPassword: string;
}

export const OTP_METHODS = ['email', 'sms'] as const;
export const VERIFY_METHODS = ['totp', 'email', 'sms', 'recovery'] as const;

export class MfaSendDto {
  @IsString() mfaToken: string;
  @IsIn(OTP_METHODS) method: 'email' | 'sms';
}
export class MfaVerifyDto {
  @IsString() mfaToken: string;
  @IsIn(VERIFY_METHODS) method: (typeof VERIFY_METHODS)[number];
  @IsString() @MinLength(6) @MaxLength(32) code: string;
}
export class StepUpSendDto {
  @IsIn(OTP_METHODS) method: 'email' | 'sms';
}
export class StepUpVerifyDto {
  @IsIn(VERIFY_METHODS) method: (typeof VERIFY_METHODS)[number];
  @IsString() @MinLength(6) @MaxLength(32) code: string;
}
