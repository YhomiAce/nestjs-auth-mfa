import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { env } from '../config/env';

@Injectable()
export class MailService {
  private readonly log = new Logger(MailService.name);
  private readonly transport = env.SMTP_HOST
    ? nodemailer.createTransport({
        host: env.SMTP_HOST,
        port: env.SMTP_PORT,
        secure: env.SMTP_PORT === 465,
        auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined,
      })
    : null;

  async send(to: string, subject: string, text: string) {
    if (!this.transport) {
      if (env.NODE_ENV === 'production') throw new Error('SMTP is not configured');
      this.log.warn(`[DEV MAIL] to=${to} subject="${subject}"\n${text}`);
      return;
    }
    await this.transport.sendMail({ from: env.MAIL_FROM, to, subject, text });
  }

  sendOtp(to: string, code: string) {
    return this.send(to, `${env.APP_NAME} verification code`, `Your code is ${code}. It expires in 5 minutes. If you didn't request it, ignore this email.`);
  }
}
