import { Injectable, Logger } from '@nestjs/common';
import { env } from '../config/env';

/**
 * SMS provider seam. Default implementation uses Twilio's REST API.
 * To use another provider (Termii, Africa's Talking, Vonage...), replace the body of send().
 */
@Injectable()
export class SmsService {
  private readonly log = new Logger(SmsService.name);

  async send(to: string, body: string) {
    const { TWILIO_ACCOUNT_SID: sid, TWILIO_AUTH_TOKEN: token, TWILIO_FROM: from } = env;
    if (!sid || !token || !from) {
      if (env.NODE_ENV === 'production') throw new Error('SMS provider is not configured');
      this.log.warn(`[DEV SMS] to=${to} body="${body}"`);
      return;
    }
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${sid}:${token}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: to, From: from, Body: body }),
    });
    if (!res.ok) throw new Error(`SMS provider error: ${res.status}`);
  }

  sendOtp(to: string, code: string) {
    return this.send(to, `${env.APP_NAME}: your verification code is ${code}. It expires in 5 minutes.`);
  }
}
