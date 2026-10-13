import { Global, Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { SmsService } from './sms.service';

@Global()
@Module({ providers: [MailService, SmsService], exports: [MailService, SmsService] })
export class NotificationsModule {}
