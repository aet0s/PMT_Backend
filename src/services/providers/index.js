// server/src/services/providers/index.js
// Pluggable provider interfaces for Email and SMS with console drivers for development and testing.

const sentEmails = [];
const sentSms = [];

class ConsoleEmailProvider {
  async sendOtp(to, otp, metadata = {}) {
    const record = {
      to,
      otp,
      type: 'otp',
      subject: 'Your Verification Code',
      body: `Your verification code is: ${otp}. It expires in 10 minutes.`,
      metadata,
      sentAt: new Date().toISOString()
    };
    sentEmails.push(record);
    console.log(`\n[EMAIL CONSOLE] >>> To: ${to} | Subject: "${record.subject}" | OTP: [${otp}]`);
    return { success: true, messageId: `console-email-${Date.now()}` };
  }

  async sendMessage(to, subject, body, metadata = {}) {
    const record = {
      to,
      subject,
      body,
      type: 'message',
      metadata,
      sentAt: new Date().toISOString()
    };
    sentEmails.push(record);
    console.log(`\n[EMAIL CONSOLE] >>> To: ${to} | Subject: "${subject}" | Content: ${body}`);
    return { success: true, messageId: `console-email-${Date.now()}` };
  }

  getLastMessage(to) {
    if (!to) return sentEmails[sentEmails.length - 1];
    return [...sentEmails].reverse().find((m) => m.to.toLowerCase() === to.toLowerCase());
  }

  clearHistory() {
    sentEmails.length = 0;
  }
}

class ConsoleSmsProvider {
  async sendOtp(to, otp, metadata = {}) {
    const record = {
      to,
      otp,
      body: `Your verification code is: ${otp}`,
      metadata,
      sentAt: new Date().toISOString()
    };
    sentSms.push(record);
    console.log(`\n[SMS CONSOLE] >>> To: ${to} | OTP: [${otp}]`);
    return { success: true, messageId: `console-sms-${Date.now()}` };
  }

  async sendMessage(to, body, metadata = {}) {
    const record = {
      to,
      body,
      metadata,
      sentAt: new Date().toISOString()
    };
    sentSms.push(record);
    console.log(`\n[SMS CONSOLE] >>> To: ${to} | Content: ${body}`);
    return { success: true, messageId: `console-sms-${Date.now()}` };
  }

  getLastMessage(to) {
    if (!to) return sentSms[sentSms.length - 1];
    return [...sentSms].reverse().find((m) => m.to === to);
  }

  clearHistory() {
    sentSms.length = 0;
  }
}

// In Phase 2, default to console providers
const emailProvider = new ConsoleEmailProvider();
const smsProvider = new ConsoleSmsProvider();

module.exports = {
  EmailProvider: emailProvider,
  SmsProvider: smsProvider,
  ConsoleEmailProvider,
  ConsoleSmsProvider
};
