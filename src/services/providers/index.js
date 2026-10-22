// server/src/services/providers/index.js
// Pluggable provider interfaces for Email and SMS with SMTP and console drivers.

const nodemailer = require('nodemailer');

const sentEmails = [];
const sentSms = [];

class ConsoleEmailProvider {
  async sendOtp(to, otp, metadata = {}) {
    const record = {
      to,
      otp,
      type: 'otp',
      subject: metadata.purpose === 'password_reset' ? 'Your Password Reset Code' : 'Your Verification Code',
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

  async sendInvitationEmail(to, options = {}) {
    const { inviterName, companyName, workspaceName, roleName, inviteUrl } = options;
    const comp = companyName || 'Our Workspace';
    const ws = workspaceName || comp;
    const inviter = inviterName || 'A team administrator';
    const role = roleName || 'Team Member';
    const subject = `You've been invited to join ${ws} on TaskFlow`;
    const plainText = `Hello,\n\n${inviter} has invited you to join ${ws} (${comp}) as a ${role}.\n\nAccept your invitation and activate your account using the link below:\n${inviteUrl}\n\nThis invitation link expires in 7 days.\n\nWelcome aboard,\nTaskFlow Team`;
    const html = buildInvitationHtml({ inviterName: inviter, companyName: comp, workspaceName: ws, roleName: role, inviteUrl });
    return this.sendMessage(to, subject, plainText, { ...options, html, purpose: 'workspace_invitation' });
  }

  getLastMessage(to) {
    if (!to) return sentEmails[sentEmails.length - 1];
    return [...sentEmails].reverse().find((m) => m.to.toLowerCase() === to.toLowerCase());
  }

  clearHistory() {
    sentEmails.length = 0;
  }
}

function buildInvitationHtml({ inviterName, companyName, workspaceName, roleName, inviteUrl }) {
  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 36px 28px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
      <div style="text-align: center; margin-bottom: 24px;">
        <div style="display: inline-block; padding: 12px 20px; background: #4f46e5; border-radius: 14px; color: #ffffff; font-weight: 800; font-size: 20px; letter-spacing: -0.5px;">
          TaskFlow
        </div>
      </div>
      <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; margin: 0 0 12px 0; text-align: center; letter-spacing: -0.5px;">
        You've been invited to join ${workspaceName}
      </h2>
      <p style="font-size: 14px; color: #64748b; text-align: center; margin: 0 0 24px 0; line-height: 1.6;">
        <strong style="color: #0f172a;">${inviterName}</strong> has invited you to collaborate with the team at <strong style="color: #0f172a;">${companyName}</strong>.
      </p>

      <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 16px; padding: 20px; margin: 24px 0;">
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <tr>
            <td style="color: #64748b; padding: 6px 0;">Workspace</td>
            <td style="color: #0f172a; font-weight: 600; text-align: right; padding: 6px 0;">${workspaceName}</td>
          </tr>
          <tr>
            <td style="color: #64748b; padding: 6px 0;">Role Assigned</td>
            <td style="color: #4f46e5; font-weight: 700; text-align: right; padding: 6px 0;">${roleName}</td>
          </tr>
          <tr>
            <td style="color: #64748b; padding: 6px 0;">Invited By</td>
            <td style="color: #0f172a; font-weight: 600; text-align: right; padding: 6px 0;">${inviterName}</td>
          </tr>
        </table>
      </div>

      <div style="text-align: center; margin: 32px 0 24px 0;">
        <a href="${inviteUrl}" style="display: inline-block; background: #4f46e5; color: #ffffff; padding: 14px 32px; border-radius: 12px; font-weight: 700; text-decoration: none; font-size: 15px; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);">
          Accept Invitation &amp; Register &rarr;
        </a>
      </div>

      <div style="background: #f1f5f9; border-radius: 12px; padding: 14px; margin-top: 24px;">
        <p style="font-size: 12px; color: #475569; margin: 0; text-align: center; line-height: 1.5;">
          ⏱ <strong>Link expires in 7 days.</strong><br/>
          If the button above does not work, copy and paste this link into your browser:<br/>
          <span style="display: inline-block; word-break: break-all; color: #4f46e5; font-size: 11px; margin-top: 6px;">${inviteUrl}</span>
        </p>
      </div>

      <p style="font-size: 11px; color: #94a3b8; text-align: center; margin-top: 28px; margin-bottom: 0;">
        Secure Team Collaboration • TaskFlow Workspace
      </p>
    </div>
  `;
}

class SmtpEmailProvider {
  constructor() {
    this.transporter = null;
    this.initTransporter();
  }

  initTransporter() {
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '465', 10);
    const secure = process.env.SMTP_SECURE === 'true' || port === 465;
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

    if (host && user && pass) {
      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure,
        auth: { user, pass },
        tls: { rejectUnauthorized: false },
        connectionTimeout: 5000,
        greetingTimeout: 5000,
        socketTimeout: 5000
      });
    }
  }

  async sendOtp(to, otp, metadata = {}) {
    const record = {
      to,
      otp,
      type: 'otp',
      subject: metadata.purpose === 'password_reset' ? 'Your Password Reset Code' : 'Your Verification Code',
      body: `Your verification code is: ${otp}. It expires in 10 minutes.`,
      metadata,
      sentAt: new Date().toISOString()
    };
    sentEmails.push(record);
    console.log(`\n[EMAIL] >>> To: ${to} | Subject: "${record.subject}" | OTP: [${otp}]`);

    if (this.transporter && process.env.NODE_ENV !== 'test' && process.env.EMAIL_PROVIDER !== 'console') {
      try {
        const from = process.env.EMAIL_FROM || `"TaskFlow" <${process.env.SMTP_USER}>`;
        const isReset = metadata.purpose === 'password_reset';
        const title = isReset ? 'Reset Your Password' : 'Verify Your Email';
        const subtext = isReset
          ? 'We received a request to reset your password for your TaskFlow account. Enter this 6-digit verification code to choose a new password:'
          : 'Welcome to TaskFlow! Enter this 6-digit verification code to verify your email and complete your registration:';

        const html = `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 36px 28px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
            <div style="text-align: center; margin-bottom: 24px;">
              <div style="display: inline-block; padding: 12px 18px; background: #4f46e5; border-radius: 14px; color: #ffffff; font-weight: 800; font-size: 20px; letter-spacing: -0.5px;">
                TaskFlow
              </div>
            </div>
            <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; margin: 0 0 10px 0; text-align: center; letter-spacing: -0.5px;">${title}</h2>
            <p style="font-size: 14px; color: #64748b; text-align: center; margin: 0 0 28px 0; line-height: 1.6;">${subtext}</p>
            <div style="text-align: center; margin: 28px 0;">
              <span style="display: inline-block; font-size: 36px; font-weight: 800; letter-spacing: 10px; color: #4f46e5; background: #f8fafc; padding: 16px 32px; border-radius: 16px; border: 2px dashed #cbd5e1; user-select: all;">${otp}</span>
            </div>
            <div style="background: #f1f5f9; border-radius: 12px; padding: 14px; margin-top: 24px;">
              <p style="font-size: 12px; color: #475569; margin: 0; text-align: center; line-height: 1.5;">
                ⏱ <strong>Code expires in 10 minutes.</strong><br/>
                If you did not make this request, you can safely ignore this email.
              </p>
            </div>
            <p style="font-size: 11px; color: #94a3b8; text-align: center; margin-top: 28px; margin-bottom: 0;">
              Secure Authentication System • TaskFlow Workspace
            </p>
          </div>
        `;

        const sendPromise = this.transporter.sendMail({
          from,
          to,
          subject: record.subject,
          text: record.body,
          html
        });

        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('SMTP connection timed out after 10000ms')), 10000)
        );

        const info = await Promise.race([sendPromise, timeoutPromise]);
        return { success: true, messageId: info.messageId };
      } catch (err) {
        console.error(`[SMTP ERROR] Could not deliver email to ${to} via SMTP (${err.message}). Logged to console as fallback.`);
        return { success: true, messageId: `fallback-console-${Date.now()}` };
      }
    }

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
    console.log(`\n[EMAIL] >>> To: ${to} | Subject: "${subject}" | Content: ${body}`);

    if (this.transporter && process.env.NODE_ENV !== 'test' && process.env.EMAIL_PROVIDER !== 'console') {
      try {
        const from = process.env.EMAIL_FROM || `"TaskFlow" <${process.env.SMTP_USER}>`;
        const sendPromise = this.transporter.sendMail({
          from,
          to,
          subject,
          text: body,
          html: metadata.html || undefined
        });

        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error('SMTP connection timed out after 5000ms')), 5000)
        );

        const info = await Promise.race([sendPromise, timeoutPromise]);
        return { success: true, messageId: info.messageId };
      } catch (err) {
        console.error('[SMTP NOTICE] Could not deliver message via SMTP, logged to console:', err.message);
        return { success: true, messageId: `fallback-console-${Date.now()}` };
      }
    }
    return { success: true, messageId: `console-email-${Date.now()}` };
  }

  async sendInvitationEmail(to, options = {}) {
    const { inviterName, companyName, workspaceName, roleName, inviteUrl } = options;
    const comp = companyName || 'Our Workspace';
    const ws = workspaceName || comp;
    const inviter = inviterName || 'A team administrator';
    const role = roleName || 'Team Member';
    const subject = `You've been invited to join ${ws} on TaskFlow`;
    const plainText = `Hello,\n\n${inviter} has invited you to join ${ws} (${comp}) as a ${role}.\n\nAccept your invitation and activate your account using the link below:\n${inviteUrl}\n\nThis invitation link expires in 7 days.\n\nWelcome aboard,\nTaskFlow Team`;
    const html = buildInvitationHtml({ inviterName: inviter, companyName: comp, workspaceName: ws, roleName: role, inviteUrl });
    return this.sendMessage(to, subject, plainText, { ...options, html, purpose: 'workspace_invitation' });
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

const isSmtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER);
const emailProvider = isSmtpConfigured ? new SmtpEmailProvider() : new ConsoleEmailProvider();
const smsProvider = new ConsoleSmsProvider();

module.exports = {
  EmailProvider: emailProvider,
  SmsProvider: smsProvider,
  SmtpEmailProvider,
  ConsoleEmailProvider,
  ConsoleSmsProvider
};
