require('dotenv').config();

/*
 * Scrabl email service — sends via Resend's HTTP API (works on Render,
 * which blocks outbound SMTP). Uses env vars:
 *   RESEND_API_KEY              your Resend API key
 *   FROM_EMAIL                  e.g.  Scrabl <noreply@scrabl.com>
 *   WAITLIST_NOTIFICATION_EMAIL where admin notices go (your inbox)
 */

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const ADMIN_EMAIL = process.env.WAITLIST_NOTIFICATION_EMAIL || process.env.SMTP_EMAIL;

// Format the "from" field so Resend always accepts it
function normalizeFrom(raw) {
    if (!raw) return 'Scrabl <onboarding@resend.dev>';
    if (raw.includes('<')) return raw;                       // already "Name <email>"
    const m = raw.match(/^(.*?)\s*([^\s]+@[^\s]+)$/);
    if (m && m[1]) return `${m[1].trim()} <${m[2]}>`;        // "Name email" -> "Name <email>"
    if (m) return m[2];                                       // bare email
    return raw;
}
const FROM_EMAIL = normalizeFrom(process.env.FROM_EMAIL);

// Kept only so server.js's setEmailTransport(...) call doesn't break.
// Resend sending does NOT use this.
let emailTransport = null;
function setEmailTransport(transport) { emailTransport = transport; }

// Core sender — one place that talks to Resend
async function sendViaResend({ to, subject, html, text }) {
    if (!RESEND_API_KEY) {
        console.warn(`⚠️  RESEND_API_KEY not set — email NOT sent: "${subject}"`);
        return null;
    }
    try {
        const res = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${RESEND_API_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ from: FROM_EMAIL, to, subject, html, text })
        });

        if (!res.ok) {
            const errText = await res.text();
            throw new Error(`Resend API ${res.status}: ${errText}`);
        }
        const data = await res.json();
        console.log(`✅ Email sent via Resend (${data.id || 'ok'}) → ${to}`);
        return data;
    } catch (err) {
        console.warn(`⚠️ Resend send failed for "${subject}":`, err.message);
        throw err;
    }
}

// ---------- 1. Waitlist verification code (to the new signup) ----------
async function sendWaitlistEmail(email, waitlistCode, name = 'Creator') {
    const displayName = name || 'Creator';
    const htmlBody = `
<div style="font-family: 'Helvetica Neue', Arial, sans-serif; max-width: 520px; margin: 0 auto; background: #0a0a0a; color: #f5f5f5; border-radius: 16px; overflow: hidden; border: 1px solid #1a1a1a;">
    <div style="padding: 40px 30px 20px; text-align: center;">
        <h1 style="color: #D4AF37; font-size: 32px; margin: 0 0 6px; font-weight: 800;">scrabl.</h1>
        <p style="color: #666; font-size: 12px; letter-spacing: 4px; text-transform: uppercase; margin: 0;">Craft Influence</p>
    </div>
    <div style="padding: 10px 30px 40px; text-align: center;">
        <p style="font-size: 16px; color: #ccc; margin-bottom: 28px;">Hello <strong>${displayName}</strong>, your spot has been secured.</p>
        <p style="font-size: 13px; color: #888; margin-bottom: 12px; letter-spacing: 2px; text-transform: uppercase;">Your Verification Code</p>
        <div style="background: #111; border: 2px solid #D4AF37; border-radius: 14px; padding: 24px; margin-bottom: 28px;">
            <span style="font-size: 38px; font-weight: bold; letter-spacing: 6px; color: #D4AF37; font-family: monospace;">${waitlistCode}</span>
        </div>
        <p style="font-size: 14px; color: #888; margin-bottom: 30px;">Enter this code on the waitlist page to confirm your spot.</p>
        <div style="border-top: 1px solid #222; padding-top: 24px;">
            <p style="font-size: 14px; color: #999; line-height: 1.7;">Scrabl is currently in development. You'll receive updates as new features become available and as we get closer to launch.</p>
        </div>
        <div style="margin-top: 30px;">
            <p style="color: #D4AF37; font-size: 13px; font-weight: 600; letter-spacing: 2px;">#scrabl26</p>
            <p style="color: #555; font-size: 12px; margin-top: 8px;">The Scrabl Team &mdash; <em>We Scrabl Out Stress.</em></p>
        </div>
    </div>
    <div style="background: #050505; padding: 16px 30px; text-align: center;">
        <p style="font-size: 11px; color: #444; margin: 0;">&copy; 2026 Scrabl Media Corp. &bull; You received this because you joined the Scrabl waitlist.</p>
    </div>
</div>`;

    return sendViaResend({
        to: email,
        subject: 'Your Scrabl Verification Code',
        text: `Hello ${displayName},\n\nYour Scrabl verification code: ${waitlistCode}\n\nEnter this code on the waitlist page to confirm your spot.\n\n#scrabl26 — The Scrabl Team`,
        html: htmlBody
    });
}

// ---------- 2. Admin notice: new waitlist signup (to you) ----------
async function sendAdminNotification(entry) {
    if (!ADMIN_EMAIL) return null;
    return sendViaResend({
        to: ADMIN_EMAIL,
        subject: `New Scrabl waitlist signup: ${entry.email}`,
        text: `New waitlist signup:\nEmail: ${entry.email}\nName: ${entry.name || 'N/A'}\nJoined: ${entry.createdAt}`,
        html: `<p><strong>New waitlist signup:</strong></p>
<ul>
    <li><strong>Email:</strong> ${entry.email}</li>
    <li><strong>Name:</strong> ${entry.name || 'N/A'}</li>
    <li><strong>Joined:</strong> ${entry.createdAt}</li>
</ul>`
    });
}

// ---------- 3. Admin notice: new feedback (to you) ----------
async function sendFeedbackNotification(feedback) {
    if (!ADMIN_EMAIL) return null;
    const r = Number(feedback.rating) || 0;
    const stars = r ? '★'.repeat(r) + '☆'.repeat(5 - r) : 'No rating';
    return sendViaResend({
        to: ADMIN_EMAIL,
        subject: `New Scrabl feedback (${feedback.category}) from ${feedback.email}`,
        text: `New feedback:\nName: ${feedback.name || 'N/A'}\nEmail: ${feedback.email}\nCategory: ${feedback.category}\nRating: ${stars}\nMessage: ${feedback.message}\nSent: ${feedback.createdAt}`,
        html: `<div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; background: #0a0a0a; color: #f5f5f5; border-radius: 14px; padding: 32px; border: 1px solid #1a1a1a;">
    <h2 style="color: #D4AF37; margin: 0 0 20px;">New Feedback Received</h2>
    <p style="margin: 8px 0;"><strong style="color:#888;">Name:</strong> ${feedback.name || 'N/A'}</p>
    <p style="margin: 8px 0;"><strong style="color:#888;">Email:</strong> ${feedback.email}</p>
    <p style="margin: 8px 0;"><strong style="color:#888;">Category:</strong> ${feedback.category}</p>
    <p style="margin: 8px 0;"><strong style="color:#888;">Rating:</strong> <span style="color:#D4AF37;">${stars}</span></p>
    <p style="margin: 16px 0 8px;"><strong style="color:#888;">Message:</strong></p>
    <p style="background:#111; border-left: 3px solid #D4AF37; padding: 14px 16px; border-radius: 8px; line-height: 1.6; margin: 0;">${feedback.message}</p>
    <p style="color:#555; font-size: 12px; margin-top: 20px;">Sent: ${feedback.createdAt}</p>
</div>`
    });
}

async function sendVerificationEmail(email, code, name = 'Creator') {
    const displayName = name || 'Creator';
    const htmlBody = `
<div style="font-family: 'Helvetica Neue', Arial, sans-serif; max-width: 520px; margin: 0 auto; background: #0a0a0a; color: #f5f5f5; border-radius: 16px; overflow: hidden; border: 1px solid #1a1a1a;">
    <div style="padding: 40px 30px 20px; text-align: center;">
        <h1 style="color: #D4AF37; font-size: 32px; margin: 0 0 6px; font-weight: 800;">scrabl.</h1>
        <p style="color: #666; font-size: 12px; letter-spacing: 4px; text-transform: uppercase; margin: 0;">Craft Influence</p>
    </div>
    <div style="padding: 10px 30px 40px; text-align: center;">
        <p style="font-size: 16px; color: #ccc; margin-bottom: 28px;">Hi <strong>${displayName}</strong>, welcome to Scrabl. Confirm your email to continue.</p>
        <p style="font-size: 13px; color: #888; margin-bottom: 12px; letter-spacing: 2px; text-transform: uppercase;">Your Verification Code</p>
        <div style="background: #111; border: 2px solid #D4AF37; border-radius: 14px; padding: 24px; margin-bottom: 28px;">
            <span style="font-size: 40px; font-weight: bold; letter-spacing: 8px; color: #D4AF37; font-family: monospace;">${code}</span>
        </div>
        <p style="font-size: 14px; color: #888; margin-bottom: 20px;">Enter this code to verify your account. It expires in 15 minutes.</p>
        <p style="font-size: 13px; color: #666;">If you didn't create a Scrabl account, you can ignore this email.</p>
        <div style="margin-top: 30px;">
            <p style="color: #D4AF37; font-size: 13px; font-weight: 600; letter-spacing: 2px;">#scrabl26</p>
        </div>
    </div>
</div>`;
    return sendViaResend({
        to: email,
        subject: `${code} is your Scrabl verification code`,
        text: `Hi ${displayName}, your Scrabl verification code is ${code}. It expires in 15 minutes.`,
        html: htmlBody
    });
}

module.exports = { sendWaitlistEmail, sendVerificationEmail, sendAdminNotification, sendFeedbackNotification, setEmailTransport };
