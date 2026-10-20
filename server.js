const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();
const { promisify } = require('util');
const scryptAsync = promisify(crypto.scrypt);
const { sendWaitlistEmail, sendVerificationEmail, sendAdminNotification, sendFeedbackNotification, setEmailTransport } = require('./emailService');

const app = express();
const PORT = process.env.PORT || 5500;

// Serve the site whether files live at the repo root OR inside a /public folder
app.use(express.static(path.join(__dirname)));
app.use(express.static(path.join(__dirname, 'public')));

// ---- Stay alive: one bad request must never take the whole server down ----
process.on('unhandledRejection', function (reason) {
    console.error('⚠️ Unhandled promise rejection (server kept alive):', reason && reason.message ? reason.message : reason);
});
process.on('uncaughtException', function (err) {
    console.error('⚠️ Uncaught exception (server kept alive):', err && err.message ? err.message : err);
});

// Initialize Gemini client with API key
let geminiClient = null;
let geminiInitError = null;
let genAI = null;                 // kept around so we can spin up a fallback model on demand
let geminiModelName = null;
try {
    const apiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
    // Default to a current, supported model. gemini-2.0-flash was retired — never fall back to it.
    const geminiModel = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    if (apiKey) {
        genAI = new GoogleGenerativeAI(apiKey);
        geminiModelName = geminiModel;
        geminiClient = genAI.getGenerativeModel({ model: geminiModel });
        console.log(`✅ Gemini client initialized with API key and model: ${geminiModel}`);
    } else {
        geminiInitError = 'Gemini API key not found. Add GOOGLE_API_KEY or GEMINI_API_KEY to your .env file.';
        console.warn('⚠️  Gemini API key not found. Add GOOGLE_API_KEY or GEMINI_API_KEY to your .env file.');
        console.warn('Get your API key from: https://makersuite.google.com/app/apikey');
    }
} catch (error) {
    geminiInitError = error.message || 'Failed to initialize Gemini client.';
    console.warn('⚠️  Failed to initialize Gemini client:', geminiInitError);
}

// Google "Continue with Google" sign-in
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
if (GOOGLE_CLIENT_ID) console.log('✅ Google sign-in configured');
else console.warn('⚠️  GOOGLE_CLIENT_ID not set — "Continue with Google" is disabled.');

// Middleware
app.use(cors());
app.use(express.json({ limit: '12mb' })); // room for Screenshot-to-Post image uploads (base64)

// ========== HELPERS ==========
function generateWaitlistCode() {
    return `SCRABL-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

// Hash a password with scrypt (built into Node, no extra packages)
async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = await scryptAsync(password, salt, 64);
    return `${salt}:${derived.toString('hex')}`;
}

// Verify a password against a stored salt:hash (used later at login)
async function verifyPassword(password, stored) {
    if (!stored || !stored.includes(':')) return false;
    const [salt, key] = stored.split(':');
    const derived = await scryptAsync(password, salt, 64);
    const keyBuf = Buffer.from(key, 'hex');
    return keyBuf.length === derived.length && crypto.timingSafeEqual(keyBuf, derived);
}

// ----- Session tokens (signed with crypto, no JWT library needed) -----
const AUTH_SECRET = process.env.AUTH_SECRET || 'scrabl-dev-secret-change-me';

function signToken(payload) {
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
    return `${body}.${sig}`;
}

function verifyToken(token) {
    if (!token || !token.includes('.')) return null;
    const [body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', AUTH_SECRET).update(body).digest('base64url');
    if (sig !== expected) return null;
    try {
        const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
        if (payload.exp && Date.now() > payload.exp) return null;
        return payload;
    } catch (e) { return null; }
}

// 6-digit email verification code
function generateVerifyCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

// ========== MONGODB CONNECTION ==========
const MONGO_URI = process.env.MONGO_URI;
if (MONGO_URI) {
    mongoose.connect(MONGO_URI, { dbName: 'scrabl' })
        .then(() => console.log('✅ MongoDB Atlas connected'))
        .catch(err => console.error('❌ MongoDB connection error:', err.message));
} else {
    console.warn('⚠️  MONGO_URI not set in .env — waitlist will NOT work');
}

// Waitlist Schema + Model
const waitlistSchema = new mongoose.Schema({
    name:        { type: String, default: '' },
    email:       { type: String, required: true, unique: true, lowercase: true, trim: true },
    waitlistCode: { type: String },
    verified:    { type: Boolean, default: false },
    source:      { type: String, default: 'waitlist-page' },
    createdAt:   { type: Date, default: Date.now },
    confirmedAt: { type: Date }
});
const WaitlistEntry = mongoose.model('WaitlistEntry', waitlistSchema);

// Feedback Schema + Model
const feedbackSchema = new mongoose.Schema({
    name:      { type: String, default: '' },
    email:     { type: String, required: true, lowercase: true, trim: true },
    category:  { type: String, default: 'other' },
    rating:    { type: Number, default: 0 },
    message:   { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Feedback = mongoose.model('Feedback', feedbackSchema);

// User Schema + Model (auth)
const userSchema = new mongoose.Schema({
    name:         { type: String, default: '' },
    email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, default: '' },         // empty for Google-only accounts
    googleId:     { type: String, default: '' },         // Google 'sub' id when they use Continue with Google
    authProvider: { type: String, default: 'email' },    // 'email' | 'google'
    verified:     { type: Boolean, default: false },
    verifyCode:        { type: String, default: '' },
    verifyCodeExpires: { type: Date },
    onboarded:    { type: Boolean, default: false },
    profile:      { type: Object, default: {} },
    voiceDNA:     { type: Object, default: null },
    voiceDNAUpdatedAt: { type: Date },
    createdAt:    { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// ========== EMAIL TRANSPORT (Gmail SMTP) ==========
let emailTransport = null;
let emailTransportReady = false;

const SMTP_EMAIL = process.env.SMTP_EMAIL;
const SMTP_PASSWORD = process.env.SMTP_PASSWORD;

if (SMTP_EMAIL && SMTP_PASSWORD) {
    emailTransport = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: SMTP_EMAIL, pass: SMTP_PASSWORD }
    });
} else {
    console.warn('⚠️  SMTP_EMAIL / SMTP_PASSWORD not set — emails will only log to console');
}

function sendEmailWithOTP(email, otp) {
    const rawMessage = {
        from: `"scrabl." <${SMTP_EMAIL || 'no-reply@scrabl.ai'}>`,
        to: email,
        subject: 'Your Scrabl verification code',
        text: `Your Scrabl verification code is ${otp}. It expires in 10 minutes.`,
        html: `<p>Your Scrabl verification code is <strong>${otp}</strong>.</p><p>It expires in 10 minutes.</p>`
    };

    if (emailTransportReady && emailTransport) {
        emailTransport.sendMail(rawMessage).catch(() => {});
    } else {
        console.log(`✉️  EMAIL SENT TO: ${email}`);
        console.log(`🔐 OTP CODE: ${otp}`);
        console.log(`⏱️  Valid for 10 minutes\n`);
    }
}

async function notifyWaitlistSignup(entry) {
    try {
        await sendWaitlistEmail(entry.email, entry.waitlistCode, entry.name);
        if (process.env.WAITLIST_NOTIFICATION_EMAIL) {
            await sendAdminNotification(entry);
        }
        return true;
    } catch (err) {
        console.warn('⚠️ Waitlist email failed:', err?.message || err);
        throw err;
    }
}

function normalizeSectionItems(value) {
    if (!value) return [];
    if (Array.isArray(value)) {
        return value.flatMap(item => {
            if (typeof item === 'string' || typeof item === 'number') {
                return String(item).trim();
            }
            if (item && typeof item === 'object') {
                if (typeof item.text === 'string') return item.text.trim();
                if (typeof item.signal === 'string') return item.signal.trim();
                if (typeof item.hook === 'string') return item.hook.trim();
                if (typeof item.description === 'string') return item.description.trim();
                if (typeof item.strategy === 'string') return item.strategy.trim();
                if (Array.isArray(item.hashtags)) return normalizeSectionItems(item.hashtags);
                return Object.values(item)
                    .filter(v => typeof v === 'string' || typeof v === 'number')
                    .map(String)
                    .map(str => str.trim())
                    .filter(Boolean);
            }
            return [];
        }).filter(Boolean);
    }
    if (typeof value === 'string') return value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
    return [];
}

async function extractGeminiRawText(result) {
    const response = result?.response;
    if (!response) return '';

    const candidate = response?.candidates?.[0];
    const content = candidate?.content;
    if (content) {
        if (Array.isArray(content.parts)) {
            return content.parts.map(part => String(part.text || '')).join('').trim();
        }
        if (typeof content.text === 'string') {
            return content.text.trim();
        }
    }

    if (typeof response.text === 'function') {
        try {
            const text = await response.text();
            return String(text || '').trim();
        } catch (e) {
            return '';
        }
    }

    if (typeof response === 'string') {
        return response.trim();
    }

    return '';
}

function parseGeminiResponse(raw) {
    const parsed = { hooks: [], description: [], strategy: [], hashtags: [] };
    if (!raw) return parsed;

    const cleaned = raw.replace(/[\u2028\u2029]/g, '').trim();
    const codeBlockMatch = cleaned.match(/```(?:json(?:\r?\n)?)?([\s\S]*?)```/i);
    const payload = codeBlockMatch ? codeBlockMatch[1].trim() : cleaned;

    try {
        const json = JSON.parse(payload);

        if (Array.isArray(json)) {
            json.forEach(item => {
                if (item.hook || item.signal) parsed.hooks.push(String(item.hook || item.signal).trim());
                if (item.description) parsed.description.push(String(item.description).trim());
                if (item.strategy) parsed.strategy.push(String(item.strategy).trim());
                if (item.hashtags) {
                    normalizeSectionItems(item.hashtags).forEach(tag => {
                        parsed.hashtags.push(tag.startsWith('#') ? tag : `#${tag.replace(/^#+/, '')}`);
                    });
                }
            });
            return parsed;
        }

        parsed.hooks = normalizeSectionItems(json.hooks || json.signals);
        parsed.description = normalizeSectionItems(json.description || json.descriptions);
        parsed.strategy = normalizeSectionItems(json.strategy || json.strategies);
        parsed.hashtags = normalizeSectionItems(json.hashtags).map(tag => tag.startsWith('#') ? tag : `#${tag.replace(/^#+/, '')}`);
        return parsed;
    } catch (err) {
        let section = null;
        const lines = cleaned.split(/\r?\n/).map(line => line.trim()).filter(Boolean);

        lines.forEach((line) => {
            const lower = line.toLowerCase();
            if (/^\[?hooks?\]?[:\-]?/.test(lower) || /^\[?signals?\]?[:\-]?/.test(lower)) {
                section = 'hooks';
                return;
            }
            if (/^\[?description[s]?\]?[:\-]?/.test(lower)) {
                section = 'description';
                return;
            }
            if (/^\[?strategy\]?[:\-]?/.test(lower)) {
                section = 'strategy';
                return;
            }
            if (/^\[?hashtags?\]?[:\-]?/.test(lower)) {
                section = 'hashtags';
                return;
            }

            if (section === 'hashtags') {
                normalizeSectionItems(line).forEach(tag => {
                    parsed.hashtags.push(tag.startsWith('#') ? tag : `#${tag.replace(/^#+/, '')}`);
                });
            } else if (section) {
                parsed[section].push(line.replace(/^[\-•\d\.\)\s]+/, '').trim());
            }
        });

        parsed.hashtags = parsed.hashtags.slice(0, 7);
        return parsed;
    }
}

// ========== GEMINI PROXY ENDPOINT ==========
app.post('/api/gemini/generate', async (req, res) => {
    if (!geminiClient) {
        const message = geminiInitError || 'Gemini client not initialized. Check GOOGLE_API_KEY in .env.';
        return res.status(500).json({ error: message });
    }

    const { directionText = '', ocrText = '', selectedVibe = '', voicePreview = '', systemPrompt = '', userPrompt = '' } = req.body;
    const payloadPrompt = systemPrompt || `You are the Scrabl Lagos Gold intelligence engine. Create premium, minimalist, authoritative copy for elite creators. Use an elevated tone, concise structure, and present content in a sharp, confident voice.`;
    const prompt = `${payloadPrompt}\n\n${userPrompt}`;

    try {
        const result = await geminiClient.generateContent(prompt);
        let rawText = await extractGeminiRawText(result);

        if (!rawText) {
            rawText = result?.response?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('').trim() || '';
        }

        const sections = parseGeminiResponse(rawText);

        if (!sections.hooks.length && !sections.description.length && !sections.hashtags.length) {
            return res.status(500).json({ error: 'Gemini returned no structured content.', rawText });
        }

        return res.json({ sections, rawText });
    } catch (error) {
        console.error('Gemini proxy error:', error);

        // Handle rate limits and invalid API key states
        const errMsg = error.message || '';
        if (errMsg.toLowerCase().includes('expired') || errMsg.toLowerCase().includes('invalid')) {
            return res.status(401).json({ error: 'Gemini API key expired or invalid. Renew the key in your .env and restart the backend.' });
        }
        if (error.status === 429 || errMsg.toLowerCase().includes('rate limit')) {
            return res.status(429).json({ error: 'Rate limit exceeded. Please try again later.' });
        }

        return res.status(500).json({ error: errMsg || 'Gemini proxy failure' });
    }
});

// ========== SIMPLE LOCAL STUB GENERATE ENDPOINT ==========
// This lightweight endpoint allows frontend testing without Gemini.
// ========== WAITLIST SIGNUP ENDPOINT ==========
app.post('/api/waitlist', async (req, res) => {
    const email = (req.body?.email || '').trim().toLowerCase();
    const name = (req.body?.name || '').trim();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    try {
        const existing = await WaitlistEntry.findOne({ email });

        if (existing && existing.verified) {
            return res.status(409).json({ error: "You're already on the waitlist! We'll be in touch soon." });
        }

        const waitlistCode = generateWaitlistCode();

        if (existing) {
            // Resend code to unverified user
            existing.waitlistCode = waitlistCode;
            existing.name = name || existing.name;
            await existing.save();
        } else {
            await WaitlistEntry.create({ email, name, waitlistCode, source: req.body?.source || 'waitlist-page' });
        }

        console.log(`✉️ Waitlist signup: ${email} | Code: ${waitlistCode}`);

        // Send email (don't block response if email fails in dev)
        try {
            await notifyWaitlistSignup({ email, waitlistCode, name, createdAt: new Date().toISOString() });
        } catch (emailErr) {
            console.warn('⚠️ Email send failed but signup saved:', emailErr?.message);
            // In dev mode without SMTP, the code is logged to console
        }

        return res.json({ message: 'Verification code sent! Check your email.', email });
    } catch (err) {
        console.error('Waitlist signup error:', err);
        if (err.code === 11000) {
            return res.status(409).json({ error: 'This email is already registered.' });
        }
        return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});

// ========== FEEDBACK ENDPOINT ==========
app.post('/api/feedback', async (req, res) => {
    const name = (req.body?.name || '').trim();
    const email = (req.body?.email || '').trim().toLowerCase();
    const category = (req.body?.category || 'other').trim();
    const rating = Number(req.body?.rating) || 0;
    const message = (req.body?.message || '').trim();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (!message) {
        return res.status(400).json({ error: 'Please enter a message.' });
    }

    try {
        // 1. SAVE to MongoDB
        await Feedback.create({ name, email, category, rating, message });
        console.log(`\ud83d\udcac New feedback from ${email} | ${category} | ${rating} star`);

        // 2. EMAIL you (don't block the response if email fails)
        try {
            await sendFeedbackNotification({ name, email, category, rating, message, createdAt: new Date().toISOString() });
        } catch (emailErr) {
            console.warn('\u26a0\ufe0f Feedback email failed but feedback saved:', emailErr?.message);
        }

        return res.status(200).json({ success: true, message: 'Feedback received!' });
    } catch (err) {
        console.error('Feedback error:', err);
        return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});

// ========== FEEDBACK ADMIN: read all feedback (password protected) ==========
app.get('/api/feedback/all', async (req, res) => {
    const key = req.query.key || req.headers['x-admin-key'];
    const ADMIN_KEY = process.env.FEEDBACK_ADMIN_KEY || 'change-me-now';
    if (key !== ADMIN_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const all = await Feedback.find().sort({ createdAt: -1 }).limit(500).lean();
        return res.status(200).json({ count: 
