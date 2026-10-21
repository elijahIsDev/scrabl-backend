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
    avatar:       { type: String, default: '' },         // small data-URL profile picture (resized client-side)
    recent:       { type: Array, default: [] },          // last few generations {input, results, ts, mode} — survives device/browser
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
        return res.status(200).json({ count: all.length, feedback: all });
    } catch (err) {
        console.error('Feedback fetch error:', err);
        return res.status(500).json({ error: 'Could not load feedback.' });
    }
});

// ========== WAITLIST CODE VERIFICATION ==========
app.post('/api/waitlist/verify', async (req, res) => {
    const email = (req.body?.email || '').trim().toLowerCase();
    const code = (req.body?.code || '').trim();

    if (!email || !code) {
        return res.status(400).json({ error: 'Email and code are required.' });
    }

    try {
        const entry = await WaitlistEntry.findOne({ email });

        if (!entry) {
            return res.status(404).json({ error: 'No signup found for this email. Please sign up first.' });
        }

        if (entry.verified) {
            return res.status(200).json({ message: "Already verified — you're on the list!" });
        }

        if (entry.waitlistCode !== code) {
            return res.status(400).json({ error: 'Wrong code. Please check your email and try again.' });
        }

        entry.verified = true;
        entry.confirmedAt = new Date();
        entry.waitlistCode = undefined;
        await entry.save();

        console.log(`🎉 Waitlist verified: ${email}`);
        return res.json({ message: "You're in! Welcome to the Scrabl waitlist." });
    } catch (err) {
        console.error('Waitlist verify error:', err);
        return res.status(500).json({ error: 'Verification failed. Please try again.' });
    }
});

// ========== AUTH: SIGNUP ==========
app.post('/api/auth/signup', async (req, res) => {
    try {
        const name = (req.body?.name || '').trim();
        const email = (req.body?.email || '').trim().toLowerCase();
        const password = req.body?.password || '';

        // Validate
        if (!name) return res.status(400).json({ error: 'Please enter your name.' });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Please enter a valid email address.' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters.' });
        }

        // Already registered?
        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }

        // Hash + create account (unverified) with a fresh 6-digit code
        const passwordHash = await hashPassword(password);
        const code = generateVerifyCode();
        const user = await User.create({
            name, email, passwordHash,
            verified: false,
            verifyCode: code,
            verifyCodeExpires: new Date(Date.now() + 15 * 60 * 1000)  // 15 min
        });
        console.log(`\ud83d\udc64 New account created (unverified): ${email}`);

        // Email the code (don't fail signup if email hiccups)
        try { await sendVerificationEmail(email, code, name); }
        catch (e) { console.warn('\u26a0\ufe0f Verification email failed to send:', e.message); }

        // Auto-login: issue a token so they flow straight into verify -> onboarding
        const token = signToken({
            id: user._id.toString(),
            email: user.email,
            exp: Date.now() + 7 * 24 * 60 * 60 * 1000
        });

        return res.status(201).json({
            success: true,
            token,
            verified: false,
            onboarded: false,
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (err) {
        if (err && err.code === 11000) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }
        console.error('Signup error:', err);
        return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});

// ========== AUTH: LOGIN ==========
app.post('/api/auth/login', async (req, res) => {
    try {
        const email = (req.body?.email || '').trim().toLowerCase();
        const password = req.body?.password || '';

        if (!email || !password) {
            return res.status(400).json({ error: 'Enter your email and password.' });
        }

        const user = await User.findOne({ email });
        // Same message whether email is unknown or password is wrong (don't leak which emails exist)
        if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });

        const valid = await verifyPassword(password, user.passwordHash);
        if (!valid) return res.status(401).json({ error: 'Incorrect email or password.' });

        const token = signToken({
            id: user._id.toString(),
            email: user.email,
            exp: Date.now() + 7 * 24 * 60 * 60 * 1000  // 7 days
        });
        console.log(`\ud83d\udd11 Login: ${email}`);

        return res.status(200).json({
            success: true,
            token,
            verified: user.verified,
            onboarded: user.onboarded,
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});

// ========== AUTH: CONTINUE WITH GOOGLE ==========
app.post('/api/auth/google', async (req, res) => {
    try {
        if (!googleClient) return res.status(503).json({ error: 'Google sign-in is not set up yet.' });
        const credential = req.body?.credential || '';
        if (!credential) return res.status(400).json({ error: 'Missing Google credential.' });

        let payload;
        try {
            const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
            payload = ticket.getPayload();
        } catch (e) {
            console.warn('Google token verify failed:', e.message);
            return res.status(401).json({ error: 'Google sign-in failed. Please try again.' });
        }

        const email = (payload.email || '').toLowerCase();
        if (!email || payload.email_verified === false) {
            return res.status(401).json({ error: 'Could not verify your Google email.' });
        }
        const name = payload.name || email.split('@')[0];

        let user = await User.findOne({ email });
        if (!user) {
            // Brand-new account via Google — already email-verified by Google
            user = await User.create({
                name, email,
                passwordHash: '',
                googleId: payload.sub || '',
                authProvider: 'google',
                verified: true,
                onboarded: false
            });
            console.log('🆕 Google signup: ' + email);
        } else {
            // Existing account — link Google to it and mark verified
            let changed = false;
            if (!user.googleId && payload.sub) { user.googleId = payload.sub; changed = true; }
            if (!user.verified) { user.verified = true; changed = true; }
            if (changed) await user.save();
            console.log('🔑 Google login: ' + email);
        }

        const token = signToken({
            id: user._id.toString(),
            email: user.email,
            exp: Date.now() + 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            success: true,
            token,
            verified: true,
            onboarded: !!user.onboarded,
            user: { id: user._id, name: user.name, email: user.email }
        });
    } catch (err) {
        console.error('Google auth error:', err);
        return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});

// Public config the frontend needs (e.g. the Google client id for the sign-in button)
app.get('/api/config', (req, res) => {
    res.json({ googleClientId: GOOGLE_CLIENT_ID || '' });
});

// ========== AUTH: VERIFY EMAIL ==========
app.post('/api/auth/verify-email', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please sign up or log in again.' });

        const code = (req.body?.code || '').trim();
        if (!code) return res.status(400).json({ error: 'Enter the 6-digit code.' });

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });
        if (user.verified) return res.status(200).json({ success: true, alreadyVerified: true, onboarded: user.onboarded });

        if (!user.verifyCode || user.verifyCode !== code) {
            return res.status(400).json({ error: 'That code is incorrect.' });
        }
        if (!user.verifyCodeExpires || Date.now() > new Date(user.verifyCodeExpires).getTime()) {
            return res.status(400).json({ error: 'That code has expired. Request a new one.' });
        }

        user.verified = true;
        user.verifyCode = '';
        user.verifyCodeExpires = undefined;
        await user.save();
        console.log(`\u2705 Email verified: ${user.email}`);

        return res.status(200).json({ success: true, verified: true, onboarded: user.onboarded });
    } catch (err) {
        console.error('Verify email error:', err);
        return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});

// ========== AUTH: RESEND VERIFICATION CODE ==========
app.post('/api/auth/resend-code', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please sign up or log in again.' });

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });
        if (user.verified) return res.status(200).json({ success: true, alreadyVerified: true });

        const code = generateVerifyCode();
        user.verifyCode = code;
        user.verifyCodeExpires = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();

        try { await sendVerificationEmail(user.email, code, user.name); }
        catch (e) { console.warn('\u26a0\ufe0f Resend verification email failed:', e.message); }
        console.log(`\ud83d\udd01 Resent verification code: ${user.email}`);

        return res.status(200).json({ success: true });
    } catch (err) {
        console.error('Resend code error:', err);
        return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
});

// ========== AUTH: CURRENT USER (verifies token) ==========
app.get('/api/auth/me', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.query.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Not authenticated.' });

        const user = await User.findById(payload.id).lean();
        if (!user) return res.status(401).json({ error: 'Account not found.' });

        return res.status(200).json({ verified: user.verified, onboarded: user.onboarded, user: { id: user._id, name: user.name, email: user.email } });
    } catch (err) {
        console.error('Auth check error:', err);
        return res.status(500).json({ error: 'Something went wrong.' });
    }
});

// ========== ONBOARDING: save profile + analyze voice + mark onboarded ==========
app.post('/api/onboarding', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please log in again.' });

        const profile = req.body?.profile || {};

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });

        // Save the profile first, so their samples are stored even if analysis needs a retry
        user.profile = profile;
        await user.save();

        // Analyze their voice — onboarding only completes if this succeeds
        let voiceDNA;
        try {
            voiceDNA = await analyzeVoiceDNA(profile);
        } catch (analysisErr) {
            console.warn('\u26a0\ufe0f Onboarding voice analysis failed:', analysisErr.message);
            const msg = analysisErr.message === 'NOT_ENOUGH_SAMPLES'
                ? 'Please add at least a couple of writing samples so we can learn your voice.'
                : 'We could not set up your voice just now. Please try again.';
            return res.status(502).json({ error: msg, onboarded: false });
        }

        user.voiceDNA = voiceDNA;
        user.voiceDNAUpdatedAt = new Date();
        user.onboarded = true;
        await user.save();
        console.log(`\ud83c\udf1f Onboarding + Voice DNA completed: ${user.email}`);

        return res.status(200).json({ success: true, onboarded: true, voiceDNA });
    } catch (err) {
        console.error('Onboarding error:', err);
        return res.status(500).json({ error: 'Could not save your setup. Please try again.' });
    }
});

// Return the logged-in user's account data (profile + voice DNA) so the app can
// load their voice on ANY device, not just the browser where they onboarded.
app.get('/api/me', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.query?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please log in again.' });

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });

        return res.status(200).json({
            success: true,
            email: user.email,
            name: user.name || '',
            avatar: user.avatar || '',
            recent: Array.isArray(user.recent) ? user.recent : [],
            onboarded: !!user.onboarded,
            profile: user.profile || {},
            voiceDNA: user.voiceDNA || null,
            voiceDNAUpdatedAt: user.voiceDNAUpdatedAt || null
        });
    } catch (err) {
        console.error('Me error:', err);
        return res.status(500).json({ error: 'Could not load your account.' });
    }
});

// Let a user set/correct their display name (e.g. when Google gave an odd one)
app.post('/api/me/name', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please log in again.' });

        const newName = (req.body?.name || '').trim();
        if (!newName) return res.status(400).json({ error: 'Enter a name.' });
        if (newName.length > 60) return res.status(400).json({ error: 'That name is too long.' });

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });
        user.name = newName;
        await user.save();
        console.log('✏️ Name updated: ' + user.email + ' -> ' + newName);
        return res.status(200).json({ success: true, name: user.name });
    } catch (err) {
        console.error('Name update error:', err);
        return res.status(500).json({ error: 'Could not save your name.' });
    }
});

// Let a user set or remove their profile picture (resized to a small data URL client-side)
app.post('/api/me/avatar', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please log in again.' });

        var avatar = (req.body && typeof req.body.avatar === 'string') ? req.body.avatar.trim() : '';
        if (avatar) {
            // Accept only small inline image data URLs; reject anything else (no remote URLs).
            if (!/^data:image\/(png|jpeg|jpg|webp);base64,/.test(avatar)) {
                return res.status(400).json({ error: 'That image format is not supported.' });
            }
            if (avatar.length > 1500000) { // ~1.1MB decoded — client resizes well below this
                return res.status(413).json({ error: 'That image is too large. Try a smaller photo.' });
            }
        }

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });
        user.avatar = avatar; // empty string removes it
        await user.save();
        console.log('🖼️ Avatar ' + (avatar ? 'updated' : 'removed') + ': ' + user.email);
        return res.status(200).json({ success: true, avatar: user.avatar });
    } catch (err) {
        console.error('Avatar update error:', err);
        return res.status(500).json({ error: 'Could not save your photo.' });
    }
});

// ========== VOICE DNA: analyze samples into a stored voice profile ==========

// Build the analysis prompt from a creator's samples + light context
function buildVoiceAnalysisPrompt(samples, context) {
    const ctx = context || {};
    const niche = Array.isArray(ctx.niche) ? ctx.niche.join(', ') : (ctx.niche || 'unspecified');
    const platforms = ctx.platforms ? Object.keys(ctx.platforms).join(', ') : 'unspecified';
    const numbered = (samples || []).map((s, i) => `SAMPLE ${i + 1}:\n${s}`).join('\n\n');

    return [
        'You are an expert linguistic analyst for African (especially Nigerian) content creators.',
        'Below are real sample posts written by ONE creator. Study HOW they write — not what they write about.',
        `Their niche: ${niche}. They post on: ${platforms}.`,
        '',
        'Return ONLY a valid JSON object (no markdown, no backticks, no commentary) with EXACTLY these keys:',
        '{',
        '  "voiceSummary": "2-3 sentences in plain English describing how this person writes, as if briefing a ghostwriter",',
        '  "tone": ["up to 4 adjectives"],',
        '  "formality": "very informal | informal | neutral | formal",',
        '  "sentenceStyle": "short description of sentence length and rhythm",',
        '  "capitalization": "how they use capitals (e.g. lowercase-heavy, standard)",',
        '  "emojiUsage": "how often and which emojis, or none",',
        '  "signaturePhrases": ["words/phrases/slang they actually use"],',
        '  "slangLevel": "none | light | moderate | heavy (note if Nigerian/Pidgin)",',
        '  "do": ["3-5 concrete instructions to sound like them"],',
        '  "dont": ["3-5 things to avoid so it does not sound generic/AI"]',
        '}',
        '',
        'Base every field ONLY on evidence in the samples. If samples are too thin for a field, make your best reasonable inference.',
        '',
        'THE CREATORS SAMPLES:',
        numbered
    ].join('\n');
}

// Pull a JSON object out of Gemini's raw text (handles ```json fences etc.)
function parseVoiceJSON(raw) {
    if (!raw) return null;
    let text = String(raw).trim();
    text = text.replace(/```json/gi, '').replace(/```/g, '').trim();
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start === -1 || end === -1 || end <= start) return null;
    try { return JSON.parse(text.slice(start, end + 1)); }
    catch (e) { return null; }
}

// Shared: analyze a profile's samples into a voiceDNA object (throws on failure)
async function analyzeVoiceDNA(profile) {
    if (!geminiClient) throw new Error(geminiInitError || 'Gemini not initialized.');
    const samples = Array.isArray(profile?.voiceSamples) ? profile.voiceSamples.filter(Boolean) : [];
    if (samples.length < 2) throw new Error('NOT_ENOUGH_SAMPLES');
    const prompt = buildVoiceAnalysisPrompt(samples, profile);
    const result = await geminiClient.generateContent(prompt);
    const rawText = await extractGeminiRawText(result);
    const voiceDNA = parseVoiceJSON(rawText);
    if (!voiceDNA || !voiceDNA.voiceSummary) {
        const e = new Error('PARSE_FAILED');
        e.rawText = rawText;
        throw e;
    }
    return voiceDNA;
}

// Standalone route: (re)analyze the logged-in user's voice on demand
app.post('/api/voice/analyze', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please log in again.' });

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });

        let voiceDNA;
        try {
            voiceDNA = await analyzeVoiceDNA(user.profile || {});
        } catch (e) {
            if (e.message === 'NOT_ENOUGH_SAMPLES') return res.status(400).json({ error: 'Not enough voice samples to analyze.' });
            if (e.message === 'PARSE_FAILED') return res.status(502).json({ error: 'Could not read a voice profile from the model.' });
            throw e;
        }

        user.voiceDNA = voiceDNA;
        user.voiceDNAUpdatedAt = new Date();
        await user.save();
        console.log(`\ud83e\uddec Voice DNA analyzed for: ${user.email}`);
        return res.status(200).json({ success: true, voiceDNA });
    } catch (err) {
        console.error('Voice analyze error:', err);
        return res.status(500).json({ error: 'Voice analysis failed. Please try again.' });
    }
});

// ========== GENERATION: full package (post + hook + hashtags) per platform ==========
const PLATFORM_RULES = {
    "X / Twitter": "Punchy and conversational. Lead with a strong hook. Keep the post under 280 characters. A natural, fragmented rhythm works well. Use 0-2 hashtags max, only if they fit naturally.",
    "Instagram": "A storytelling caption with natural line breaks and real personality. Emotive and relatable. End with a question or CTA that drives comments. Provide 5-10 relevant hashtags.",
    "TikTok": "A short, hook-forward caption written to sit under a video. Trend-aware and casual. Provide 3-5 hashtags mixing niche and broad discovery tags.",
    "LinkedIn": "Professional but genuinely human. A real insight or short story, no corporate cringe, no buzzwords. Short paragraphs. Provide up to 3 hashtags.",
    "YouTube": "The post should be a compelling video TITLE, then a short description on the following lines. Provide 3-5 hashtags.",
    "Facebook": "Warm, conversational, community feel. Slightly longer is fine. Provide 0-3 hashtags.",
    "Threads": "Casual and conversational, like a relaxed X post. Minimal or no hashtags."
};

function buildGenerationPrompt(input, platforms, user, mode) {
    const dna = user.voiceDNA || null;
    const profile = user.profile || {};
    const niche = Array.isArray(profile.niche) ? profile.niche.join(', ') : (profile.niche || 'general');
    const isScreenshot = mode === 'screenshot';

    let voiceBlock;
    if (dna) {
        const parts = [];
        parts.push(`- How they write: ${dna.voiceSummary || ''}`);
        if (dna.tone) parts.push(`- Tone: ${Array.isArray(dna.tone) ? dna.tone.join(', ') : dna.tone}`);
        if (dna.capitalization) parts.push(`- Capitalization: ${dna.capitalization}`);
        if (dna.emojiUsage) parts.push(`- Emoji use: ${dna.emojiUsage}`);
        if (dna.signaturePhrases && dna.signaturePhrases.length) parts.push(`- Signature phrases: ${dna.signaturePhrases.join(', ')}`);
        if (dna.do && dna.do.length) parts.push(`- DO: ${dna.do.join('; ')}`);
        if (dna.dont && dna.dont.length) parts.push(`- DO NOT: ${dna.dont.join('; ')}`);
        voiceBlock = `THE CREATOR'S VOICE SAMPLE — your MASTER reference for HOW they sound (tone, formality, vocabulary, rhythm, emoji habits, personality). Shape the post to sound like them:\n${parts.join('\n')}\nIMPORTANT: this shapes their ENGLISH only. It does NOT license Pidgin, dialect or slang unless the creator's CURRENT input below is itself written that way. If any phrase above is Pidgin/dialect, express that same energy in clean English instead — unless THIS input uses Pidgin.`;
    } else {
        voiceBlock = `This creator has not set up a voice profile yet, so write in clean, natural, everyday English — simple, human, and neutral. Do NOT default to Pidgin or heavy slang; only mirror the exact style the creator's own input shows.`;
    }

    const platformInstructions = platforms.map(function (p) {
        const rule = PLATFORM_RULES[p] || 'Write a natural post optimized for this platform.';
        return `PLATFORM "${p}": ${rule}`;
    }).join('\n');

    return `You are Scrabl — a ghostwriter for ONE specific creator. You take a raw thought from the creator and turn it into content they could post RIGHT NOW, written exactly as if they wrote it themselves.

${voiceBlock}

The creator's niche: ${niche}.

========================= THE #1 RULE (read carefully) =========================
The creator is handing you a personal thought, opinion, feeling, or moment — NOT a topic to explain.
Your job is to write a POST in FIRST PERSON, as if it came straight from the creator's own mouth.

DO NOT explain, define, teach, or summarize the topic.
DO NOT list facts, benefits, side-effects, or "tips" about it.
Write what THIS creator would actually say to their audience about it.

EXAMPLE A — voice sample = casual warm English; input is PLAIN ENGLISH:
  idea: "I want to stop eating shawarma too much because I know junk isn't good for me"
  WRONG (explaining): "Eating too much junk food can lead to health issues. Here's why moderation matters..." — forbidden.
  WRONG (robot): "An internal review of personal dietary consumption patterns..." — forbidden.
  RIGHT: "I really need to lay off the shawarma man 😮‍💨 I know junk isn't doing me any favors, but cutting back? that's the real fight."
  (100% clean English — because the input was English. No pidgin anywhere.)

EXAMPLE B — voice sample = formal, polished English; input is PLAIN ENGLISH:
  idea: "I just shipped my first app after 3 months of building"
  RIGHT: "Three months of work, and it's finally live. Still a little stunned that it actually runs."
  (Formal English kept consistently — the sample's formality shaped it, still 100% standard English.)

EXAMPLE C — input is in PIDGIN:
  idea: "I don tire for this Lagos traffic abeg, I just wan reach house and rest"
  RIGHT: "Omo this Lagos traffic don tire me today 😩 I just wan reach house make I rest small."
  (Pidgin output — ONLY because the INPUT itself was pidgin.)

WRONG — THE DRIFT BUG, NEVER DO THIS:
  input (plain English): "Mondays are so draining"
  BAD: "Mondays really drain me... omo e be like say we go dey suffer till further notice 😔"
  ✗ The input was plain English, but a pidgin line got slipped in. FORBIDDEN. Never switch language mid-post.

Every RIGHT post stays in ONE language the whole way (the language of the INPUT), sounds like the creator's voice sample, stays true to their intent, and never explains the topic.

============================== HOW TO WRITE =================================
- Plain, clean, standard English by default — the kind anyone anywhere can read. Write how a real person TALKS and TEXTS, not an essay or a brand.
- Use contractions, keep it natural; a little imperfect is fine.
- LANGUAGE: only write in Pidgin/dialect if THIS input (the idea, or the screenshot text) is itself in Pidgin/dialect. Otherwise clean English start to finish — no stray pidgin or dialect line slipped in.
- Keep the creator's actual opinion/feeling/angle from their idea. Never swap in a different take.
- NEVER use AI or corporate language or shapes: "in today's world", "in the world of", "unlock", "elevate", "game-changer", "dive into", "navigate", "it's important to", "when it comes to", "look no further", neat 3-point lists, or suspiciously perfect parallel sentences.
- Don't stuff hashtags into the post body — hashtags go only in the hashtags field.

For EACH platform below, write it natively for that platform (never copy-paste the same text across platforms):
${platformInstructions}

${isScreenshot
  ? `THE SOURCE — A SCREENSHOT:
A screenshot of a post/tweet the creator LIKES is attached as an image. READ the words inside that screenshot. That post is only your REFERENCE for the idea and angle — take its core message and rewrite it completely as THIS creator's OWN post, in their voice (all rules above).
- Do NOT copy it word-for-word, and do NOT keep the original author's voice — make it sound like the creator, not the person in the screenshot.
- Do NOT mention the screenshot, do NOT describe the image, do NOT quote it. Just give the creator's own version of that kind of post.
- Ignore any usernames, handles, timestamps, like/retweet counts, or UI buttons in the image — only the actual post message matters.${input ? `\n- The creator also added this note to steer it: "${input}"` : ''}`
  : `THE CREATOR'S RAW IDEA:
${input}`}

Return ONLY valid JSON (no markdown, no backticks, no commentary) in EXACTLY this shape:
{
  "platforms": {
    "<platform name exactly as given>": {
      "post": "the ready-to-post text, first person, in the creator's voice — a real post, not an explanation",
      "hook": "a scroll-stopping first line (this can be the opening line of the post)",
      "hashtags": ["#relevant"]
    }
  }
}
Every single post must read like the creator wrote it themselves about their own idea — never like an explanation OF the idea. Include an entry for every platform requested.`;
}

// Call Gemini with automatic retries. Google's free tier throws transient
// 503 (overloaded) / 429 (rate limit) / 500 errors — those are NOT our bug,
// so we wait briefly and try again instead of failing the user.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The hard rules live HERE as a system instruction — Gemini obeys these far more
// strictly than anything placed inside the user prompt. This is what stops the
// "explain the topic / corporate robot" output for good.
const POST_SYSTEM_INSTRUCTION = `You are Scrabl, a ghostwriter for ONE social-media creator.
You receive a raw personal thought from the creator. Your ONLY job is to turn it into a social post written in FIRST PERSON, as if the creator typed it themselves on their phone.

ABSOLUTE RULES — breaking any of these means you failed:

1. YOU ARE THE CREATOR. Write their post in first person, as if they typed it themselves. NEVER explain, define, teach, review, or summarise the topic — you are posting a thought, not describing one.

2. THE VOICE SAMPLE IS YOUR MASTER for HOW they sound: tone, formality, rhythm, vocabulary, emoji habits, personality. Match it so the post feels like THEY wrote it.

3. LANGUAGE — THE MOST IMPORTANT RULE. Default to plain, clean, standard English that anyone in the world can read. Do NOT use Pidgin, creole, or heavy regional dialect UNLESS the creator's CURRENT input (their typed idea, or the text inside the screenshot they pasted) is ITSELF written in that dialect.
   - First decide: is this input in plain English, or in Pidgin/dialect?
   - Input is plain English -> the ENTIRE post is plain clean English. Zero pidgin words. None.
   - Input is Pidgin/dialect -> write the WHOLE post in that same Pidgin/dialect.
   - The voice sample only flavours the ENGLISH (casual, warm, formal, punchy...). It NEVER licenses switching out of standard English. Even if the sample itself contains pidgin, you still write clean English unless THIS input uses pidgin.

4. ONE LANGUAGE, ONE REGISTER, THE WHOLE POST. Never start in clean English and slip a pidgin, slang or dialect line in later. No stray out-of-place sentence. Start to finish: one voice, one language.

5. The input is your REFERENCE, not a script — expand it into a natural, ready-to-post piece, but keep the creator's real intent and feeling. Don't flip their take or invent facts that contradict them.

6. NEVER use corporate, academic, or AI-sounding language. BANNED (and anything like them): "internal review", "consumption patterns", "optimization", "optimal", "leverage", "utilize", "implement", "initiative", "in today's world", "dive into", "elevate", "unlock", "game-changer", "it's important to", "when it comes to", "delve", "tapestry", "testament", "S-tier".

Before you answer: would a real person actually post this, in exactly this language? Scan it for ANY pidgin or dialect word the input did not use — if you find one, delete it and write it in clean English. If it sounds like a report or a robot, rewrite it.

Output ONLY valid JSON in the exact shape requested. No markdown, no backticks, no commentary.`;

// Higher temperature = looser, more human. Force raw JSON so parsing never breaks.
const POST_GEN_CONFIG = { temperature: 0.95, topP: 0.95, responseMimeType: 'application/json' };

// Build an ordered list of models to try. If the primary is overloaded or
// missing, we progressively fall through to lighter / alternate models so
// one busy model can never take generation down.
function buildModelChain() {
    const chain = [];
    const push = (m) => { if (m && !chain.includes(m)) chain.push(m); };
    push(geminiModelName);                      // whatever GEMINI_MODEL is set to
    push(process.env.GEMINI_FALLBACK_MODEL);    // optional manual override
    push('gemini-2.5-flash');
    push('gemini-2.5-flash-lite');
    push('gemini-flash-latest');
    return chain;
}

async function generateContentResilient(prompt) {
    const transient = [429, 500, 502, 503, 504]; // Google busy — safe to retry
    const attemptsPerModel = 2;
    const models = buildModelChain();
    let lastErr = null;

    for (const modelName of models) {
        let model;
        try {
            // Always build a fresh model carrying the system instruction + JSON config.
            model = genAI.getGenerativeModel({
                model: modelName,
                systemInstruction: POST_SYSTEM_INSTRUCTION,
                generationConfig: POST_GEN_CONFIG
            });
        } catch (e) { lastErr = e; continue; }

        for (let attempt = 1; attempt <= attemptsPerModel; attempt++) {
            try {
                return await model.generateContent(prompt);
            } catch (err) {
                lastErr = err;
                const status = err && err.status;
                if (status === 404) break;                 // model unavailable → next in chain
                if (!transient.includes(status)) throw err; // real error (bad key/prompt) → surface it
                const waitMs = 500 * attempt;              // 0.5s, then 1s
                console.warn(`Gemini ${status} on ${modelName} (try ${attempt}/${attemptsPerModel}) — retrying in ${waitMs}ms`);
                await sleep(waitMs);
            }
        }
        console.warn(`Gemini: ${modelName} unavailable/overloaded — moving to next model`);
    }
    throw lastErr;
}

app.post('/api/generate', async (req, res) => {
    try {
        const auth = req.headers.authorization || '';
        const token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.body?.token || '');
        const payload = verifyToken(token);
        if (!payload) return res.status(401).json({ error: 'Please log in again.' });

        if (!geminiClient) return res.status(503).json({ error: geminiInitError || 'Gemini not initialized.' });

        const input = (req.body?.input || '').trim();
        let platforms = req.body?.platforms;

        // Screenshot-to-Post: an optional image the user uploaded. It may arrive as a
        // raw base64 string or as a data URL ("data:image/png;base64,....").
        let imageRaw = req.body?.image || '';
        let imageMime = req.body?.imageMimeType || '';
        if (imageRaw && imageRaw.startsWith('data:')) {
            const m = imageRaw.match(/^data:([^;]+);base64,(.*)$/);
            if (m) { imageMime = imageMime || m[1]; imageRaw = m[2]; }
        }
        const hasImage = !!imageRaw;
        const mode = hasImage ? 'screenshot' : 'text';
        if (!hasImage) imageMime = '';
        else if (!imageMime) imageMime = 'image/png';

        // Text mode needs an idea. Screenshot mode needs the image (a note is optional).
        if (!hasImage && !input) return res.status(400).json({ error: 'Type an idea to generate from.' });
        if (!Array.isArray(platforms) || platforms.length === 0) {
            return res.status(400).json({ error: 'Pick at least one platform.' });
        }
        platforms = platforms.slice(0, 7);

        const user = await User.findById(payload.id);
        if (!user) return res.status(404).json({ error: 'Account not found.' });

        const prompt = buildGenerationPrompt(input, platforms, user, mode);
        // When there's a screenshot, send the prompt + image together as multimodal parts.
        const request = hasImage
            ? [{ text: prompt }, { inlineData: { mimeType: imageMime, data: imageRaw } }]
            : prompt;
        const result = await generateContentResilient(request);
        const rawText = await extractGeminiRawText(result);
        const parsed = parseVoiceJSON(rawText);

        if (!parsed || !parsed.platforms) {
            return res.status(502).json({ error: 'Could not generate right now. Please try again.' });
        }

        // Save to the account's recent history so it shows on any device, not just this
        // browser (mobile private-mode / quota can silently drop localStorage).
        try {
            const entry = { input: input, results: parsed.platforms, ts: Date.now(), mode: mode };
            const prev = Array.isArray(user.recent) ? user.recent : [];
            user.recent = [entry].concat(prev).slice(0, 8);
            user.markModified('recent');
            await user.save();
        } catch (e) { console.error('Recent save failed:', e && e.message); }

        console.log('Generated (' + mode + ') for ' + user.email + ' - platforms: ' + platforms.join(', '));
        return res.status(200).json({ success: true, results: parsed.platforms });
    } catch (err) {
        console.error('Generate error:', err);
        // Google overloaded even after retries — tell the user it's temporary, not their fault.
        if (err && [429, 503].includes(err.status)) {
            return res.status(503).json({
                error: 'Our AI is a little busy right now. Give it a few seconds and tap Generate again.'
            });
        }
        return res.status(500).json({ error: 'Generation failed. Please try again.' });
    }
});

// ========== HEALTH CHECK ==========
app.get('/api/health', (req, res) => {
    res.json({ status: 'Scrabl Backend is running ✨' });
});

async function startServer() {
    // Verify SMTP if configured
    if (emailTransport) {
        setEmailTransport(emailTransport);
        try {
            await emailTransport.verify();
            emailTransportReady = true;
            console.log('✅ Gmail SMTP verified and ready');
        } catch (err) {
            console.warn('⚠️ SMTP verification failed:', err.message);
            console.warn('   Waitlist codes will be logged to console instead');
        }
    }

    const server = app.listen(PORT, () => {
        console.log(`\n🚀 Scrabl Backend running on http://localhost:${PORT}`);
        console.log(`📝 OTP codes logged to console in dev mode\n`);
    });

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`\n⚠️  Port ${PORT} is already in use. Stop the other process or set a different PORT in .env.`);
            process.exit(1);
        }
        throw err;
    });
}

startServer();