# Deploy Scrabl to PXXL (free) — one unified app

This folder IS your app. server.js serves the whole site (frontend + API)
on one URL, so you deploy ONE project. No separate frontend/backend.

## 0. Before anything — rotate your secrets
These were exposed in an old backup, so make fresh ones:
- New Gemini API key (Google AI Studio)
- New MongoDB Atlas database password
- New Gmail app password (only if you still use SMTP)
Then DELETE scrabl-service-account.json from your project — it is not used.

## 1. Put this folder in your GitHub repo
Replace your repo's contents with these files (server.js is next to all the
.html files — keep it that way; that is what makes the site serve).
Make sure .gitignore is included so .env and keys are never pushed.
Commit and push to GitHub.

## 2. Create a free PXXL account
Go to pxxl.app → sign up (free, no card). 

## 3. New project → connect GitHub → pick this repo
- Framework/type: Node.js
- Build command: npm install
- Start command: npm start
- PXXL auto-deploys on every push.

## 4. Add environment variables (dashboard → Environment)
Copy the names from env.sample and paste your REAL values:
GOOGLE_API_KEY, GEMINI_MODEL, MONGO_URI, AUTH_SECRET,
RESEND_API_KEY, FROM_EMAIL, and the optional ones you use.
Do NOT add PORT — PXXL sets it automatically (server.js reads it).

## 5. Deploy & test on the free subdomain
Open your-app.pxxl.app and test: homepage loads, sign up, verify email,
onboarding saves. Check live logs in the dashboard if anything errors.

## 6. (Later) Point your domain
Add your custom domain in PXXL and update your DNS as it instructs.
