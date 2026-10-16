# Scrabl on PXXL — Node web service

Structure: server.js serves the site from the public/ folder.
Root has NO index.html, so PXXL detects this as a Node.js web service
(not a static HTML site).

PXXL deploy settings:
- Language/Framework: Node.js (Express)
- Install command: npm install   (NOT npm ci)
- Start command:   npm start
- Working directory / root: /
- Port: 3000  (also set env var PORT=3000)

Environment variables (Settings -> Environment): see env.sample, use real values.
