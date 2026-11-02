# PURE LOADSTRING PRO v2

Upload the four files with this structure:
- `package.json` (repository root)
- `server.js` (repository root)
- `README.md` (repository root)
- `public/index.html` (inside a folder named `public`)

Render Web Service:
- Build Command: `npm install`
- Start Command: `npm start`

The server serves `public/index.html` at `/`. It provides `/api/health` and `/api/fetch`.
This is a public-source fetcher and static analyzer, not a universal deobfuscator. It does not execute remote code or bypass authentication/protection.
