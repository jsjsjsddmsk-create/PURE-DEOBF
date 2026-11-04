# PURE DEOBFUSCATOR PRO

## Render Web Service
- Runtime: Node.js 20+
- Build command: `npm install`
- Start command: `npm start`
- Root directory: leave blank

## Files
- `package.json`
- `server.js`
- `index.html`
- `README.md`

## What it does
- Accepts pasted Lua/Luau source.
- Fetches public text resources from URLs, with private-network address blocking and size/time limits.
- Runs heuristic static checks for common obfuscation indicators.
- Does not execute imported code or claim guaranteed deobfuscation.

## Limitations
This is a static analyzer, not a universal deobfuscator. It cannot recover private server-side source, bypass authentication/access controls, or guarantee reconstruction of VM-based or encrypted code. Only inspect code you own or have permission to analyze.
