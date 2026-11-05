PURE DEOBF V3
================

Node.js / Express application for static inspection of Lua and Roblox Luau source.

To deploy on Render:
1. Put the real files package.json, server.js, and index.html in the repository root.
2. Create a Render Web Service connected to the repository.
3. Build Command: npm install
4. Start Command: npm start
5. Leave Root Directory blank if the files are in the repository root.

API:
GET /api/health
POST /api/analyze  JSON: { "source": "..." }
POST /api/fetch     JSON: { "url": "https://public-host/script.lua" }

The analyzer uses heuristic pattern matching and conservative whitespace cleanup. It does not execute submitted scripts and does not guarantee deobfuscation or recovery of VM/bytecode-protected source. Obfuscator names in the report are indicator matches, not confirmed identification.

Remote fetching is restricted to public HTTP/HTTPS hosts, blocks private/reserved IP ranges, checks redirects, uses a timeout, and limits files to 1 MB.
