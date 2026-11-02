# Lua Deobfuscator Pro

A local browser workbench for **static inspection** of Lua and Roblox Luau source.

## Requirements
- Node.js 20 or newer
- npm

## Run
1. Extract the project folder.
2. Open a terminal in that folder.
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start the app:
   ```bash
   npm start
   ```
5. Open http://127.0.0.1:3000

For development with automatic restart, use `npm run dev`.

## Included features
- Monaco-based Lua editor
- Open `.lua`, `.luau`, and `.txt` files
- Heuristic signature checks for common obfuscator names
- Basic loader and encoded-string detection
- Conservative decoding of simple `\\xNN` byte escapes inside quoted strings
- Optional retrieval of public HTTP(S) text URLs
- 1 MiB input limit and worker-thread analysis timeout

## Important limitations
This is a **static-analysis helper**, not a universal deobfuscator. It does not reverse virtualized VM payloads, reconstruct protected control flow, or guarantee recovery of original source. Signature results are heuristic and can produce false positives or miss unknown protectors.

Pasted and fetched code is never executed. Remote URL retrieval is restricted to public HTTP(S) destinations and intended for text files only. Do not expose this local development server directly to the public internet.

## Project structure
```text
lua-deobfuscator-pro/
├── server.js
├── package.json
├── README.md
└── public/
    ├── index.html
    ├── app.js
    └── style.css
```


## Deploy to Render

This project includes `render.yaml` for Render Blueprint deployment.

### Option A — Blueprint (recommended)
1. Push the whole project folder to a GitHub repository.
2. In Render, choose **New + → Blueprint**.
3. Connect the GitHub repository.
4. Render reads `render.yaml`; approve the deployment.

### Option B — Create a Web Service manually
- Runtime: **Node**
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/api/health`

Render supplies the `PORT` environment variable. The server binds to `0.0.0.0` so the public Render service can reach it.

### Notes
- Keep `server.js`, `package.json`, `render.yaml`, and the `public/` directory in the repository root as shown.
- Do not commit `node_modules/`.
- The free Render instance may spin down after inactivity and take a little time to wake up.
- This remains a static-analysis tool; it does not execute pasted or fetched scripts.
