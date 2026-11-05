const express = require("express");
const dns = require("node:dns").promises;
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");

const app = express();
const PORT = process.env.PORT || 3000;
const LIMIT = 1024 * 1024;
app.use(express.json({ limit: "1mb" }));
app.use(express.static(__dirname));

function privateIP(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || p[0] >= 224;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    return x === "::" || x === "::1" || x.startsWith("fc") ||
      x.startsWith("fd") || x.startsWith("fe8") ||
      x.startsWith("fe9") || x.startsWith("fea") ||
      x.startsWith("feb");
  }
  return true;
}
async function checkUrl(value) {
  const u = new URL(value);
  if (!["http:", "https:"].includes(u.protocol)) throw Error("Only HTTP/HTTPS URLs are allowed.");
  if (u.username || u.password) throw Error("URL credentials are not allowed.");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local"))
    throw Error("Local hosts are blocked.");
  if (net.isIP(host)) {
    if (privateIP(host)) throw Error("Private IP addresses are blocked.");
  } else {
    const records = await dns.lookup(host, { all: true });
    if (!records.length || records.some(r => privateIP(r.address)))
      throw Error("Host resolves to a private/reserved address.");
  }
  return u;
}
function fetchText(u, redirects = 0) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.get(u, { timeout: 10000, headers: { "User-Agent": "PURE-DEOBF/3.0" } }, res => {
      if ([301,302,303,307,308].includes(res.statusCode)) {
        res.resume();
        if (redirects >= 3 || !res.headers.location) return reject(Error("Redirect limit reached."));
        checkUrl(new URL(res.headers.location, u).href)
          .then(next => fetchText(next, redirects + 1)).then(resolve, reject);
        return;
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume(); return reject(Error("Remote HTTP " + res.statusCode));
      }
      let size = 0, chunks = [];
      res.on("data", chunk => {
        size += chunk.length;
        if (size > LIMIT) req.destroy(Error("Fetched file exceeds 1 MB."));
        else chunks.push(chunk);
      });
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    req.on("timeout", () => req.destroy(Error("Request timed out.")));
    req.on("error", reject);
  });
}
function analyze(source) {
  const tests = [
    ["MoonSec-like marker", /moonsec|moon\s*sec/i],
    ["Luraph-like marker", /luraph|lph_obf/i],
    ["MoonVeil-like marker", /moonveil|moon\s*veil/i],
    ["VM/dispatcher pattern", /while\s+true[\s\S]{0,500}(?:opcode|instruction|\bpc\b)/i],
    ["Escaped hexadecimal strings", /\\x[0-9a-f]{2}/i],
    ["Large numeric table", /\{\s*\d+(?:\s*,\s*\d+){30,}\s*\}/],
    ["Dynamic code loading", /\b(loadstring|load)\s*\(/i],
    ["Environment access", /\b(getfenv|setfenv|getgenv|_G)\b/i],
    ["Metatable operations", /\b(setmetatable|getmetatable|__index|__newindex)\b/i],
    ["String transformation", /\bstring\.(byte|char|gsub|reverse)\b/i],
    ["Hex constants", /0x[0-9a-f]+/i],
    ["Bitwise helpers", /\b(bit32|bit)\.(bxor|band|bor|lshift|rshift)\b/i],
    ["Debug library", /\bdebug\.(getinfo|traceback|info)\b/i],
    ["Protected calls", /\b(pcall|xpcall)\s*\(/i],
    ["Roblox APIs", /\b(game:GetService|Instance\.new|workspace)\b/]
  ];
  const found = tests.filter(x => x[1].test(source)).map(x => x[0]);
  return {
    language: /\b(game:GetService|Instance\.new|workspace)\b/.test(source) ? "Roblox Luau / Lua" : "Lua-like source",
    characters: source.length,
    lines: source.split(/\r?\n/).length,
    indicators: found,
    score: Math.min(100, found.length * 6),
    result: found.length >= 7 ? "Many indicators found" : found.length >= 3 ? "Some indicators found" : "Few indicators found",
    warning: "Heuristic static analysis only. It cannot guarantee identification or deobfuscation."
  };
}
app.get("/api/health", (req,res) => res.json({ ok:true, name:"PURE DEOBF", version:"3.0.0" }));
app.post("/api/analyze", (req,res) => {
  const source = req.body && req.body.source;
  if (typeof source !== "string" || !source.trim()) return res.status(400).json({ error:"Paste Lua/Luau source first." });
  if (Buffer.byteLength(source) > LIMIT) return res.status(413).json({ error:"Source exceeds 1 MB." });
  const formatted = source.replace(/\r\n?/g,"\n").split("\n").map(x=>x.replace(/[ \t]+$/,"")).join("\n");
  res.json({ analysis:analyze(source), formatted });
});
app.post("/api/fetch", async (req,res) => {
  try {
    if (!req.body || typeof req.body.url !== "string") return res.status(400).json({error:"Enter a public URL."});
    const u = await checkUrl(req.body.url.trim());
    const source = await fetchText(u);
    if (Buffer.byteLength(source) > LIMIT) return res.status(413).json({error:"Source exceeds 1 MB."});
    res.json({ source, characters:source.length });
  } catch (e) { res.status(400).json({error:e.message || "Fetch failed."}); }
});
app.get("*", (req,res) => res.sendFile(path.join(__dirname,"index.html")));
app.listen(PORT, () => console.log("PURE DEOBF listening on " + PORT));
