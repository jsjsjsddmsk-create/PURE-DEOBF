'use strict';

const express = require('express');
const path = require('node:path');
const dns = require('node:dns').promises;
const net = require('node:net');
const { Worker } = require('node:worker_threads');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_SOURCE = 1024 * 1024;

app.disable('x-powered-by');
app.use(express.json({ limit: '1100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/vendor/monaco', express.static(
  path.join(__dirname, 'node_modules/monaco-editor/min/vs')
));

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127);
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    return v === '::' || v === '::1' || v.startsWith('fc') ||
      v.startsWith('fd') || v.startsWith('fe8') ||
      v.startsWith('fe9') || v.startsWith('fea') ||
      v.startsWith('feb') || v.startsWith('::ffff:');
  }
  return true;
}

async function validatePublicUrl(raw) {
  const url = new URL(raw);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)
    throw new Error('Only credential-free HTTP(S) URLs are accepted.');
  if (url.port && !['80', '443'].includes(url.port))
    throw new Error('Only standard HTTP(S) ports are accepted.');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local'))
    throw new Error('Local hostnames are blocked.');
  const records = net.isIP(host) ? [{ address: host }] :
    await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some(r => isPrivateAddress(r.address)))
    throw new Error('Private, local, or reserved network addresses are blocked.');
  return url;
}

app.get('/api/health', (_req, res) =>
  res.json({ ok: true, mode: 'static-analysis-only', maxBytes: MAX_SOURCE }));

app.post('/api/fetch-url', async (req, res) => {
  try {
    let current = String(req.body?.url || '');
    for (let hop = 0; hop <= 3; hop++) {
      const url = await validatePublicUrl(current);
      const response = await fetch(url, {
        redirect: 'manual',
        signal: AbortSignal.timeout(8000),
        headers: { 'User-Agent': 'LuaDeobfuscatorPro/1.0', 'Accept': 'text/plain,*/*;q=0.5' }
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        if (!location || hop === 3) throw new Error('Redirect limit exceeded.');
        current = new URL(location, url).toString();
        continue;
      }
      if (!response.ok) throw new Error(`Remote server returned HTTP ${response.status}.`);
      if ((response.headers.get('content-type') || '').includes('text/html'))
        throw new Error('The URL returned HTML rather than script text.');
      const reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_SOURCE) {
          await reader.cancel();
          throw new Error('Remote script exceeds the 1 MiB limit.');
        }
        chunks.push(value);
      }
      return res.json({ url: url.toString(), source: Buffer.concat(chunks).toString('utf8'), bytes: size });
    }
  } catch (error) {
    res.status(400).json({ error: error.message || 'Fetch failed.' });
  }
});

app.post('/api/analyze', (req, res) => {
  const source = req.body?.source;
  if (typeof source !== 'string' || !source.trim())
    return res.status(400).json({ error: 'Paste a Lua/Luau source string first.' });
  if (Buffer.byteLength(source, 'utf8') > MAX_SOURCE)
    return res.status(413).json({ error: 'Source exceeds the 1 MiB limit.' });

  const workerCode = `
    const { parentPort, workerData } = require('node:worker_threads');
    const source = workerData.source;
    const signatures = [
      ['Luraph', /Luraph|\\\\x4c\\\\x75\\\\x72\\\\x61\\\\x70\\\\x68/i],
      ['MoonSec', /MoonSec|MoonSecV[0-9]?/i],
      ['MoonVeil', /MoonVeil/i], ['MoonSic', /MoonSic/i],
      ['IronBrew', /IronBrew|Ironbrew/i],
      ['Prometheus', /Prometheus|\\\\bLPH_[A-Z0-9_]+/i],
      ['Synapse wrapper', /synapse|identifyexecutor/i]
    ];
    const detectedObfuscators = signatures.filter(([, re]) => re.test(source)).map(([n]) => n);
    const loadstring = /loadstring\\\\s*\\\\(/i.test(source);
    const httpGet = /(?:game\\\\s*:\\\\s*HttpGet|HttpGetAsync)\\\\s*\\\\(/i.test(source);
    const encoded = /\\\\\\\\x[0-9a-f]{2}|\\\\b[A-Za-z0-9+/]{80,}={0,2}\\\\b|\\\\bstring\\\\s*\\\\.\\\\s*char\\\\s*\\\\(/i.test(source);
    const layers = [
      loadstring && 'Loadstring wrapper',
      httpGet && 'HTTP loader',
      encoded && 'Encoded strings or payload'
    ].filter(Boolean);
    const output = source.replace(/(["'])(?:\\\\\\\\x[0-9a-fA-F]{2})+\\\\1/g, value =>
      value.replace(/\\\\\\\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    );
    const notes = ['Static inspection completed. No input code was executed.'];
    if (detectedObfuscators.length) notes.push('Obfuscator signatures are heuristic, not proof of attribution.');
    if (encoded) notes.push('Encoded payload detected; arbitrary VM payloads are not executed or emulated.');
    if (loadstring || httpGet) notes.push('Loader detected. Use Fetch URL to retrieve remote text.');
    parentPort.postMessage({
      scriptType: /\\\\b(game|workspace|Instance|Vector3|CFrame)\\\\b/.test(source) ? 'Roblox Luau / Lua candidate' : 'Lua candidate',
      detectedObfuscators, detectionConfidence: detectedObfuscators.length ? 'Heuristic' : 'Undetermined',
      layers, lineCount: source.split(/\\\\r?\\\\n/).length,
      extractionStatus: detectedObfuscators.length || layers.length ? 'PARTIAL SUCCESS' : 'SUCCESS',
      source: output, notes,
      toolsUsed: ['loader detection', 'signature scan', 'escaped-string inspection']
    });
  `;
  const started = Date.now();
  const worker = new Worker(workerCode, { eval: true, workerData: { source } });
  let settled = false;
  const timer = setTimeout(() => {
    if (settled) return;
    settled = true; worker.terminate();
    res.status(408).json({ error: 'Analysis time limit exceeded.' });
  }, 10000);
  worker.once('message', result => {
    if (settled) return;
    settled = true; clearTimeout(timer);
    res.json({ ...result, processingMs: Date.now() - started });
  });
  worker.once('error', error => {
    if (settled) return;
    settled = true; clearTimeout(timer);
    res.status(500).json({ error: error.message });
  });
  worker.once('exit', code => {
    if (settled || code === 0) return;
    settled = true; clearTimeout(timer);
    res.status(500).json({ error: `Analysis worker exited (${code}).` });
  });
});

const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () =>
  console.log(`Lua Deobfuscator Pro listening on ${HOST}:${PORT}`));
