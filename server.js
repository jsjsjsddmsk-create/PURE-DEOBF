'use strict';

const express = require('express');
const dns = require('node:dns').promises;
const net = require('node:net');
const path = require('node:path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const MAX_TEXT = 500_000;
const MAX_FETCH = 1_000_000;

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
app.use(express.json({ limit: '600kb' }));
app.use(express.static(ROOT, { index: 'index.html', extensions: ['html'] }));

function privateIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a,b] = p;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
}
function privateIPv6(ip) {
  const x = ip.toLowerCase();
  return x === '::' || x === '::1' || x.startsWith('fc') || x.startsWith('fd') ||
    x.startsWith('fe80:') || x.startsWith('::ffff:127.') || x.startsWith('::ffff:10.') ||
    x.startsWith('::ffff:192.168.');
}
async function validatePublicUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('الرابط غير صالح.'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('يسمح فقط بروابط HTTP وHTTPS.');
  if (u.username || u.password) throw new Error('الروابط التي تحتوي بيانات دخول غير مسموحة.');
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new Error('هذا العنوان محلي وغير مسموح.');
  }
  if (net.isIP(host)) {
    if ((net.isIPv4(host) && privateIPv4(host)) || (net.isIPv6(host) && privateIPv6(host))) {
      throw new Error('العناوين الخاصة أو المحلية غير مسموحة.');
    }
  } else {
    const records = await dns.lookup(host, { all: true });
    if (!records.length || records.some(r => net.isIPv4(r.address) ? privateIPv4(r.address) : privateIPv6(r.address))) {
      throw new Error('تعذر التحقق من عنوان عام آمن لهذا النطاق.');
    }
  }
  return u;
}

async function fetchPublicText(raw) {
  let current = await validatePublicUrl(raw);
  for (let hop = 0; hop < 4; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    let response;
    try {
      response = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'PURE-DEOBF-PRO/1.0', 'Accept': 'text/plain,text/javascript,application/javascript,text/*;q=0.9,*/*;q=0.1' }
      });
    } finally { clearTimeout(timer); }

    if ([301,302,303,307,308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('إعادة توجيه غير مكتملة.');
      current = await validatePublicUrl(new URL(location, current).toString());
      continue;
    }
    if (!response.ok) throw new Error(`تعذر جلب الملف: HTTP ${response.status}`);
    const type = response.headers.get('content-type') || '';
    if (type.includes('text/html') && !current.hostname.endsWith('githubusercontent.com')) {
      throw new Error('الرابط يعرض صفحة HTML وليس ملف سكربت نصياً مباشراً.');
    }
    const declared = Number(response.headers.get('content-length') || 0);
    if (declared > MAX_FETCH) throw new Error('حجم الملف أكبر من الحد المسموح (1MB).');
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_FETCH) { await reader.cancel(); throw new Error('حجم الملف أكبر من الحد المسموح (1MB).'); }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
  }
  throw new Error('عدد التحويلات بين الروابط أكبر من المسموح.');
}

function analyzeLua(source) {
  const checks = [];
  const add = (name, found, detail) => checks.push({ name, status: found ? 'detected' : 'not-detected', detail });
  const patterns = [
    ['Loadstring / dynamic loading', /\bloadstring\b|\bload\s*\(/i, 'رصد تحميل أو تجميع كود ديناميكي.'],
    ['HttpGet references', /\bHttpGet\b|\bGetAsync\b/i, 'رصد طلبات HTTP داخل النص.'],
    ['Luraph-like markers', /Luraph|LPH_|LuraphObfuscator/i, 'مؤشرات نصية محتملة؛ ليست إثباتاً لنوع الحماية.'],
    ['IronBrew-like markers', /IronBrew|Ironbrew|IB2/i, 'مؤشرات نصية محتملة.'],
    ['MoonSec-like markers', /MoonSec|Moon\s*Sec/i, 'مؤشرات نصية محتملة.'],
    ['Prometheus-like markers', /Prometheus|PrometheusObfuscator/i, 'مؤشرات نصية محتملة.'],
    ['VM / virtualized code markers', /virtual.?machine|vm_execute|opcode|opcodes/i, 'قد تشير إلى طبقة آلة افتراضية.'],
    ['Large escaped strings', /(?:\\x[0-9a-f]{2}){8,}|(?:\\[0-7]{3}){8,}/i, 'سلاسل طويلة ذات محارف مهروبة.'],
    ['Base64-like blobs', /["'][A-Za-z0-9+/]{80,}={0,2}["']/i, 'سلسلة طويلة تشبه Base64؛ لم يتم فكها تلقائياً.'],
    ['Hex-like blobs', /(?:0x[0-9a-f]{2}[,\s]*){12,}/i, 'كتلة أرقام سداسية طويلة.'],
    ['Environment access', /\b(getfenv|setfenv|_ENV|getgenv)\b/i, 'رصد الوصول إلى بيئة التنفيذ.'],
    ['Metatables', /\b(setmetatable|getmetatable|__index|__newindex)\b/i, 'رصد استخدام metatables.'],
    ['Debug library', /\bdebug\.(getinfo|setupvalue|getupvalue|traceback)/i, 'رصد استخدام مكتبة debug.'],
    ['String byte/char transforms', /\b(string\.byte|string\.char|string\.gsub|string\.sub)\b/i, 'قد تستخدم لمعالجة أو ترميز النصوص.'],
    ['Table-driven dispatch', /\bwhile\b[\s\S]{0,500}\btable\b|\bipairs\b|\bpairs\b/i, 'مؤشرات على منطق يعتمد على الجداول.'],
    ['Dynamic key construction', /\[[^\]\n]{1,80}\s*\.\.\s*[^\]\n]{1,80}\]/, 'مؤشر على بناء مفاتيح ديناميكياً.'],
    ['Control-flow keywords', /\b(repeat|until|while|goto)\b/i, 'تم رصد تراكيب تحكم قد تحتاج مراجعة.'],
    ['Unicode escapes', /\\u\{?[0-9a-f]{2,8}\}?/i, 'رصد تسلسلات Unicode مهروبة.']
  ];
  for (const [name, regex, detail] of patterns) add(name, regex.test(source), detail);
  const lines = source.split(/\r?\n/);
  const nonEmpty = lines.filter(x => x.trim()).length;
  const comments = (source.match(/--/g) || []).length;
  const strings = (source.match(/(["'])/g) || []).length / 2;
  const longLines = lines.filter(x => x.length > 500).length;
  add('Very long lines', longLines > 0, `${longLines} سطر يتجاوز 500 حرف.`);
  add('Low comment density', nonEmpty > 20 && comments / nonEmpty < 0.03, `تقريباً ${comments} علامة تعليق مقابل ${nonEmpty} سطر غير فارغ.`);
  add('String-heavy source', strings > Math.max(20, nonEmpty), `تقدير أولي: ${Math.floor(strings)} علامات اقتباس مزدوجة/مفردة.`);
  add('Repeated character runs', /(.)\1{12,}/.test(source), 'تم فحص التكرارات الطويلة.');
  add('Minified source hint', nonEmpty > 0 && (source.length / nonEmpty) > 250, 'متوسط طول السطر مرتفع.');
  add('Balanced delimiters (rough)', (source.match(/\(/g)||[]).length === (source.match(/\)/g)||[]).length &&
    (source.match(/\{/g)||[]).length === (source.match(/\}/g)||[]).length &&
    (source.match(/\[/g)||[]).length === (source.match(/\]/g)||[]).length, 'فحص تقريبي لتوازن الأقواس؛ لا يغني عن parser.');
  add('Potential bytecode payload', /string\.dump|bytecode|prototype|instruction stream/i.test(source), 'مؤشرات نصية محتملة لبيانات تعليمات.');
  add('Protected / anti-tamper hints', /anti.?tamper|checksum|integrity|tamper/i.test(source), 'مؤشرات حماية أو تحقق من سلامة النص.');
  add('Obfuscation name patterns', /\b[a-zA-Z_]\w{0,2}\s*=\s*function|\blocal\s+[a-zA-Z_]\w{0,1}\s*=/i.test(source), 'أسماء قصيرة قد تكون طبيعية أو ناتجة عن تصغير الأسماء.');

  return {
    summary: {
      characters: source.length,
      lines: lines.length,
      detected: checks.filter(x => x.status === 'detected').length,
      checks: checks.length
    },
    checks,
    note: 'النتائج مؤشرات ثابتة وليست فك تشفير مضموناً. لم يتم تشغيل السكربت أو تجاوز حماية أو استعادة كود خادمي خاص.'
  };
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'PURE DEOBFUSCATOR PRO' }));

app.post('/api/fetch', async (req, res) => {
  try {
    const url = String(req.body?.url || '').trim();
    if (!url) return res.status(400).json({ error: 'أدخل رابطاً أولاً.' });
    const source = await fetchPublicText(url);
    res.json({ source, length: source.length });
  } catch (err) {
    res.status(400).json({ error: err.message || 'فشل جلب الرابط.' });
  }
});

app.post('/api/analyze', (req, res) => {
  const source = String(req.body?.source || '');
  if (!source.trim()) return res.status(400).json({ error: 'ألصق كود Lua أولاً.' });
  if (source.length > MAX_TEXT) return res.status(413).json({ error: 'الحد الأقصى للنص 500KB.' });
  res.json(analyzeLua(source));
});

app.get('*', (_req, res) => {
  res.sendFile(INDEX, err => {
    if (err && !res.headersSent) res.status(404).send('index.html not found');
  });
});

app.use((err, _req, res, _next) => {
  res.status(400).json({ error: 'طلب غير صالح.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`PURE DEOBFUSCATOR PRO listening on ${PORT}`);
});
