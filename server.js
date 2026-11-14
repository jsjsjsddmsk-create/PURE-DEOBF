// ============================================
// NovaHost — Backend Server
// Language: JavaScript (Node.js - CommonJS)
// Optimized for: Render Deployment
// ============================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const crypto = require('crypto');

// ===== إعداد Express + Socket.IO =====
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 60000,
  pingInterval: 25000
});

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== مجلد حفظ البوتات =====
const BOTS_DIR = path.join(__dirname, 'bots');
if (!fs.existsSync(BOTS_DIR)) fs.mkdirSync(BOTS_DIR, { recursive: true });

// ===== إعداد رفع الملفات =====
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ===== تخزين البوتات في الذاكرة =====
const bots = new Map();

// ===== إعدادات كل لغة برمجية =====
const LANG_CONFIG = {
  javascript: { file: 'index.js',  run: 'node index.js' },
  python:     { file: 'main.py',   run: 'python3 main.py' },
  java:       { file: 'Main.java', run: 'java Main' },
  php:        { file: 'index.php', run: 'php index.php' },
  go:         { file: 'main.go',   run: 'go run main.go' },
  ruby:       { file: 'main.rb',   run: 'ruby main.rb' },
  lua:        { file: 'main.lua',  run: 'lua main.lua' }
};

// ===== دالة: إرسال لوج للـ client =====
function emitLog(bot, msg, type = 'log') {
  const log = { msg, type, time: Date.now() };
  if (!bot.logs) bot.logs = [];
  bot.logs.push(log);
  if (bot.logs.length > 500) bot.logs.shift();
  io.to('bot_' + bot.id).emit('log', log);
}

// ===== كلمات تدل إن البوت اتصل بنجاح =====
const ONLINE_KEYWORDS = [
  'logged in as',
  'bot is ready',
  'ready!',
  'is online',
  'connected as',
  'client ready',
  'logged in'
];

// ===== دالة: استقبال مخرجات البوت + كشف online =====
function handleOutput(bot, data, stream) {
  const text = data.toString();
  text.split('\n').filter(Boolean).forEach((line) => {
    emitLog(bot, line, stream === 'stderr' ? 'error' : 'log');

    const lower = line.toLowerCase();
    const isOnline = ONLINE_KEYWORDS.some((k) => lower.includes(k));

    if (isOnline && bot.status !== 'online') {
      bot.status = 'online';
      emitLog(bot, '✓ Bot was online successfully', 'success');
      io.to('bot_' + bot.id).emit('status', 'online');
    }
  });
}

// ===== دالة: تشغيل أمر shell (npm install / pip install) =====
function runCommand(bot, cmd, label = '') {
  return new Promise((resolve, reject) => {
    if (label) emitLog(bot, `◉ ${label}...`, 'info');

    const child = spawn(cmd, { cwd: bot.dir, shell: true });
    child.stdout.on('data', (d) => handleOutput(bot, d, 'stdout'));
    child.stderr.on('data', (d) => handleOutput(bot, d, 'stderr'));
    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Command failed with exit code ${code}`));
    });
    child.on('error', reject);
  });
}

// ===== دالة: تشغيل البوت (spawn process حقيقي) =====
function startBot(bot) {
  const cfg = LANG_CONFIG[bot.language];
  if (!cfg) throw new Error('Unsupported language');

  const [cmd, ...args] = cfg.run.split(' ');

  const child = spawn(cmd, args, {
    cwd: bot.dir,
    env: {
      ...process.env,
      DISCORD_TOKEN: bot.token,
      BOT_TOKEN: bot.token,
      TOKEN: bot.token,
      NODE_ENV: 'production'
    },
    shell: false
  });

  bot.process = child;
  bot.status = 'starting';
  bot.startedAt = Date.now();
  emitLog(bot, `→ Spawned process PID ${child.pid}`, 'dim');

  child.stdout.on('data', (d) => handleOutput(bot, d, 'stdout'));
  child.stderr.on('data', (d) => handleOutput(bot, d, 'stderr'));

  child.on('exit', (code) => {
    bot.process = null;
    bot.status = 'stopped';
    emitLog(bot, `Process exited with code ${code}`, code === 0 ? 'warn' : 'error');
    io.to('bot_' + bot.id).emit('status', 'stopped');
  });

  // fallback: لو مفيش exit بعد 8 ثواني → اعتبرها online
  setTimeout(() => {
    if (bot.process === child && bot.status === 'starting') {
      bot.status = 'online';
      emitLog(bot, '✓ Bot was online successfully', 'success');
      io.to('bot_' + bot.id).emit('status', 'online');
    }
  }, 8000);
}

// ===== دالة: النشر الكامل (تثبيت + تشغيل) =====
async function deployBot(bot) {
  emitLog(bot, '◉ Uploading files...', 'info');

  // تثبيت تلقائي لـ Node.js
  if (bot.language === 'javascript') {
    const pkgPath = path.join(bot.dir, 'package.json');
    if (!fs.existsSync(pkgPath)) {
      fs.writeFileSync(
        pkgPath,
        JSON.stringify(
          {
            name: 'my-bot',
            version: '1.0.0',
            dependencies: { 'discord.js': '^14.14.1' }
          },
          null,
          2
        )
      );
      emitLog(bot, '→ Created default package.json (discord.js)', 'dim');
    }
    await runCommand(bot, 'npm install', 'Installing dependencies (npm install)');
  }

  // تثبيت تلقائي لـ Python
  if (bot.language === 'python') {
    const reqPath = path.join(bot.dir, 'requirements.txt');
    if (!fs.existsSync(reqPath)) {
      fs.writeFileSync(reqPath, 'discord.py\n');
      emitLog(bot, '→ Created default requirements.txt (discord.py)', 'dim');
    }
    await runCommand(bot, 'pip3 install -r requirements.txt', 'Installing dependencies (pip install)');
  }

  emitLog(bot, '✓ Dependencies installed', 'success');
  emitLog(bot, '◉ Starting bot process...', 'info');

  startBot(bot);
}

// ============================================
// ===== API Routes =====
// ============================================

// ===== Health Check (مهم لـ Render) =====
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    bots: bots.size,
    timestamp: new Date().toISOString()
  });
});

// ===== API: نشر بوت جديد =====
app.post('/api/deploy', upload.array('files'), (req, res) => {
  try {
    const { language, token, code } = req.body;

    if (!language || !LANG_CONFIG[language]) {
      return res.status(400).json({ error: 'اللغة غير مدعومة' });
    }
    if (!token) {
      return res.status(400).json({ error: 'التوكن مطلوب' });
    }

    const botId = crypto.randomBytes(8).toString('hex');
    const botDir = path.join(BOTS_DIR, botId);
    fs.mkdirSync(botDir, { recursive: true });

    // حفظ الملفات المرفوعة
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        fs.writeFileSync(path.join(botDir, file.originalname), file.buffer);
      }
    } else if (code && code.trim()) {
      fs.writeFileSync(path.join(botDir, LANG_CONFIG[language].file), code);
    } else {
      fs.rmSync(botDir, { recursive: true });
      return res.status(400).json({ error: 'ارفع ملف أو الصق كود' });
    }

    const bot = {
      id: botId,
      language,
      token,
      dir: botDir,
      status: 'idle',
      process: null,
      logs: [],
      startedAt: null
    };
    bots.set(botId, bot);

    res.json({ ok: true, botId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ===== API: حالة البوت =====
app.get('/api/bot/:id', (req, res) => {
  const bot = bots.get(req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });

  res.json({
    id: bot.id,
    status: bot.status,
    language: bot.language,
    uptime: bot.startedAt ? Date.now() - bot.startedAt : 0
  });
});

// ===== API: قائمة كل البوتات =====
app.get('/api/bots', (req, res) => {
  const list = Array.from(bots.values()).map((b) => ({
    id: b.id,
    language: b.language,
    status: b.status,
    uptime: b.startedAt ? Date.now() - b.startedAt : 0
  }));
  res.json(list);
});

// ============================================
// ===== Socket.IO =====
// ============================================
io.on('connection', (socket) => {
  console.log('🟢 Client connected:', socket.id);

  // الاشتراك في قناة بوت معين
  socket.on('subscribe', (botId) => {
    socket.join('bot_' + botId);
    const bot = bots.get(botId);
    if (bot && bot.logs) {
      bot.logs.forEach((l) => socket.emit('log', l));
    }
  });

  // النشر
  socket.on('deploy', async (botId) => {
    const bot = bots.get(botId);
    if (!bot) return socket.emit('error', 'Bot not found');

    try {
      await deployBot(bot);
    } catch (err) {
      emitLog(bot, '✗ ' + err.message, 'error');
      bot.status = 'error';
      io.to('bot_' + botId).emit('status', 'error');
    }
  });

  // تشغيل
  socket.on('start', (botId) => {
    const bot = bots.get(botId);
    if (!bot || bot.process) return;
    emitLog(bot, '◉ Starting bot...', 'info');
    try {
      startBot(bot);
    } catch (err) {
      emitLog(bot, err.message, 'error');
      io.to('bot_' + botId).emit('status', 'error');
    }
  });

  // إيقاف
  socket.on('stop', (botId) => {
    const bot = bots.get(botId);
    if (bot && bot.process) {
      emitLog(bot, '◉ Stopping bot...', 'warn');
      try {
        bot.process.kill('SIGTERM');
        // لو معنديش استجابة خلال 5 ثواني → SIGKILL
        setTimeout(() => {
          if (bot.process) {
            try { bot.process.kill('SIGKILL'); } catch (e) {}
          }
        }, 5000);
      } catch (err) {
        emitLog(bot, '✗ ' + err.message, 'error');
      }
    }
  });

  socket.on('disconnect', () => {
    console.log('🔴 Client disconnected:', socket.id);
  });
});

// ============================================
// ===== Server Listen (متوافق مع Render) =====
// ============================================
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

server.listen(PORT, HOST, () => {
  console.log('════════════════════════════════════════');
  console.log('🚀 NovaHost Server Started');
  console.log(`🌐 Listening on http://${HOST}:${PORT}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🩺 Health check: /health`);
  console.log('════════════════════════════════════════');
});

// ============================================
// ===== Graceful Shutdown (مهم لـ Render) =====
// ============================================
function shutdown(signal) {
  console.log(`\n⚠️  Received ${signal}. Shutting down gracefully...`);

  // إيقاف كل البوتات
  for (const bot of bots.values()) {
    if (bot.process) {
      try { bot.process.kill('SIGTERM'); } catch (e) {}
    }
  }

  server.close(() => {
    console.log('✅ Server closed. Bye!');
    process.exit(0);
  });

  // لو مقفلش في 10 ثواني → اخرج فورًا
  setTimeout(() => {
    console.log('⏱️  Force exit');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// ===== منع السيرفر من الانهيار بسبب خطأ غير متوقع =====
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Rejection:', reason);
});
