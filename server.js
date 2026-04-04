const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');

const PORT      = process.env.PORT || 3000;
const API_KEY   = process.env.ANTHROPIC_API_KEY || '';
const ANTHROPIC = 'api.anthropic.com';
const MODEL     = 'claude-haiku-4-5-20251001';

if (!API_KEY) {
  console.error('ANTHROPIC_API_KEY environment variable not set!');
  process.exit(1);
}

console.log('GrantScout UK starting on port ' + PORT);

const MIME = {
  '.html': 'text/html',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
};

// ── Sleep helper ───────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── Request queue — only ONE Anthropic call at a time ─────────────────────
// This prevents concurrent requests from both pages hammering the rate limit
let queueRunning = false;
const queue = [];

function enqueue(task) {
  return new Promise((resolve, reject) => {
    queue.push({ task, resolve, reject });
    processQueue();
  });
}

async function processQueue() {
  if (queueRunning || queue.length === 0) return;
  queueRunning = true;
  const { task, resolve, reject } = queue.shift();
  try {
    const result = await task();
    resolve(result);
  } catch (err) {
    reject(err);
  } finally {
    queueRunning = false;
    // Small gap between requests to be kind to rate limits
    await sleep(300);
    processQueue();
  }
}

// ── Call Anthropic with retry on 429 ──────────────────────────────────────
async function callAnthropic(payload, retries = 4) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const result = await new Promise((resolve, reject) => {
      const options = {
        hostname: ANTHROPIC,
        path:     '/v1/messages',
        method:   'POST',
        headers: {
          'Content-Type':      'application/json',
          'Content-Length':    Buffer.byteLength(payload),
          'x-api-key':         API_KEY,
          'anthropic-version': '2023-06-01',
          'anthropic-beta':    'web-search-2025-03-05',
        }
      };

      const apiReq = https.request(options, apiRes => {
        let data = '';
        apiRes.on('data', c => data += c);
        apiRes.on('end', () => resolve({ status: apiRes.statusCode, body: data }));
      });

      apiReq.on('error', err => reject(err));
      apiReq.write(payload);
      apiReq.end();
    });

    // Success or non-retryable error
    if (result.status !== 429 && result.status !== 529) return result;

    // Work out how long to wait
    let waitMs = Math.pow(2, attempt) * 3000; // 6s, 12s, 24s, 48s
    try {
      const parsed = JSON.parse(result.body);
      if (parsed.error && parsed.error.retry_after) waitMs = parsed.error.retry_after * 1000 + 500;
    } catch (_) {}

    console.log(`429 rate limit. Attempt ${attempt}/${retries}. Waiting ${waitMs/1000}s…`);
    if (attempt < retries) await sleep(waitMs);
    else return result; // Return 429 to client after exhausting retries
  }
}

// ── HTTP Server ────────────────────────────────────────────────────────────
http.createServer((req, res) => {

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── API proxy with queue + retry ──
  if (req.method === 'POST' && req.url === '/api/chat') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      let parsed;
      try { parsed = JSON.parse(body); }
      catch (e) { res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid JSON' })); return; }

      parsed.model      = MODEL;
      parsed.max_tokens = parsed.max_tokens || 8000;
      delete parsed.stream;

      const payload = JSON.stringify(parsed);

      try {
        // Queue the request — prevents concurrent calls that cause 429s
        const result = await enqueue(() => callAnthropic(payload));
        res.writeHead(result.status, { 'Content-Type': 'application/json' });
        res.end(result.body);
      } catch (err) {
        console.error('API error:', err.message);
        res.writeHead(502);
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // ── Serve static files ──
  let filePath = req.url === '/' ? '/index.html' : req.url.split('?')[0];
  filePath = path.join(__dirname, filePath);
  if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end('Forbidden'); return; }

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const mime = MIME[path.extname(filePath)] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });

}).listen(PORT, '0.0.0.0', () => console.log('Ready on port ' + PORT));
