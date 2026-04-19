const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const crypto= require('crypto');

// ── Config ─────────────────────────────────────────────────────────────────
const PORT                 = process.env.PORT || 3000;
const ANTHROPIC_KEY        = process.env.ANTHROPIC_API_KEY        || '';
const STRIPE_SECRET        = process.env.STRIPE_SECRET_KEY        || '';
const STRIPE_PUBLISHABLE   = process.env.STRIPE_PUBLISHABLE_KEY   || '';
const STRIPE_WEBHOOK_SECRET= process.env.STRIPE_WEBHOOK_SECRET    || '';
const STRIPE_PRICE_ID      = process.env.STRIPE_PRICE_ID          || '';
const SUPABASE_URL         = process.env.SUPABASE_URL             || '';
const SUPABASE_KEY         = process.env.SUPABASE_SERVICE_KEY     || '';
const JWT_SECRET           = process.env.JWT_SECRET               || '';
const RESEND_API_KEY       = process.env.RESEND_API_KEY           || '';
const FROM_EMAIL           = process.env.FROM_EMAIL               || 'onboarding@resend.dev';
const MODEL                = 'claude-haiku-4-5-20251001';
const APP_URL              = process.env.APP_URL                  || `http://localhost:${PORT}`;

const REQUIRED_ENV = {
  ANTHROPIC_API_KEY:       ANTHROPIC_KEY,
  STRIPE_SECRET_KEY:       STRIPE_SECRET,
  STRIPE_PUBLISHABLE_KEY:  STRIPE_PUBLISHABLE,
  STRIPE_WEBHOOK_SECRET:   STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICE_ID:         STRIPE_PRICE_ID,
  SUPABASE_URL:            SUPABASE_URL,
  SUPABASE_SERVICE_KEY:    SUPABASE_KEY,
  JWT_SECRET:              JWT_SECRET,
};
const missingVars = Object.entries(REQUIRED_ENV).filter(([,v]) => !v).map(([k]) => k);
if (missingVars.length > 0) {
  console.error('\n❌ Missing required environment variables:');
  missingVars.forEach(k => console.error('   - ' + k));
  console.error('\nSet these in Railway → Variables then redeploy.\n');
  process.exit(1);
}
if (!RESEND_API_KEY) console.warn('⚠️  RESEND_API_KEY not set — grant alert emails will be disabled.');

console.log('GrantScout UK starting on port ' + PORT);

// ── MIME types ─────────────────────────────────────────────────────────────
const MIME = {
  '.html':'text/html', '.js':'application/javascript',
  '.css':'text/css',   '.json':'application/json', '.ico':'image/x-icon'
};

// ── In-memory grant cache for fast repeat searches ─────────────────────────
let memGrantCache = null;
let memGrantCacheTime = 0;
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

// ── Helpers ────────────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));

function jsonReq(hostname, path, method, body, extraHeaders) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : '';
    const opts = {
      hostname, path, method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        ...extraHeaders
      }
    };
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(d) }); }
        catch(_) { resolve({ status: res.statusCode, body: d }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function rawReq(hostname, path, method, rawBody, extraHeaders) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody);
    const opts = { hostname, path, method, headers: { ...extraHeaders, 'Content-Length': buf.byteLength } };
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', reject);
    req.write(buf);
    req.end();
  });
}

// Dedicated Stripe helper — always uses form-encoded body
function stripeReq(path, params) {
  const body = Buffer.from(new URLSearchParams(params).toString());
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: 'api.stripe.com',
      path,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${STRIPE_SECRET}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': body.byteLength,
      }
    };
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(d) }); }
        catch(_) { resolve({ status: res.statusCode, body: d }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── JWT (HS256, no library) ────────────────────────────────────────────────
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function signJWT(payload) {
  const header  = b64url(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const body    = b64url(JSON.stringify({ ...payload, iat: Math.floor(Date.now()/1000) }));
  const sig     = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}
function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = b64url(crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest());
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch(_) { return null; }
}

// ── Supabase helpers ───────────────────────────────────────────────────────
const SB_HOST = SUPABASE_URL.replace('https://','');

async function sbQuery(table, filter) {
  const res = await jsonReq(SB_HOST, `/rest/v1/${table}?${filter}&limit=1`, 'GET', null, {
    'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Accept': 'application/json'
  });
  return Array.isArray(res.body) ? res.body[0] : null;
}
async function sbInsert(table, data) {
  return jsonReq(SB_HOST, `/rest/v1/${table}`, 'POST', data, {
    'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Prefer': 'return=representation'
  });
}
async function sbUpdate(table, filter, data) {
  return jsonReq(SB_HOST, `/rest/v1/${table}?${filter}`, 'PATCH', data, {
    'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`,
    'Prefer': 'return=representation'
  });
}

// ── Password hashing (no bcrypt, use SHA-256+salt for simplicity) ──────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const attempt = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return attempt === hash;
}

// ── Request body reader ────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ── Anthropic queue (one call at a time to avoid 429s) ────────────────────
let qRunning = false;
const queue = [];
function enqueue(task) {
  return new Promise((resolve, reject) => {
    queue.push({ task, resolve, reject });
    processQ();
  });
}
async function processQ() {
  if (qRunning || !queue.length) return;
  qRunning = true;
  const { task, resolve, reject } = queue.shift();
  try { resolve(await task()); } catch(e) { reject(e); }
  finally { qRunning = false; await sleep(300); processQ(); }
}

async function callAnthropic(payload, retries = 4) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const result = await new Promise((resolve, reject) => {
      const opts = {
        hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'x-api-key': ANTHROPIC_KEY,
          'anthropic-version': '2023-06-01',
          'anthropic-beta': 'web-search-2025-03-05'
        }
      };
      const req = https.request(opts, res => {
        let d = ''; res.on('data', c => d += c);
        res.on('end', () => resolve({ status: res.statusCode, body: d }));
      });
      req.on('error', reject);
      req.write(payload); req.end();
    });
    if (result.status !== 429 && result.status !== 529) return result;
    let wait = Math.pow(2, attempt) * 3000;
    try {
      const p = JSON.parse(result.body);
      if (p.error?.retry_after) wait = p.error.retry_after * 1000 + 500;
    } catch(_) {}
    console.log(`429 — waiting ${wait/1000}s (attempt ${attempt}/${retries})`);
    if (attempt < retries) await sleep(wait); else return result;
  }
}

// ── Streaming Anthropic call — pipes SSE to client response ───────────────
function streamAnthropic(payload, res) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'web-search-2025-03-05'
      }
    };
    const req = https.request(opts, upstream => {
      let buffer = '';
      upstream.on('data', chunk => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop(); // keep incomplete line
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6).trim();
            if (data === '[DONE]') { res.write('data: [DONE]\n\n'); continue; }
            try {
              const evt = JSON.parse(data);
              // Forward text delta events
              if (evt.type === 'content_block_delta' && evt.delta?.type === 'text_delta') {
                res.write(`data: ${JSON.stringify({ text: evt.delta.text })}\n\n`);
              }
              // Signal end of stream
              if (evt.type === 'message_stop') {
                res.write('data: [DONE]\n\n');
              }
            } catch(_) {}
          }
        }
      });
      upstream.on('end', () => resolve());
      upstream.on('error', reject);
    });
    req.on('error', reject);
    req.write(payload); req.end();
  });
}

// ── Auth middleware ────────────────────────────────────────────────────────
function getUser(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  return verifyJWT(token);
}

// ── Tier enforcement ───────────────────────────────────────────────────────
async function checkTier(userId, action) {
  // action: 'search' | 'application' | 'score' | 'improve_all'
  const user = await sbQuery('grantscout_users', `id=eq.${userId}`);
  if (!user) return { allowed: false, reason: 'User not found' };

  if (user.tier === 'premium') return { allowed: true, user };

  // Free tier limits
  const today = new Date().toISOString().slice(0, 10);
  const month = new Date().toISOString().slice(0, 7);

  if (action === 'search') {
    // Reset counter if new day
    if (user.search_date !== today) {
      await sbUpdate('grantscout_users', `id=eq.${userId}`, { search_count_today: 0, search_date: today });
      user.search_count_today = 0;
    }
    if (user.search_count_today >= 3) {
      return { allowed: false, reason: 'Free plan: 3 searches per day. Upgrade to Premium for unlimited.' };
    }
    await sbUpdate('grantscout_users', `id=eq.${userId}`, {
      search_count_today: user.search_count_today + 1, search_date: today
    });
    return { allowed: true, user };
  }

  if (action === 'application') {
    if (user.application_month !== month) {
      await sbUpdate('grantscout_users', `id=eq.${userId}`, { application_count_month: 0, application_month: month });
      user.application_count_month = 0;
    }
    if (user.application_count_month >= 1) {
      return { allowed: false, reason: 'Free plan: 1 grant application per month. Upgrade to Premium for unlimited.' };
    }
    await sbUpdate('grantscout_users', `id=eq.${userId}`, {
      application_count_month: user.application_count_month + 1, application_month: month
    });
    return { allowed: true, user };
  }

  if (action === 'score')       return { allowed: false, reason: 'Application scoring is a Premium feature. Upgrade to unlock.' };
  if (action === 'improve_all') return { allowed: false, reason: 'Free plan: only the Project section can be improved. Upgrade to unlock all sections.' };

  return { allowed: true, user };
}


// ══════════════════════════════════════════════════════════════════════════
// GRANT ALERT EMAIL SYSTEM
// ══════════════════════════════════════════════════════════════════════════

// ── Send email via Resend ─────────────────────────────────────────────────
async function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY) { console.warn('Resend not configured, skipping email to', to); return false; }
  const payload = JSON.stringify({ from: FROM_EMAIL, to, subject, html });
  return new Promise((resolve) => {
    const opts = {
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };
    const req = https.request(opts, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        if (!ok) console.error(`Resend error ${res.statusCode}:`, d);
        resolve(ok);
      });
    });
    req.on('error', err => { console.error('Resend request error:', err.message); resolve(false); });
    req.write(payload); req.end();
  });
}

// ── Build HTML email for grant alerts ─────────────────────────────────────
function buildAlertEmail(newGrants, totalGrants) {
  const grantRows = newGrants.slice(0, 8).map(g => `
    <tr>
      <td style="padding:14px 0;border-bottom:1px solid #252d45;">
        <a href="${g.url||'https://www.gov.uk'}" style="font-family:Georgia,serif;font-size:16px;color:#00e5a0;text-decoration:none;font-weight:600;">${g.title||'Untitled Grant'}</a>
        <div style="font-size:12px;color:#6b7a9e;margin-top:3px;">${g.dept||''} · <span style="color:#00e5a0;font-family:monospace;">${g.amount||''}</span></div>
        <div style="font-size:13px;color:#b0bcd4;margin-top:6px;line-height:1.5;">${(g.summary||'').slice(0,120)}${(g.summary||'').length>120?'…':''}</div>
        <div style="margin-top:8px;">
          <span style="display:inline-block;font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(0,229,160,.1);color:#00e5a0;border:1px solid rgba(0,229,160,.2);">${g.status||'open'}</span>
          <span style="display:inline-block;font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(79,109,255,.1);color:#4f6dff;border:1px solid rgba(79,109,255,.2);margin-left:4px;">${g.sector||''}</span>
        </div>
      </td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>New UK Grants Available — GrantScout</title></head>
<body style="margin:0;padding:0;background:#0a0e1a;font-family:'DM Sans',Arial,sans-serif;color:#e2e8f8;">
  <div style="max-width:600px;margin:0 auto;padding:24px 16px;">

    <!-- Header -->
    <div style="text-align:center;padding:32px 0 24px;">
      <div style="display:inline-flex;align-items:center;gap:10px;text-decoration:none;">
        <div style="width:36px;height:36px;background:#00e5a0;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;font-size:18px;">🏛️</div>
        <span style="font-family:Georgia,serif;font-size:22px;color:#ffffff;">Grant<span style="color:#00e5a0;">Scout</span> UK</span>
      </div>
    </div>

    <!-- Hero -->
    <div style="background:#1a2035;border:1px solid #252d45;border-radius:16px;padding:28px;margin-bottom:20px;text-align:center;">
      <div style="font-size:32px;margin-bottom:12px;">🔔</div>
      <h1 style="font-family:Georgia,serif;font-size:26px;color:#ffffff;margin:0 0 10px;line-height:1.2;">
        ${newGrants.length} New Grant${newGrants.length===1?'':'s'} Available
      </h1>
      <p style="font-size:15px;color:#6b7a9e;margin:0;line-height:1.6;">
        We found ${newGrants.length} new UK government grant${newGrants.length===1?'':'s'} since your last alert.<br>
        ${totalGrants} total grants are currently available on GOV.UK.
      </p>
    </div>

    <!-- Grants list -->
    <div style="background:#1a2035;border:1px solid #252d45;border-radius:16px;padding:24px;margin-bottom:20px;">
      <h2 style="font-size:14px;font-weight:600;letter-spacing:1.5px;text-transform:uppercase;color:#6b7a9e;margin:0 0 4px;">New This Week</h2>
      <table style="width:100%;border-collapse:collapse;">${grantRows}</table>
    </div>

    <!-- CTA -->
    <div style="text-align:center;margin-bottom:24px;">
      <a href="${APP_URL}/index.html" style="display:inline-block;padding:14px 32px;background:#00e5a0;color:#0a0e1a;border-radius:10px;text-decoration:none;font-size:16px;font-weight:700;">
        View All Grants →
      </a>
    </div>

    <!-- Footer -->
    <div style="text-align:center;padding-top:20px;border-top:1px solid #252d45;">
      <p style="font-size:12px;color:#6b7a9e;margin:0 0 8px;">
        You're receiving this because you signed up for grant alerts on GrantScout UK.
      </p>
      <p style="font-size:11px;color:#3d4a6b;margin:0;">
        © 2026 GrantScout UK · Powered by Claude AI · Data from GOV.UK
      </p>
    </div>
  </div>
</body>
</html>`;
}

// ── Run the grant search (same logic as /api/search but no auth) ───────────
async function runGrantSearch() {
  const SYSTEM = `You are a UK government grants specialist. Search GOV.UK for currently available grants.
Return a single valid JSON array only — no markdown, no preamble.
Each grant: id, title, dept, amount (string), amountNum (integer), summary (2 sentences),
description (4 sentences), eligibility (3 sentences), howToApply (2 sentences),
sector (innovation|green|digital|health|export|skills|property|rural),
bizTypes (array: sme|startup|charity|social|manufacturing|tech|farming|retail),
status ("open"|"upcoming"), deadline (string|null), url (string).`;

  const USER = `Search GOV.UK right now and find 18 real currently available UK government grants. Include Innovate UK, DEFRA, British Business Bank, DESNZ, UKRI. Return ONLY a valid JSON array.`;

  let messages = [{ role: 'user', content: USER }];
  let finalText = '';

  for (let loop = 0; loop < 8; loop++) {
    const payload = JSON.stringify({
      model: MODEL, max_tokens: 8000, system: SYSTEM,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages
    });
    const result = await enqueue(() => callAnthropic(payload));
    const data = JSON.parse(result.body);
    if (result.status !== 200) throw new Error(`Anthropic ${result.status}`);
    if (data.stop_reason === 'end_turn') {
      finalText = (data.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('');
      break;
    }
    if (data.stop_reason === 'tool_use') {
      messages.push({ role: 'assistant', content: data.content });
      const toolResults = [];
      for (const block of (data.content||[])) {
        if (block.type === 'tool_use' && block.name === 'web_search') {
          toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: 'Search done. Compile grants into JSON array.' });
        }
      }
      if (toolResults.length) messages.push({ role: 'user', content: toolResults });
      else { finalText = (data.content||[]).filter(b=>b.type==='text').map(b=>b.text).join(''); break; }
    } else {
      finalText = (data.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('');
      break;
    }
  }

  const match = finalText.match(/\[\s*\{[\s\S]*\}\s*\]/);
  if (!match) throw new Error('No JSON found in response');
  try { return JSON.parse(match[0]); }
  catch(_) {
    const cut = match[0].lastIndexOf('},');
    if (cut > 0) return JSON.parse(match[0].slice(0, cut+1) + ']');
    throw new Error('Could not parse grant JSON');
  }
}

// ── Detect new grants by comparing to cached list ─────────────────────────
function findNewGrants(freshGrants, cachedGrants) {
  if (!cachedGrants || !cachedGrants.length) return freshGrants;
  const cachedTitles = new Set(cachedGrants.map(g => (g.title||'').toLowerCase().trim()));
  return freshGrants.filter(g => !cachedTitles.has((g.title||'').toLowerCase().trim()));
}

// ── Save grants to cache in Supabase ─────────────────────────────────────
async function saveGrantCache(grants) {
  // Also update in-memory cache
  memGrantCache = grants;
  memGrantCacheTime = Date.now();

  const SB_HOST = SUPABASE_URL.replace('https://','');
  const payload = JSON.stringify({ id: 1, grants, updated_at: new Date().toISOString() });
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(payload);
    const opts = {
      hostname: SB_HOST,
      path: '/rest/v1/grant_cache',
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': buf.byteLength,
        'Prefer': 'resolution=merge-duplicates'
      }
    };
    const req = https.request(opts, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode }));
    });
    req.on('error', reject);
    req.write(buf); req.end();
  });
}

// ── Load cached grants from Supabase ─────────────────────────────────────
async function loadGrantCache() {
  // Return in-memory cache if fresh
  if (memGrantCache && (Date.now() - memGrantCacheTime) < CACHE_TTL_MS) {
    return memGrantCache;
  }
  const SB_HOST = SUPABASE_URL.replace('https://','');
  const result = await jsonReq(SB_HOST, '/rest/v1/grant_cache?id=eq.1&limit=1', 'GET', null, {
    'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Accept': 'application/json'
  });
  const rows = Array.isArray(result.body) ? result.body : [];
  const grants = rows[0]?.grants || [];
  if (grants.length) {
    memGrantCache = grants;
    memGrantCacheTime = Date.now();
  }
  return grants;
}

// ── Send alerts to all subscribers ────────────────────────────────────────
async function sendGrantAlerts(newGrants, totalGrants) {
  if (!RESEND_API_KEY) { console.log('Resend not configured, skipping alerts'); return; }
  if (!newGrants.length) { console.log('No new grants found, skipping alerts'); return; }

  const SB_HOST = SUPABASE_URL.replace('https://','');
  const result = await jsonReq(SB_HOST, '/rest/v1/email_signups?select=email&limit=1000', 'GET', null, {
    'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Accept': 'application/json'
  });
  const subscribers = Array.isArray(result.body) ? result.body : [];
  if (!subscribers.length) { console.log('No subscribers yet'); return; }

  console.log(`Sending grant alerts to ${subscribers.length} subscribers...`);
  const subject = `🔔 ${newGrants.length} New UK Grant${newGrants.length===1?'':'s'} Available — GrantScout`;
  const html = buildAlertEmail(newGrants, totalGrants);

  let sent = 0;
  for (let i = 0; i < subscribers.length; i += 10) {
    const batch = subscribers.slice(i, i + 10);
    await Promise.all(batch.map(async sub => {
      const ok = await sendEmail(sub.email, subject, html);
      if (ok) sent++;
    }));
    if (i + 10 < subscribers.length) await sleep(1000);
  }
  console.log(`✅ Sent ${sent}/${subscribers.length} alert emails`);
}

// ── Daily grant check scheduler ─────────────────────────────────────────
async function runDailyCheck() {
  console.log('\n🔍 Running daily grant check...');
  try {
    const [freshGrants, cachedGrants] = await Promise.all([
      runGrantSearch(),
      loadGrantCache()
    ]);
    console.log(`Found ${freshGrants.length} grants. Cached: ${cachedGrants.length}`);

    const newGrants = findNewGrants(freshGrants, cachedGrants);
    console.log(`New grants since last check: ${newGrants.length}`);

    await saveGrantCache(freshGrants);

    if (newGrants.length > 0) {
      await sendGrantAlerts(newGrants, freshGrants.length);
    }

    console.log('✅ Daily grant check complete\n');
  } catch(err) {
    console.error('❌ Daily grant check failed:', err.message);
  }
}

// Schedule daily check at 8am UTC every day
function scheduleDailyCheck() {
  const now = new Date();
  const next8am = new Date(now);
  next8am.setUTCHours(8, 0, 0, 0);
  if (next8am <= now) next8am.setUTCDate(next8am.getUTCDate() + 1);
  const msUntil8am = next8am - now;
  console.log(`⏰ Next grant check scheduled in ${Math.round(msUntil8am/1000/60)} minutes (8am UTC)`);
  setTimeout(() => {
    runDailyCheck();
    setInterval(runDailyCheck, 24 * 60 * 60 * 1000);
  }, msUntil8am);
}

// ── HTTP Server ────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── POST /api/register ──────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/register') {
    const buf = await readBody(req);
    const { email, password } = JSON.parse(buf.toString());
    if (!email || !password || password.length < 8) {
      res.writeHead(400); res.end(JSON.stringify({ error: 'Email and password (8+ chars) required' })); return;
    }
    const existing = await sbQuery('grantscout_users', `email=eq.${encodeURIComponent(email)}`);
    if (existing) { res.writeHead(409); res.end(JSON.stringify({ error: 'Email already registered' })); return; }
    const hash = hashPassword(password);
    const result = await sbInsert('grantscout_users', { email, password_hash: hash });
    if (result.status !== 201) { res.writeHead(500); res.end(JSON.stringify({ error: 'Registration failed' })); return; }
    const user = Array.isArray(result.body) ? result.body[0] : result.body;
    const token = signJWT({ sub: user.id, email: user.email, tier: user.tier, exp: Math.floor(Date.now()/1000) + 86400*30 });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ token, tier: user.tier, email: user.email }));
    return;
  }

  // ── POST /api/login ─────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/login') {
    const buf = await readBody(req);
    const { email, password } = JSON.parse(buf.toString());
    const user = await sbQuery('grantscout_users', `email=eq.${encodeURIComponent(email)}`);
    if (!user || !verifyPassword(password, user.password_hash)) {
      res.writeHead(401); res.end(JSON.stringify({ error: 'Invalid email or password' })); return;
    }
    const token = signJWT({ sub: user.id, email: user.email, tier: user.tier, exp: Math.floor(Date.now()/1000) + 86400*30 });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ token, tier: user.tier, email: user.email }));
    return;
  }

  // ── GET /api/me ─────────────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/api/me') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end(JSON.stringify({ error: 'Not logged in' })); return; }
    const dbUser = await sbQuery('grantscout_users', `id=eq.${user.sub}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ email: dbUser.email, tier: dbUser.tier,
      searches_today: dbUser.search_count_today, applications_month: dbUser.application_count_month }));
    return;
  }

  // ── POST /api/checkout ──────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/checkout') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end(JSON.stringify({ error: 'Login required' })); return; }

    try {
      const dbUser = await sbQuery('grantscout_users', `id=eq.${user.sub}`);
      if (!dbUser) { res.writeHead(404); res.end(JSON.stringify({ error: 'User not found' })); return; }

      let customerId = dbUser.stripe_customer_id;
      if (!customerId) {
        const cust = await stripeReq('/v1/customers', {
          email: dbUser.email,
          'metadata[user_id]': user.sub
        });
        if (!cust.body.id) {
          console.error('Stripe customer create failed:', JSON.stringify(cust.body));
          res.writeHead(500); res.end(JSON.stringify({ error: 'Could not create Stripe customer: ' + (cust.body.error?.message || 'unknown') })); return;
        }
        customerId = cust.body.id;
        await sbUpdate('grantscout_users', `id=eq.${user.sub}`, { stripe_customer_id: customerId });
        console.log('Created Stripe customer:', customerId);
      }

      const session = await stripeReq('/v1/checkout/sessions', {
        'customer': customerId,
        'mode': 'subscription',
        'line_items[0][price]': STRIPE_PRICE_ID,
        'line_items[0][quantity]': '1',
        'success_url': `${APP_URL}/index.html?upgraded=1`,
        'cancel_url': `${APP_URL}/index.html`,
        'metadata[user_id]': user.sub,
        'payment_method_types[0]': 'card',
      });

      console.log('Stripe session status:', session.status, 'url:', session.body.url ? 'ok' : 'missing');

      if (!session.body.url) {
        console.error('Stripe session error:', JSON.stringify(session.body));
        res.writeHead(500);
        res.end(JSON.stringify({ error: session.body.error?.message || 'Stripe did not return a checkout URL' }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ url: session.body.url }));

    } catch(err) {
      console.error('Checkout error:', err.message);
      res.writeHead(500); res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // ── POST /api/portal (manage subscription) ──────────────────────────────
  if (req.method === 'POST' && url === '/api/portal') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end(JSON.stringify({ error: 'Login required' })); return; }

    try {
      const dbUser = await sbQuery('grantscout_users', `id=eq.${user.sub}`);
      if (!dbUser.stripe_customer_id) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'No subscription found' })); return;
      }

      const portal = await stripeReq('/v1/billing_portal/sessions', {
        'customer': dbUser.stripe_customer_id,
        'return_url': `${APP_URL}/index.html`
      });

      if (!portal.body.url) {
        console.error('Portal error:', JSON.stringify(portal.body));
        res.writeHead(500);
        res.end(JSON.stringify({ error: portal.body.error?.message || 'Could not open billing portal' }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ url: portal.body.url }));

    } catch(err) {
      console.error('Portal error:', err.message);
      res.writeHead(500); res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // ── POST /api/webhook/stripe ─────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/webhook/stripe') {
    const buf = await readBody(req);
    const sig = req.headers['stripe-signature'] || '';

    try {
      const parts   = sig.split(',').reduce((o, p) => { const [k,v]=p.split('='); o[k]=v; return o; }, {});
      const ts      = parts.t;
      const payload = `${ts}.${buf.toString()}`;
      const expected= crypto.createHmac('sha256', STRIPE_WEBHOOK_SECRET).update(payload).digest('hex');
      if (expected !== parts.v1) throw new Error('Signature mismatch');
    } catch(e) {
      console.error('Webhook sig failed:', e.message);
      res.writeHead(400); res.end('Invalid signature'); return;
    }

    const event = JSON.parse(buf.toString());
    console.log('Stripe event:', event.type);

    if (event.type === 'checkout.session.completed') {
      const userId = event.data.object.metadata?.user_id;
      const subId  = event.data.object.subscription;
      if (userId) {
        await sbUpdate('grantscout_users', `id=eq.${userId}`, { tier: 'premium', stripe_subscription_id: subId });
        console.log(`Upgraded user ${userId} to premium`);
      }
    }

    if (event.type === 'customer.subscription.deleted' || event.type === 'invoice.payment_failed') {
      const customerId = event.data.object.customer;
      const dbUser = await sbQuery('grantscout_users', `stripe_customer_id=eq.${customerId}`);
      if (dbUser) {
        await sbUpdate('grantscout_users', `id=eq.${dbUser.id}`, { tier: 'free', stripe_subscription_id: null });
        console.log(`Downgraded user ${dbUser.id} to free`);
      }
    }

    res.writeHead(200); res.end('ok');
    return;
  }

  // ── POST /api/search — with caching for speed ─────────────────────────────
  if (req.method === 'POST' && url === '/api/search') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end(JSON.stringify({ error: 'Please log in to search for grants' })); return; }

    // Check cache first — return immediately if fresh
    const cached = await loadGrantCache();
    if (cached && cached.length > 0) {
      console.log(`Cache hit: returning ${cached.length} grants instantly`);
      // Still check tier (counts a search)
      const check = await checkTier(user.sub, 'search');
      if (!check.allowed) {
        res.writeHead(403); res.end(JSON.stringify({ error: check.reason, upgrade: true })); return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ grants: cached, searches: 0, cached: true }));
      return;
    }

    const check = await checkTier(user.sub, 'search');
    if (!check.allowed) {
      res.writeHead(403); res.end(JSON.stringify({ error: check.reason, upgrade: true })); return;
    }

    const SYSTEM = `HARD SECURITY RULES: You have zero access to local files, env vars, cookies, clipboard or device hardware.
You are a UK government grants specialist. Search GOV.UK and official UK government sites for currently available grants.
Return a single valid JSON array only — no markdown fences, no preamble, no trailing text.
Each grant object must have:
id (number), title (string), dept (string), amount (string e.g. "Up to £50,000"),
amountNum (integer), summary (2 sentences), description (4 sentences),
eligibility (3 sentences), howToApply (2 sentences),
sector (one of: innovation|green|digital|health|export|skills|property|rural),
bizTypes (array from: sme|startup|charity|social|manufacturing|tech|farming|retail),
status ("open" or "upcoming"), deadline (string or null), url (string).`;

    const USER = `Search GOV.UK right now and find 18 real currently available UK government grants for businesses.
Search across departments: Innovate UK, DEFRA, British Business Bank, DESNZ, UKRI, Dept for Business and Trade.
Return ONLY a valid JSON array starting with [ and ending with ]. No markdown, no explanation.`;

    try {
      let messages = [{ role: 'user', content: USER }];
      let finalText = '';
      let searches = 0;

      for (let loop = 0; loop < 8; loop++) {
        const payload = JSON.stringify({
          model: MODEL,
          max_tokens: 8000,
          system: SYSTEM,
          tools: [{ type: 'web_search_20250305', name: 'web_search' }],
          messages
        });

        const result = await enqueue(() => callAnthropic(payload));
        const data = JSON.parse(result.body);

        if (result.status !== 200) {
          throw new Error(`Anthropic ${result.status}: ${JSON.stringify(data).slice(0, 200)}`);
        }

        if (data.stop_reason === 'end_turn') {
          finalText = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
          break;
        }

        if (data.stop_reason === 'tool_use') {
          messages.push({ role: 'assistant', content: data.content });
          const toolResults = [];
          for (const block of (data.content || [])) {
            if (block.type === 'tool_use' && block.name === 'web_search') {
              searches++;
              console.log(`Grant search ${searches}: ${block.input?.query}`);
              toolResults.push({
                type: 'tool_result',
                tool_use_id: block.id,
                content: 'Search completed. Compile all grants found into the JSON array.'
              });
            }
          }
          if (toolResults.length) {
            messages.push({ role: 'user', content: toolResults });
          } else {
            finalText = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
            break;
          }
        } else {
          finalText = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
          break;
        }
      }

      const match = finalText.match(/\[\s*\{[\s\S]*\}\s*\]/);
      if (!match) throw new Error('No grant data found in response');

      let grants;
      try { grants = JSON.parse(match[0]); }
      catch (_) {
        const cut = match[0].lastIndexOf('},');
        if (cut > 0) grants = JSON.parse(match[0].slice(0, cut + 1) + ']');
        else throw new Error('Could not parse grant JSON');
      }

      if (!grants || !grants.length) throw new Error('Empty grants array');

      // Cache the fresh results
      saveGrantCache(grants).catch(e => console.error('Cache save error:', e.message));

      console.log(`Search complete: ${grants.length} grants, ${searches} web searches`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ grants, searches }));

    } catch (err) {
      console.error('Search error:', err.message);
      res.writeHead(500);
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // ── POST /api/chat/stream — SSE streaming chat ────────────────────────────
  if (req.method === 'POST' && url === '/api/chat/stream') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end(JSON.stringify({ error: 'Please log in to use this feature' })); return; }

    const buf = await readBody(req);
    let parsed;
    try { parsed = JSON.parse(buf.toString()); } catch(e) { res.writeHead(400); res.end('Bad JSON'); return; }

    // Tier check
    const action = parsed._action || 'chat';
    delete parsed._action;
    const check = await checkTier(user.sub, action);
    if (!check.allowed) {
      res.writeHead(403); res.end(JSON.stringify({ error: check.reason, upgrade: true })); return;
    }

    parsed.model      = MODEL;
    parsed.max_tokens = parsed.max_tokens || 1000;
    parsed.stream     = true; // Enable streaming

    // Set SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    const payload = JSON.stringify(parsed);
    try {
      await streamAnthropic(payload, res);
    } catch(err) {
      res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    }
    res.end();
    return;
  }

  // ── POST /api/chat — non-streaming fallback ──────────────────────────────
  if (req.method === 'POST' && url === '/api/chat') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end(JSON.stringify({ error: 'Please log in to use this feature' })); return; }

    const buf = await readBody(req);
    let parsed;
    try { parsed = JSON.parse(buf.toString()); } catch(e) { res.writeHead(400); res.end('Bad JSON'); return; }

    const action = parsed._action || 'chat';
    delete parsed._action;
    const check = await checkTier(user.sub, action);
    if (!check.allowed) {
      res.writeHead(403); res.end(JSON.stringify({ error: check.reason, upgrade: true })); return;
    }

    parsed.model      = MODEL;
    parsed.max_tokens = parsed.max_tokens || 8000;
    delete parsed.stream;

    const payload = JSON.stringify(parsed);
    try {
      const result = await enqueue(() => callAnthropic(payload));
      res.writeHead(result.status, { 'Content-Type': 'application/json' });
      res.end(result.body);
    } catch(err) {
      res.writeHead(502); res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // ── GET /api/config ─────────────────────────────────────────────────────
  if (req.method === 'GET' && url === '/api/config') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ stripePk: STRIPE_PUBLISHABLE }));
    return;
  }

  // ── GET /api/test-alerts (manual trigger for testing) ────────────────────
  if (req.method === 'GET' && url === '/api/test-alerts') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end('Unauthorised'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Daily check triggered — check Railway logs' }));
    runDailyCheck();
    return;
  }

  // ── POST /api/email-signup ──────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/email-signup') {
    try {
      const buf  = await readBody(req);
      const { email } = JSON.parse(buf.toString());
      if (!email || !email.includes('@')) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Valid email required' })); return;
      }
      const existing = await sbQuery('email_signups', `email=eq.${encodeURIComponent(email)}`);
      if (existing) {
        res.writeHead(200, {'Content-Type':'application/json'});
        res.end(JSON.stringify({ ok: true, message: 'Already signed up!' })); return;
      }
      await sbInsert('email_signups', { email });
      res.writeHead(200, {'Content-Type':'application/json'});
      res.end(JSON.stringify({ ok: true, message: "You're on the list!" }));
    } catch(err) {
      console.error('Email signup error:', err.message);
      res.writeHead(500); res.end(JSON.stringify({ error: 'Signup failed, please try again' }));
    }
    return;
  }

  // ── Serve static files ──────────────────────────────────────────────────
  let fileName = url === '/' ? 'landing.html' : url.replace(/^\//, '').split('?')[0].split('#')[0];
  if (fileName.includes('..')) { res.writeHead(403); res.end('Forbidden'); return; }
  const fullPath = path.join(__dirname, fileName);
  console.log('Static request: ' + url + ' -> ' + fullPath);

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      console.error('File not found: ' + fullPath);
      fs.readdir(__dirname, (e2, files) => {
        const list = e2 ? 'unknown' : (files||[]).filter(f=>/\.(html|js|json)$/.test(f)).join(', ');
        res.writeHead(404, {'Content-Type':'text/html'});
        res.end('<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px"><h2>404 - Not Found</h2><p>Requested: <code>' + fileName + '</code></p><p>Files available: <code>' + list + '</code></p><p><a href=\"/\">Home</a></p></body></html>');
      });
      return;
    }
    const mime = MIME[path.extname(fullPath)] || 'application/octet-stream';
    res.writeHead(200, {'Content-Type': mime});
    res.end(data);
  });

}).listen(PORT, '0.0.0.0', () => {
  console.log('Ready on port ' + PORT);
  scheduleDailyCheck();
});
