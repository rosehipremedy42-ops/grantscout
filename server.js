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
const MODEL                = 'claude-haiku-4-5-20251001';
const APP_URL              = process.env.APP_URL                  || `http://localhost:${PORT}`;

[ANTHROPIC_KEY, STRIPE_SECRET, STRIPE_PUBLISHABLE, STRIPE_WEBHOOK_SECRET,
 STRIPE_PRICE_ID, SUPABASE_URL, SUPABASE_KEY, JWT_SECRET].forEach((v, i) => {
  if (!v) { console.error(`Missing env var #${i}`); process.exit(1); }
});

console.log('GrantScout UK starting on port ' + PORT);

// ── MIME types ─────────────────────────────────────────────────────────────
const MIME = {
  '.html':'text/html', '.js':'application/javascript',
  '.css':'text/css',   '.json':'application/json', '.ico':'image/x-icon'
};

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
    const opts = { hostname, path, method, headers: { ...extraHeaders, 'Content-Length': rawBody.length } };
    const req = https.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    req.on('error', reject);
    req.write(rawBody);
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
    const dbUser = await sbQuery('grantscout_users', `id=eq.${user.sub}`);

    // Create or reuse Stripe customer
    let customerId = dbUser.stripe_customer_id;
    if (!customerId) {
      const cust = await jsonReq('api.stripe.com', '/v1/customers', 'POST',
        `email=${encodeURIComponent(dbUser.email)}&metadata[user_id]=${user.sub}`,
        { 'Authorization': `Bearer ${STRIPE_SECRET}`, 'Content-Type': 'application/x-www-form-urlencoded' });
      customerId = cust.body.id;
      await sbUpdate('grantscout_users', `id=eq.${user.sub}`, { stripe_customer_id: customerId });
    }

    // Create checkout session
    const params = new URLSearchParams({
      'customer': customerId,
      'mode': 'subscription',
      'line_items[0][price]': STRIPE_PRICE_ID,
      'line_items[0][quantity]': '1',
      'success_url': `${APP_URL}/index.html?upgraded=1`,
      'cancel_url': `${APP_URL}/index.html`,
      'metadata[user_id]': user.sub,
      'payment_method_types[0]': 'card',
      'payment_method_types[1]': 'link',
    }).toString();

    const session = await rawReq('api.stripe.com', '/v1/checkout/sessions', 'POST',
      Buffer.from(params), { 'Authorization': `Bearer ${STRIPE_SECRET}`,
        'Content-Type': 'application/x-www-form-urlencoded' });
    const sessionData = JSON.parse(session.body);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ url: sessionData.url }));
    return;
  }

  // ── POST /api/portal (manage subscription) ──────────────────────────────
  if (req.method === 'POST' && url === '/api/portal') {
    const user = getUser(req);
    if (!user) { res.writeHead(401); res.end(JSON.stringify({ error: 'Login required' })); return; }
    const dbUser = await sbQuery('grantscout_users', `id=eq.${user.sub}`);
    if (!dbUser.stripe_customer_id) {
      res.writeHead(400); res.end(JSON.stringify({ error: 'No subscription found' })); return;
    }
    const params = new URLSearchParams({
      'customer': dbUser.stripe_customer_id,
      'return_url': `${APP_URL}/index.html`
    }).toString();
    const portal = await rawReq('api.stripe.com', '/v1/billing_portal/sessions', 'POST',
      Buffer.from(params), { 'Authorization': `Bearer ${STRIPE_SECRET}`,
        'Content-Type': 'application/x-www-form-urlencoded' });
    const portalData = JSON.parse(portal.body);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ url: portalData.url }));
    return;
  }

  // ── POST /api/webhook/stripe ─────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/webhook/stripe') {
    const buf = await readBody(req);
    const sig = req.headers['stripe-signature'] || '';

    // Verify Stripe signature
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

  // ── POST /api/chat ──────────────────────────────────────────────────────
  if (req.method === 'POST' && url === '/api/chat') {
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

  // ── Serve static files ──────────────────────────────────────────────────
  let filePath = url === '/' ? '/login.html' : url;
  filePath = path.join(__dirname, filePath);
  if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end('Forbidden'); return; }

  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const mime = MIME[path.extname(filePath)] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });

}).listen(PORT, '0.0.0.0', () => console.log('Ready on port ' + PORT));
