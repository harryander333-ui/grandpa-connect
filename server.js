const express = require('express');
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const WebSocket = require('ws');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2kb' }));
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});
for (const [url, file] of [['/', 'index.html'], ['/viewer.html', 'viewer.html'], ['/dashboard.html', 'dashboard.html']]) {
  app.get(url, (_req, res) => res.sendFile(path.join(__dirname, file)));
}
app.get('/health', (_req, res) => res.json({ status: 'running' }));

const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true, maxPayload: 65536 });
const sessions = new Map();
const tokens = new Map();
const failures = new Map();
const INVITE_MS = 30 * 60 * 1000;
const SESSION_MS = 2 * 60 * 60 * 1000;
const RECONNECT_MS = 2 * 60 * 1000;
const fallbackIce = [{ urls: 'stun:stun.l.google.com:19302' }];

const randomToken = () => crypto.randomBytes(32).toString('base64url');
function safeSend(ws, message) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message));
}
function constantTimeMatch(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
async function loadIce() {
  const { XIRSYS_IDENT: ident, XIRSYS_SECRET: secret, XIRSYS_CHANNEL: channel } = process.env;
  if (ident && secret && channel) {
    try {
      const authorization = Buffer.from(`${ident}:${secret}`).toString('base64');
      const response = await fetch(`https://global.xirsys.net/_turn/${encodeURIComponent(channel)}?webrtc=1&expire=3600`, {
        method: 'PUT', headers: { Authorization: `Basic ${authorization}` }, signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (result.s !== 'ok' || !Array.isArray(result.v?.iceServers) || !result.v.iceServers.length) {
        throw new Error('Invalid TURN response');
      }
      console.log('Xirsys TURN ready');
      return [...fallbackIce, ...result.v.iceServers];
    } catch (error) {
      console.error('Xirsys error:', error.message);
    }
  } else if (process.env.ICE_SERVERS_JSON) {
    try { return JSON.parse(process.env.ICE_SERVERS_JSON); }
    catch { console.error('Invalid ICE_SERVERS_JSON'); }
  } else {
    console.warn('TURN not configured; using STUN only');
  }
  return fallbackIce;
}
function endSession(id, reason = 'ended') {
  const session = sessions.get(id);
  if (!session) return;
  sessions.delete(id);
  for (const [token, entry] of tokens) if (entry.id === id) tokens.delete(token);
  for (const ws of [session.grandpa, session.viewer]) {
    safeSend(ws, { type: reason });
    if (ws && ws.readyState === WebSocket.OPEN) ws.close(1000, 'Session ended');
  }
}
function isBlocked(ip) {
  const entry = failures.get(ip);
  return entry && entry.count >= 10 && Date.now() < entry.reset;
}
function markFailure(ip) {
  const now = Date.now();
  const entry = failures.get(ip);
  failures.set(ip, (!entry || now > entry.reset)
    ? { count: 1, reset: now + 60000 }
    : { count: entry.count + 1, reset: entry.reset });
}

app.post('/api/invitations', (req, res) => {
  if (!process.env.OWNER_SECRET) return res.status(503).json({ error: 'Set OWNER_SECRET in Render' });
  if (isBlocked(req.ip)) return res.status(429).json({ error: 'Too many attempts. Try again shortly.' });
  if (!constantTimeMatch(req.get('x-owner-secret') || '', process.env.OWNER_SECRET)) {
    markFailure(req.ip);
    return res.status(403).json({ error: 'Wrong secret' });
  }
  const id = crypto.randomUUID();
  const grandpaToken = randomToken();
  const viewerToken = randomToken();
  sessions.set(id, {
    grandpa: null, viewer: null, expires: Date.now() + INVITE_MS,
    started: false, hadBoth: false, missingSince: null,
    ice: null, iceCreated: 0, refreshing: null, lastRestart: 0
  });
  tokens.set(grandpaToken, { id, role: 'grandpa' });
  tokens.set(viewerToken, { id, role: 'viewer' });
  const protocol = (req.get('x-forwarded-proto') || req.protocol).split(',')[0].trim();
  const base = `${protocol}://${req.get('host')}`;
  res.json({
    grandpaUrl: `${base}/?invite=${grandpaToken}`,
    viewerUrl: `${base}/viewer.html?token=${viewerToken}`,
    expiresInMinutes: 30
  });
});

server.on('upgrade', (req, socket, head) => {
  let url;
  try { url = new URL(req.url, 'https://localhost'); }
  catch { socket.destroy(); return; }
  if (url.pathname !== '/ws') { socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});
function getIce(session, force = false) {
  if (session.refreshing) return session.refreshing;
  if (!force && session.ice && Date.now() - session.iceCreated < 45 * 60 * 1000) {
    return Promise.resolve(session.ice);
  }
  session.refreshing = loadIce().then(ice => {
    session.ice = ice;
    session.iceCreated = Date.now();
    return ice;
  }).finally(() => { session.refreshing = null; });
  return session.refreshing;
}
function notifyPaired(session) {
  if (!session.grandpa || !session.viewer) return;
  session.missingSince = null;
  if (!session.started) {
    session.started = true;
    session.expires = Date.now() + SESSION_MS;
  }
  session.hadBoth = true;
  safeSend(session.viewer, { type: 'paired' });
  safeSend(session.grandpa, { type: 'paired' });
}
wss.on('connection', async (ws, req) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  const url = new URL(req.url, 'https://localhost');
  const access = tokens.get(url.searchParams.get('token'));
  if (!access) { ws.close(1008, 'Invalid link'); return; }
  const session = sessions.get(access.id);
  if (!session || Date.now() > session.expires ||
      (session.missingSince && Date.now() - session.missingSince > RECONNECT_MS)) {
    ws.close(1008, 'Session expired'); return;
  }
  const role = access.role;
  const other = role === 'viewer' ? 'grandpa' : 'viewer';
  // Reject simultaneous logins rather than silently stealing an active connection.
  if (session[role]) { ws.close(1008, 'Already connected'); return; }
  let ice;
  try { ice = await getIce(session); }
  catch { ws.close(1011, 'TURN unavailable'); return; }
  if (ws.readyState !== WebSocket.OPEN || sessions.get(access.id) !== session || session[role]) {
    if (ws.readyState === WebSocket.OPEN) ws.close(1008, 'Unavailable');
    return;
  }
  session[role] = ws;
  safeSend(ws, { type: 'config', data: { iceServers: ice } });
  if (session[other]) notifyPaired(session);
  else safeSend(ws, { type: 'waiting' });

  ws.on('message', async raw => {
    if (sessions.get(access.id) !== session || session[role] !== ws) return;
    if (Date.now() > session.expires) { endSession(access.id, 'expired'); return; }
    let message;
    try { message = JSON.parse(raw.toString()); }
    catch { ws.close(1008, 'Invalid message'); return; }
    if (message.type === 'end') { endSession(access.id); return; }
    if (message.type === 'restart') {
      if (!session[other] || Date.now() - session.lastRestart < 5000) return;
      session.lastRestart = Date.now();
      const newIce = await getIce(session);
      if (sessions.get(access.id) !== session) return;
      for (const client of [session.viewer, session.grandpa]) {
        safeSend(client, { type: 'config', data: { iceServers: newIce } });
        safeSend(client, { type: 'paired' });
      }
      return;
    }
    if (['offer', 'answer', 'candidate'].includes(message.type) && message.data) {
      safeSend(session[other], { type: message.type, data: message.data });
    }
  });
  ws.on('close', () => {
    if (session[role] !== ws || sessions.get(access.id) !== session) return;
    session[role] = null;
    if (!session.missingSince) session.missingSince = Date.now();
    safeSend(session[other], { type: 'peer-left' });
  });
});
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 25000);
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now > session.expires ||
        (session.missingSince && now - session.missingSince > RECONNECT_MS)) {
      endSession(id, 'expired');
    }
  }
  for (const [ip, entry] of failures) if (now > entry.reset) failures.delete(ip);
}, 5000);
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log(`Grandpa Connect running on port ${PORT}`));
