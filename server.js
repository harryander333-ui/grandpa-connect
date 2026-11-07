
const express = require("express");
const http = require("http");
const crypto = require("crypto");
const WebSocket = require("ws");
const path = require("path");

const app = express();
app.set("trust proxy", 1);
const server = http.createServer(app);
const wss = new WebSocket.Server({
  noServer: true,
  maxPayload: 65536
});

app.use(express.json({ limit: "2kb" }));

app.use((req, res, next) => {
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");
  next();
});

for (const [route, file] of [
  ["/", "index.html"],
  ["/viewer.html", "viewer.html"],
  ["/dashboard.html", "dashboard.html"]
]) {
  app.get(route, (req, res) => {
    res.sendFile(path.join(__dirname, file));
  });
}

app.get("/health", (req, res) => {
  res.json({ status: "running" });
});

// XIRSYS TURN CONFIGURATION
const defaultIce = [
  { urls: "stun:stun.l.google.com:19302" }
];

async function getIceServers() {
  const ident = process.env.XIRSYS_IDENT;
  const secret = process.env.XIRSYS_SECRET;
  const channel = process.env.XIRSYS_CHANNEL;

  if (!ident || !secret || !channel) {
    console.warn("Xirsys not configured");
    return defaultIce;
  }

  try {
    const auth = Buffer.from(
      `${ident}:${secret}`
    ).toString("base64");

    const url =
      "https://global.xirsys.net/_turn/" +
      encodeURIComponent(channel) +
      "?webrtc=1&expire=3600";

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: "Basic " + auth
      },
      signal: AbortSignal.timeout(10000)
    });

    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const result = await response.json();

    if (
      result.s !== "ok" ||
      !Array.isArray(result.v?.iceServers) ||
      result.v.iceServers.length === 0
    ) {
      throw new Error("Invalid Xirsys response");
    }

    console.log("Xirsys TURN ready");
    return [...defaultIce, ...result.v.iceServers];

  } catch (error) {
    console.error("Xirsys error:", error.message);
    return defaultIce;
  }
}

// SESSION MANAGEMENT
const sessions = new Map();
const tokens = new Map();
const failures = new Map();

const INVITE_LENGTH = 30 * 60 * 1000;
const CALL_LENGTH = 2 * 60 * 60 * 1000;

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function secretMatches(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return x.length === y.length &&
    crypto.timingSafeEqual(x, y);
}

function isBlocked(ip) {
  const rec = failures.get(ip);
  return rec &&
    Date.now() < rec.reset &&
    rec.count >= 10;
}

function recordFailure(ip) {
  const now = Date.now();
  let rec = failures.get(ip);

  if (!rec || now > rec.reset) {
    rec = {
      count: 0,
      reset: now + 60000
    };
  }

  rec.count++;
  failures.set(ip, rec);
}

function safeSend(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function cleanupSession(id) {
  sessions.delete(id);

  for (const [key, value] of tokens) {
    if (value.id === id) {
      tokens.delete(key);
    }
  }
}

// CREATE INVITATIONS
app.post("/api/invitations", (req, res) => {
  const ownerSecret = process.env.OWNER_SECRET;

  if (!ownerSecret) {
    return res.status(503).json({
      error: "Set OWNER_SECRET in Render"
    });
  }

  if (isBlocked(req.ip)) {
    return res.status(429).json({
      error: "Too many attempts. Try again later."
    });
  }

  const supplied = req.get("x-owner-secret") || "";

  if (!secretMatches(supplied, ownerSecret)) {
    recordFailure(req.ip);

    return res.status(403).json({
      error: "Wrong secret"
    });
  }

  const id = crypto.randomUUID();
  const inviteToken = randomToken();
  const viewerToken = randomToken();

  sessions.set(id, {
    expires: Date.now() + INVITE_LENGTH,
    grandpa: null,
    viewer: null,
    iceServers: null
  });

  tokens.set(inviteToken, {
    id,
    role: "grandpa"
  });

  tokens.set(viewerToken, {
    id,
    role: "viewer"
  });

  const proto = (
    req.get("x-forwarded-proto") ||
    req.protocol ||
    "https"
  ).split(",")[0].trim();

  const base = `${proto}://${req.get("host")}`;

  res.json({
    grandpaUrl: `${base}/?invite=${inviteToken}`,
    viewerUrl:
      `${base}/viewer.html?token=${viewerToken}`,
    expiresInMinutes: 30
  });
});

// WEBSOCKET CONNECTION
server.on("upgrade", (req, socket, head) => {
  let url;

  try {
    url = new URL(req.url, "https://localhost");
  } catch {
    socket.destroy();
    return;
  }

  if (url.pathname !== "/ws") {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, ws => {
    wss.emit("connection", ws, req);
  });
});

wss.on("connection", async (ws, req) => {
  ws.isAlive = true;

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  const url = new URL(
    req.url,
    "https://localhost"
  );

  const token = url.searchParams.get("token");
  const access = tokens.get(token);

  if (!access) {
    ws.close(1008, "Invalid invitation");
    return;
  }

  const session = sessions.get(access.id);

  if (!session || Date.now() > session.expires) {
    tokens.delete(token);
    ws.close(1008, "Invitation expired");
    return;
  }

  const role = access.role;
  const otherRole =
    role === "viewer" ? "grandpa" : "viewer";

  if (session[role]) {
    ws.close(1008, "Already connected");
    return;
  }

  // Obtain TURN configuration for the session.
  if (!session.iceServers) {
    session.iceServers = await getIceServers();
  }

  // Check again after the asynchronous request.
  if (
    ws.readyState !== WebSocket.OPEN ||
    sessions.get(access.id) !== session ||
    Date.now() > session.expires ||
    session[role]
  ) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1008, "Session unavailable");
    }
    return;
  }

  tokens.delete(token);
  session[role] = ws;

  // Send TURN settings before pairing.
  safeSend(ws, {
    type: "config",
    data: {
      iceServers: session.iceServers
    }
  });

  if (session[otherRole]) {
    session.expires = Date.now() + CALL_LENGTH;

    safeSend(session.viewer, {
      type: "paired"
    });

    safeSend(session.grandpa, {
      type: "paired"
    });
  } else {
    safeSend(ws, {
      type: "waiting"
    });
  }

  ws.on("message", raw => {
    if (Date.now() > session.expires) {
      ws.close(1008, "Session expired");
      return;
    }

    try {
      const message = JSON.parse(raw.toString());

      if (![
        "offer",
        "answer",
        "candidate"
      ].includes(message.type)) {
        return;
      }

      safeSend(session[otherRole], {
        type: message.type,
        data: message.data
      });
    } catch {
      ws.close(1008, "Invalid message");
    }
  });

  ws.on("close", () => {
    if (session[role] !== ws) return;

    const recipient = session[otherRole];

    if (
      recipient &&
      recipient.readyState === WebSocket.OPEN
    ) {
      safeSend(recipient, { type: "ended" });
      recipient.close();
    }

    cleanupSession(access.id);
  });
});

// WEBSOCKET HEARTBEAT
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }

    ws.isAlive = false;
    ws.ping();
  }
}, 25000);

// EXPIRE OLD SESSIONS
setInterval(() => {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (now > session.expires) {
      for (const ws of [
        session.viewer,
        session.grandpa
      ]) {
        if (
          ws &&
          ws.readyState === WebSocket.OPEN
        ) {
          safeSend(ws, { type: "expired" });
          ws.close(1008, "Session expired");
        }
      }

      cleanupSession(id);
    }
  }

  for (const [ip, rec] of failures) {
    if (now > rec.reset) {
      failures.delete(ip);
    }
  }
}, 30000);

// START SERVER
const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    "Grandpa Connect running on port " + PORT
  );
});
