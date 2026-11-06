
const express = require("express");
const http = require("http");
const crypto = require("crypto");
const WebSocket = require("ws");

const app = express();
const server = http.createServer(app);

const wss = new WebSocket.Server({
  noServer: true,
  maxPayload: 65536
});

app.use(express.json({ limit: "2kb" }));

app.use((req, res, next) => {
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
});

app.get("/", (req, res) =>
  res.sendFile(__dirname + "/index.html")
);

app.get("/viewer.html", (req, res) =>
  res.sendFile(__dirname + "/viewer.html")
);

app.get("/health", (req, res) =>
  res.json({ status: "running" })
);

const sessions = new Map();
const tokens = new Map();

const OWNER_SECRET = process.env.OWNER_SECRET;
const SESSION_LENGTH = 30 * 60 * 1000;

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function secretMatches(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return x.length === y.length &&
    crypto.timingSafeEqual(x, y);
}

app.post("/api/invitations", (req, res) => {
  if (!OWNER_SECRET) {
    return res.status(503).json({
      error: "Server authentication is not configured"
    });
  }

  const supplied = req.get("x-owner-secret") || "";

  if (!secretMatches(supplied, OWNER_SECRET)) {
    return res.status(403).json({
      error: "Not authorised"
    });
  }

  const id = crypto.randomUUID();
  const inviteToken = randomToken();
  const viewerToken = randomToken();

  const session = {
    expires: Date.now() + SESSION_LENGTH,
    grandpa: null,
    viewer: null
  };

  sessions.set(id, session);

  tokens.set(inviteToken, {
    id,
    role: "grandpa"
  });

  tokens.set(viewerToken, {
    id,
    role: "viewer"
  });

  const protocol =
    req.get("x-forwarded-proto") || "https";

  const base = `${protocol}://${req.get("host")}`;

  res.setHeader("Cache-Control", "no-store");

  res.json({
    grandpaUrl: `${base}/?invite=${inviteToken}`,
    viewerUrl: `${base}/viewer.html?token=${viewerToken}`,
    expiresInMinutes: 30
  });
});

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "https://localhost");

  if (url.pathname !== "/ws") {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, ws => {
    wss.emit("connection", ws, req);
  });
});

wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "https://localhost");
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

  if (session[role]) {
    ws.close(1008, "Already connected");
    return;
  }

  // Each invitation credential can only be used once.
  tokens.delete(token);
  session[role] = ws;

  const otherRole =
    role === "viewer" ? "grandpa" : "viewer";

  if (session[otherRole]) {
    session.viewer.send(JSON.stringify({ type: "paired" }));
    session.grandpa.send(JSON.stringify({ type: "paired" }));
  } else {
    ws.send(JSON.stringify({ type: "waiting" }));
  }

  ws.on("message", raw => {
    if (Date.now() > session.expires) {
      ws.close(1008, "Session expired");
      return;
    }

    try {
      const message = JSON.parse(raw.toString());

      if (!["offer", "answer", "candidate"].includes(message.type)) {
        return;
      }

      const recipient = session[otherRole];

      if (recipient && recipient.readyState === WebSocket.OPEN) {
        recipient.send(JSON.stringify({
          type: message.type,
          data: message.data
        }));
      }
    } catch {
      ws.close(1008, "Invalid message");
    }
  });

  ws.on("close", () => {
    const recipient = session[otherRole];

    if (recipient && recipient.readyState === WebSocket.OPEN) {
      recipient.send(JSON.stringify({ type: "ended" }));
      recipient.close();
    }

    sessions.delete(access.id);
  });
});

setInterval(() => {
  for (const [id, session] of sessions) {
    if (Date.now() > session.expires) {
      for (const ws of [session.viewer, session.grandpa]) {
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "expired" }));
          ws.close();
        }
      }

      sessions.delete(id);

      for (const [token, value] of tokens) {
        if (value.id === id) tokens.delete(token);
      }
    }
  }
}, 30000);

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log("Grandpa Connect server started");
});
