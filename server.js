
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.get("/", (req, res) => {
  res.send("Grandpa Connect server is running ❤️");
});

const sessions = new Map();

function makeCode() {
  return crypto.randomBytes(4).toString("hex");
}

wss.on("connection", (ws) => {
  let currentSession = null;
  let role = null;

  ws.on("message", (raw) => {
    try {
      const message = JSON.parse(raw);

      if (message.type === "create") {
        if (role) return;

        const code = makeCode();
        sessions.set(code, { viewer: ws, grandpa: null });

        currentSession = code;
        role = "viewer";

        ws.send(JSON.stringify({
          type: "created",
          code
        }));
        return;
      }

      if (message.type === "join") {
        if (role || typeof message.code !== "string") return;

        const code = message.code.toLowerCase();
        const session = sessions.get(code);

        if (!session || session.grandpa) {
          ws.send(JSON.stringify({ type: "unavailable" }));
          return;
        }

        currentSession = code;
        role = "grandpa";
        session.grandpa = ws;

        session.viewer.send(JSON.stringify({
          type: "grandpa-joined"
        }));
        return;
      }

      if (!currentSession || !role) return;

      const session = sessions.get(currentSession);
      if (!session) return;

      const recipient =
        role === "viewer" ? session.grandpa : session.viewer;

      if (recipient && recipient.readyState === WebSocket.OPEN) {
        if (["offer", "answer", "candidate", "leave"].includes(message.type)) {
          recipient.send(JSON.stringify({
            type: message.type,
            data: message.data ?? null
          }));
        }
      }
    } catch {
      ws.send(JSON.stringify({ type: "error" }));
    }
  });

  ws.on("close", () => {
    if (!currentSession) return;

    const session = sessions.get(currentSession);
    if (!session) return;

    const other =
      role === "viewer" ? session.grandpa : session.viewer;

    if (other && other.readyState === WebSocket.OPEN) {
      other.send(JSON.stringify({ type: "leave" }));
    }

    sessions.delete(currentSession);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Grandpa Connect running on port ${PORT}`);
});
