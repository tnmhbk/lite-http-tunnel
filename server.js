const http = require('http');
const { v4: uuidV4 } = require('uuid');
const express = require('express');
const morgan = require('morgan');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const path = require('path');

require('dotenv').config();

const { TunnelRequest, TunnelResponse } = require('./lib');

const app = express();
const httpServer = http.createServer(app);

// 1️⃣ Socket.IO instance cho dashboard (mặc định path: /socket.io)
const ioDashboard = new Server(httpServer, { cors: { origin: '*' }, path: '/dashboard-socket' });

// 2️⃣ Socket.IO instance cho tunnel client (path: /$web_tunnel)
const ioTunnel = new Server(httpServer, {
  path: '/$web_tunnel',
  maxHttpBufferSize: 1e8,
  cors: { origin: '*' },
});

require('events').defaultMaxListeners = 30;

// 🌟 Gửi log tới dashboard
function emitLog(msg, type = 'info') {
  console.log(msg);
  ioDashboard.emit('proxy-log', {
    time: new Date().toISOString(),
    message: msg,
    type,
  });
}

// Dashboard HTML
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Dashboard socket.io
ioDashboard.on('connection', (socket) => {
  console.log('📡 Dashboard client connected');
  socket.on('disconnect', () => console.log('❌ Dashboard client disconnected'));
});

// Tunnels
let tunnelSockets = [];

function getTunnelSocket(host, pathPrefix) {
  return tunnelSockets.find((s) => s.host === host && s.pathPrefix === pathPrefix);
}

function setTunnelSocket(host, pathPrefix, socket) {
  emitLog(`ℹ️ Adding tunnel for ${host}, prefix: ${pathPrefix}`);
  tunnelSockets.push({ host, pathPrefix, socket });
}

function removeTunnelSocket(host, pathPrefix) {
  emitLog(`ℹ️ Removing tunnel for ${host}, prefix: ${pathPrefix}`);
  tunnelSockets = tunnelSockets.filter((s) => !(s.host === host && s.pathPrefix === pathPrefix));
}

function getAvailableTunnelSocket(host, url) {
  const tunnels = tunnelSockets
    .filter((s) => {
      if (s.host !== host) return false;
      if (!s.pathPrefix) return true;
      return url.indexOf(s.pathPrefix) === 0;
    })
    .sort((a, b) => (!a.pathPrefix ? 1 : !b.pathPrefix ? -1 : b.pathPrefix.length - a.pathPrefix.length));
  emitLog(`🔎 Matching tunnel for host=${host}, url=${url}: ${tunnels.length} found`);
  return tunnels[0]?.socket || null;
}

// JWT Auth for tunnel
ioTunnel.use((socket, next) => {
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  emitLog(`🔑 Auth attempt for ${connectHost}, prefix=${pathPrefix}`);
  if (getTunnelSocket(connectHost, pathPrefix)) {
    emitLog(`❌ Reject: ${connectHost} already connected`, 'error');
    return next(new Error(`${connectHost} already has a connection`));
  }
  const token = socket.handshake.auth?.token;
  if (!token) {
    emitLog('❌ Reject: Missing token', 'error');
    return next(new Error('Authentication error'));
  }
  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err || decoded.token !== process.env.VERIFY_TOKEN) {
      emitLog('❌ Reject: Invalid token', 'error');
      return next(new Error('Authentication error'));
    }
    emitLog('✅ Auth success');
    next();
  });
});

// Tunnel socket.io connection
ioTunnel.on('connection', (socket) => {
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  setTunnelSocket(connectHost, pathPrefix, socket);
  emitLog(`✅ Client connected: ${connectHost}, prefix=${pathPrefix}`);
  socket.on('message', (msg) => emitLog(`💬 [${connectHost}] ${msg}`));
  socket.once('disconnect', (reason) => {
    emitLog(`⚠️ Client disconnected: ${reason}`);
    removeTunnelSocket(connectHost, pathPrefix);
  });
});

// JWT endpoint
app.use(morgan('tiny'));
app.get('/tunnel_jwt_generator', (req, res) => {
  process.env.JWT_GENERATOR_USERNAME = 'admin';
  process.env.JWT_GENERATOR_PASSWORD = 'admin';
  process.env.VERIFY_TOKEN = '123456';
  process.env.SECRET_KEY = '123456';
  emitLog('🔑 JWT generator called');

  if (!req.query.username || !req.query.password) {
    emitLog('❌ Missing credentials in JWT generator', 'error');
    return res.status(401).send('Forbidden');
  }
  if (req.query.username === process.env.JWT_GENERATOR_USERNAME && req.query.password === process.env.JWT_GENERATOR_PASSWORD) {
    const jwtToken = jwt.sign({ token: process.env.VERIFY_TOKEN }, process.env.SECRET_KEY);
    emitLog('✅ JWT issued');
    return res.status(200).send(jwtToken);
  }
  emitLog('❌ Invalid credentials', 'error');
  res.status(401).send('Forbidden');
});

// Helper
function getReqHeaders(req) {
  const encrypted = !!(req.isSpdy || req.connection.encrypted || req.connection.pair);
  const headers = { ...req.headers };
  const url = new URL(`${encrypted ? 'https' : 'http'}://${req.headers.host}`);
  const forwardValues = {
    for: req.connection.remoteAddress || req.socket.remoteAddress,
    port: url.port || (encrypted ? 443 : 80),
    proto: encrypted ? 'https' : 'http',
  };
  ['for', 'port', 'proto'].forEach((key) => {
    const prev = req.headers[`x-forwarded-${key}`] || '';
    headers[`x-forwarded-${key}`] = `${prev ? prev + ',' : ''}${forwardValues[key]}`;
  });
  headers['x-forwarded-host'] = req.headers['x-forwarded-host'] || req.headers.host || '';
  return headers;
}

// Main tunnel handler
app.use('/', (req, res) => {
  emitLog(`🌐 HTTP ${req.method}: ${req.url}`);
  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) {
    emitLog('❌ No tunnel socket found', 'error');
    return res.status(404).send('Not Found');
  }

  const requestId = uuidV4();
  const tunnelRequest = new TunnelRequest({ socket: tunnelSocket, requestId, request: {
    method: req.method, headers: getReqHeaders(req), path: req.url
  }});

  const onReqError = (e) => {
    emitLog('❌ Request error: ' + e, 'error');
    tunnelRequest.destroy(new Error(e || 'Aborted'));
  };
  req.once('aborted', onReqError);
  req.once('error', onReqError);
  req.pipe(tunnelRequest);
  req.once('finish', () => {
    req.off('aborted', onReqError);
    req.off('error', onReqError);
  });

  const tunnelResponse = new TunnelResponse({ socket: tunnelSocket, responseId: requestId });
  tunnelResponse.once('requestError', () => {
    emitLog('❌ Tunnel request error', 'error');
    res.status(502).end('Request error');
  });
  tunnelResponse.once('response', ({ statusCode, statusMessage, headers }) => {
    emitLog(`↩️ Response: ${statusCode} ${statusMessage}`);
    res.writeHead(statusCode, statusMessage, headers);
  });
  tunnelResponse.pipe(res);
});

// Start server
httpServer.listen(process.env.PORT || 3000, () => {
  emitLog(`🚀 Server started at http://localhost:${process.env.PORT || 3000}`);
});
