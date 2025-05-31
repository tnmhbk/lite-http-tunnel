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
const webTunnelPath = '/$web_tunnel';
const io = new Server(httpServer, {
  path: webTunnelPath,
  maxHttpBufferSize: 1e8,
  cors: {
    origin: '*', // Cho phép dashboard kết nối
  },
});

// Increase max listeners to avoid warning
require('events').defaultMaxListeners = 30;

// Dashboard Socket.IO namespace
const dashboardIO = io.of('/dashboard-logs');
function emitLog(msg, type = 'info') {
  console.log(msg);
  dashboardIO.emit('proxy-log', {
    time: new Date().toISOString(),
    message: msg,
    type,
  });
}

const clientDir = path.dirname(require.resolve('socket.io-client')) + '/dist';
app.use('/socket.io', express.static(clientDir));

// Dashboard HTML
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Dashboard Socket.IO handlers
dashboardIO.on('connection', (socket) => {
  console.log('📡 Dashboard client connected!');
  socket.on('disconnect', () => console.log('❌ Dashboard client disconnected'));
});

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
  emitLog('tunnelSockets: ' + tunnelSockets.map((s) => s.host + (s.pathPrefix || '')).join(', '));
}

function getAvailableTunnelSocket(host, url) {
  const tunnels = tunnelSockets
    .filter((s) => {
      if (s.host !== host) return false;
      if (!s.pathPrefix) return true;
      return url.indexOf(s.pathPrefix) === 0;
    })
    .sort((a, b) => {
      if (!a.pathPrefix) return 1;
      if (!b.pathPrefix) return -1;
      return b.pathPrefix.length - a.pathPrefix.length;
    });
  emitLog(`🔎 Matching tunnel for host=${host}, url=${url}: ${tunnels.length} found`);
  return tunnels[0]?.socket || null;
}

// JWT authentication
io.use((socket, next) => {
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  emitLog(`🔑 Auth attempt for ${connectHost}, pathPrefix=${pathPrefix}`);

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

io.on('connection', (socket) => {
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  setTunnelSocket(connectHost, pathPrefix, socket);
  emitLog(`✅ Client connected: ${connectHost}, prefix=${pathPrefix}`);

  const onMessage = (message) => {
    emitLog(`💬 [${connectHost}] Message: ${message}`);
    if (message === 'ping') {
      socket.send('pong');
    }
  };
  const onDisconnect = (reason) => {
    emitLog(`⚠️ Client disconnected (${connectHost}, prefix=${pathPrefix}): ${reason}`);
    removeTunnelSocket(connectHost, pathPrefix);
  };

  socket.on('message', onMessage);
  socket.once('disconnect', onDisconnect);
});

// JWT generator endpoint
app.use(morgan('tiny'));
app.get('/tunnel_jwt_generator', (req, res) => {
  emitLog('🔑 JWT generator called');
  process.env.JWT_GENERATOR_USERNAME = 'admin';
  process.env.JWT_GENERATOR_PASSWORD = 'admin';
  process.env.VERIFY_TOKEN = '123456';
  process.env.SECRET_KEY = '123456';

  if (!req.query.username || !req.query.password) {
    emitLog('❌ Missing credentials in JWT generator', 'error');
    return res.status(401).send('Forbidden');
  }

  if (
    req.query.username === process.env.JWT_GENERATOR_USERNAME &&
    req.query.password === process.env.JWT_GENERATOR_PASSWORD
  ) {
    const jwtToken = jwt.sign({ token: process.env.VERIFY_TOKEN }, process.env.SECRET_KEY);
    emitLog('✅ JWT issued');
    return res.status(200).send(jwtToken);
  }
  emitLog('❌ Invalid credentials in JWT generator', 'error');
  res.status(401).send('Forbidden');
});

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

app.get('/tunnels', (req, res) => {
  res.json(tunnelSockets.map((s) => ({
    host: s.host,
    pathPrefix: s.pathPrefix,
    connected: s.socket.connected,
  })));
});

app.use('/', (req, res) => {
  emitLog(`🌐 HTTP ${req.method}: ${req.url}`);
  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) {
    emitLog('❌ No tunnel socket found', 'error');
    return res.status(404).send('Not Found');
  }

  const requestId = uuidV4();
  const tunnelRequest = new TunnelRequest({
    socket: tunnelSocket,
    requestId,
    request: {
      method: req.method,
      headers: getReqHeaders(req),
      path: req.url,
    },
  });

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

  const tunnelResponse = new TunnelResponse({
    socket: tunnelSocket,
    responseId: requestId,
  });

  const onRequestError = () => {
    emitLog('❌ Tunnel request error', 'error');
    tunnelResponse.off('response', onResponse);
    tunnelResponse.destroy();
    res.status(502).end('Request error');
  };
  const onResponse = ({ statusCode, statusMessage, headers }) => {
    emitLog(`↩️ Response: ${statusCode} ${statusMessage}`);
    tunnelRequest.off('requestError', onRequestError);
    res.writeHead(statusCode, statusMessage, headers);
  };

  tunnelResponse.once('requestError', onRequestError);
  tunnelResponse.once('response', onResponse);
  tunnelResponse.pipe(res);

  const onSocketError = () => {
    emitLog('❌ Tunnel socket disconnect', 'error');
    res.off('close', onResClose);
    res.status(500).end();
  };
  const onResClose = () => {
    emitLog('ℹ️ Response closed');
    tunnelSocket.off('disconnect', onSocketError);
  };

  tunnelSocket.once('disconnect', onSocketError);
  res.once('close', onResClose);
});

httpServer.listen(process.env.PORT || 3000, () => {
  emitLog(`🚀 Server started at http://localhost:${process.env.PORT || 3000}`);
});
