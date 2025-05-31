require('dotenv').config();
const http = require('http');
const express = require('express');
const morgan = require('morgan');
const { v4: uuidV4 } = require('uuid');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const path = require('path');
const { TunnelRequest, TunnelResponse } = require('./lib');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  path: '/$web_tunnel',
  maxHttpBufferSize: 1e8
});

// Realtime log to dashboard
const originalLog = console.log;
const originalErr = console.error;
function emitLog(message, type = 'log') {
  io.emit('proxy-log', { time: new Date().toISOString(), type, message });
}
console.log = (...args) => {
  originalLog(...args);
  emitLog(args.join(' '));
};
console.error = (...args) => {
  originalErr(...args);
  emitLog(args.join(' '), 'error');
};

require('events').defaultMaxListeners = 30;
let tunnelSockets = [];

function getTunnelSocket(host, pathPrefix) {
  return tunnelSockets.find(s => s.host === host && s.pathPrefix === pathPrefix);
}
function setTunnelSocket(host, pathPrefix, socket) {
  tunnelSockets.push({ host, pathPrefix, socket });
}
function removeTunnelSocket(host, pathPrefix) {
  tunnelSockets = tunnelSockets.filter(s => !(s.host === host && s.pathPrefix === pathPrefix));
}
function getAvailableTunnelSocket(host, url) {
  return tunnelSockets
    .filter(s => s.host === host && (!s.pathPrefix || url.startsWith(s.pathPrefix)))
    .sort((a, b) => (b.pathPrefix?.length || 0) - (a.pathPrefix?.length || 0))[0]?.socket || null;
}

io.use((socket, next) => {
  const host = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  const token = socket.handshake.auth?.token;

  if (getTunnelSocket(host, pathPrefix)) {
    return next(new Error('Tunnel already connected'));
  }
  if (!token) return next(new Error('No token'));

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err || decoded.token !== process.env.VERIFY_TOKEN) {
      return next(new Error('Auth error'));
    }
    next();
  });
});

io.on('connection', socket => {
  const host = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  setTunnelSocket(host, pathPrefix, socket);

  socket.on('message', msg => {
    if (msg === 'ping') socket.send('pong');
  });
  socket.once('disconnect', () => {
    removeTunnelSocket(host, pathPrefix);
  });
});

// Dashboard
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});
app.use(morgan('tiny'));

// JWT generator
app.get('/tunnel_jwt_generator', (req, res) => {
  const { username, password } = req.query;
  if (username === 'admin' && password === 'admin') {
    const jwtToken = jwt.sign({ token: process.env.VERIFY_TOKEN }, process.env.SECRET_KEY);
    return res.send(jwtToken);
  }
  res.status(401).send('Forbidden');
});

// API list active tunnels
app.get('/tunnels', (req, res) => {
  res.json(tunnelSockets.map(s => ({
    host: s.host,
    pathPrefix: s.pathPrefix,
    connected: s.socket.connected
  })));
});

// Proxy logic
function getReqHeaders(req) {
  const encrypted = !!(req.connection.encrypted || req.isSpdy || req.connection.pair);
  const headers = { ...req.headers };
  const url = new URL(`${encrypted ? 'https' : 'http'}://${req.headers.host}`);
  const forwarded = {
    for: req.connection.remoteAddress || req.socket.remoteAddress,
    port: url.port || (encrypted ? 443 : 80),
    proto: encrypted ? 'https' : 'http'
  };
  ['for', 'port', 'proto'].forEach(key => {
    const prev = req.headers[`x-forwarded-${key}`] || '';
    headers[`x-forwarded-${key}`] = prev ? `${prev},${forwarded[key]}` : forwarded[key];
  });
  headers['x-forwarded-host'] = req.headers['x-forwarded-host'] || req.headers.host || '';
  return headers;
}

app.use('/', (req, res) => {
  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) return res.status(404).send('Not Found');

  const requestId = uuidV4();
  const tunnelRequest = new TunnelRequest({
    socket: tunnelSocket,
    requestId,
    request: {
      method: req.method,
      headers: getReqHeaders(req),
      path: req.url
    }
  });
  req.once('aborted', () => tunnelRequest.destroy(new Error('Aborted')));
  req.once('error', err => tunnelRequest.destroy(err));
  req.pipe(tunnelRequest);

  const tunnelResponse = new TunnelResponse({ socket: tunnelSocket, responseId: requestId });
  tunnelResponse.once('response', ({ statusCode, statusMessage, headers }) => {
    res.writeHead(statusCode, statusMessage, headers);
  });
  tunnelResponse.once('requestError', () => {
    res.status(502).end('Tunnel error');
  });
  tunnelResponse.pipe(res);

  io.emit('proxy-log', {
    type: 'HTTP',
    method: req.method,
    url: req.url,
    time: new Date().toISOString()
  });
});

// WS upgrade
function createSocketHttpHeader(line, headers) {
  return Object.keys(headers).reduce((arr, key) => {
    const value = headers[key];
    if (Array.isArray(value)) value.forEach(v => arr.push(`${key}: ${v}`));
    else arr.push(`${key}: ${value}`);
    return arr;
  }, [line]).join('\r\n') + '\r\n\r\n';
}
server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/$web_tunnel')) return;
  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) return;

  if (head?.length) socket.unshift(head);
  const requestId = uuidV4();
  const tunnelRequest = new TunnelRequest({
    socket: tunnelSocket,
    requestId,
    request: {
      method: req.method,
      headers: getReqHeaders(req),
      path: req.url
    }
  });
  req.pipe(tunnelRequest);

  const tunnelResponse = new TunnelResponse({ socket: tunnelSocket, responseId: requestId });
  tunnelResponse.once('response', ({ statusCode, statusMessage, headers, httpVersion }) => {
    socket.write(createSocketHttpHeader(`HTTP/${httpVersion} ${statusCode} ${statusMessage}`, headers));
    tunnelResponse.pipe(socket).pipe(tunnelResponse);
  });
  tunnelResponse.once('requestError', () => {
    socket.end();
  });
  io.emit('proxy-log', {
    type: 'WS',
    method: req.method,
    url: req.url,
    time: new Date().toISOString()
  });
});

server.listen(process.env.PORT || 3000, () => {
  console.log(`🚀 Server ready at http://localhost:${process.env.PORT || 3000}`);
});
