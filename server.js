const http = require('http');
const { v4: uuidV4 } = require('uuid');
const express = require('express');
const morgan = require('morgan');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const { TunnelRequest, TunnelResponse } = require('./lib');

const app = express();
const httpServer = http.createServer(app);
const webTunnelPath = '/$web_tunnel';
const io = new Server(httpServer, {
  path: webTunnelPath,
  maxHttpBufferSize: 1e8,
});

// Increase max listeners to avoid warning
require('events').defaultMaxListeners = 30;

let tunnelSockets = [];

function getTunnelSocket(host, pathPrefix) {
  return tunnelSockets.find((s) => s.host === host && s.pathPrefix === pathPrefix);
}

function setTunnelSocket(host, pathPrefix, socket) {
  console.log(`ℹ️ Adding tunnel for ${host}, prefix: ${pathPrefix}`);
  tunnelSockets.push({ host, pathPrefix, socket });
}

function removeTunnelSocket(host, pathPrefix) {
  console.log(`ℹ️ Removing tunnel for ${host}, prefix: ${pathPrefix}`);
  tunnelSockets = tunnelSockets.filter((s) => !(s.host === host && s.pathPrefix === pathPrefix));
  console.log('tunnelSockets:', tunnelSockets.map((s) => s.host + (s.pathPrefix || '')));
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
  console.log(`🔎 Matching tunnel for host=${host}, url=${url}: ${tunnels.length} found`);
  return tunnels[0]?.socket || null;
}

// JWT authentication
io.use((socket, next) => {
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];

  console.log(`🔑 Auth attempt for ${connectHost}, pathPrefix=${pathPrefix}`);

  if (getTunnelSocket(connectHost, pathPrefix)) {
    console.log(`❌ Reject: ${connectHost} already connected`);
    return next(new Error(`${connectHost} already has a connection`));
  }

  const token = socket.handshake.auth?.token;
  if (!token) {
    console.log('❌ Reject: Missing token');
    return next(new Error('Authentication error'));
  }

  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err || decoded.token !== process.env.VERIFY_TOKEN) {
      console.log('❌ Reject: Invalid token');
      return next(new Error('Authentication error'));
    }
    console.log('✅ Auth success');
    next();
  });
});

io.on('connection', (socket) => {
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  setTunnelSocket(connectHost, pathPrefix, socket);
  console.log(`✅ Client connected: ${connectHost}, prefix=${pathPrefix}`);

  const onMessage = (message) => {
    console.log(`💬 [${connectHost}] Message: ${message}`);
    if (message === 'ping') {
      socket.send('pong');
    }
  };
  const onDisconnect = (reason) => {
    console.log(`⚠️ Client disconnected (${connectHost}, prefix=${pathPrefix}):`, reason);
    removeTunnelSocket(connectHost, pathPrefix);
  };

  socket.on('message', onMessage);
  socket.once('disconnect', onDisconnect);
});

// JWT generator endpoint
app.use(morgan('tiny'));
app.get('/tunnel_jwt_generator', (req, res) => {
  console.log('🔑 JWT generator called');
  process.env.JWT_GENERATOR_USERNAME = 'admin';
  process.env.JWT_GENERATOR_PASSWORD = 'admin';
  process.env.VERIFY_TOKEN = '123456';
  process.env.SECRET_KEY = '123456';

  if (!req.query.username || !req.query.password) {
    console.log('❌ Missing credentials in JWT generator');
    return res.status(401).send('Forbidden');
  }

  if (
    req.query.username === process.env.JWT_GENERATOR_USERNAME &&
    req.query.password === process.env.JWT_GENERATOR_PASSWORD
  ) {
    const jwtToken = jwt.sign({ token: process.env.VERIFY_TOKEN }, process.env.SECRET_KEY);
    console.log('✅ JWT issued');
    return res.status(200).send(jwtToken);
  }
  console.log('❌ Invalid credentials in JWT generator');
  res.status(401).send('Forbidden');
});

// Helper to clean forwarded headers
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
  console.log(`🌐 HTTP ${req.method}: ${req.url}`);
  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) {
    console.log('❌ No tunnel socket found');
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
    console.log('❌ Request error:', e);
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
    console.log('❌ Tunnel request error');
    tunnelResponse.off('response', onResponse);
    tunnelResponse.destroy();
    res.status(502).end('Request error');
  };
  const onResponse = ({ statusCode, statusMessage, headers }) => {
    console.log(`↩️ Response: ${statusCode} ${statusMessage}`);
    tunnelRequest.off('requestError', onRequestError);
    res.writeHead(statusCode, statusMessage, headers);
  };

  tunnelResponse.once('requestError', onRequestError);
  tunnelResponse.once('response', onResponse);
  tunnelResponse.pipe(res);

  const onSocketError = () => {
    console.log('❌ Tunnel socket disconnect');
    res.off('close', onResClose);
    res.status(500).end();
  };
  const onResClose = () => {
    console.log('ℹ️ Response closed');
    tunnelSocket.off('disconnect', onSocketError);
  };

  tunnelSocket.once('disconnect', onSocketError);
  res.once('close', onResClose);
});

// WS upgrade handling
function createSocketHttpHeader(line, headers) {
  return Object.keys(headers)
    .reduce((head, key) => {
      const value = headers[key];
      if (Array.isArray(value)) {
        value.forEach((v) => head.push(`${key}: ${v}`));
      } else {
        head.push(`${key}: ${value}`);
      }
      return head;
    }, [line])
    .join('\r\n') + '\r\n\r\n';
}

httpServer.on('upgrade', (req, socket, head) => {
  console.log(`🌐 WS Upgrade: ${req.url}`);
  if (req.url.indexOf(webTunnelPath) === 0) return;

  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) {
    console.log('❌ No tunnel socket found for WS upgrade');
    return;
  }

  if (head && head.length) socket.unshift(head);
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
  req.pipe(tunnelRequest);

  const tunnelResponse = new TunnelResponse({
    socket: tunnelSocket,
    responseId: requestId,
  });

  const onRequestError = () => {
    console.log('❌ Tunnel request error during WS upgrade');
    tunnelResponse.off('response', onResponse);
    tunnelResponse.destroy();
    socket.end();
  };
  const onResponse = ({ statusCode, statusMessage, headers, httpVersion }) => {
    tunnelResponse.off('requestError', onRequestError);

    if (statusCode) {
      console.log(`↩️ WS Response: ${statusCode} ${statusMessage}`);
      socket.write(
        createSocketHttpHeader(`HTTP/${httpVersion} ${statusCode} ${statusMessage}`, headers)
      );
      tunnelResponse.pipe(socket);
      return;
    }

    console.log('↔️ WS Proxy established');
    const onSocketError = () => {
      console.log('❌ WS Socket error');
      socket.off('end', onSocketEnd);
      tunnelSocket.off('disconnect', onTunnelError);
      tunnelResponse.destroy();
    };
    const onSocketEnd = () => {
      console.log('ℹ️ WS Socket end');
      socket.off('error', onSocketError);
      tunnelSocket.off('disconnect', onTunnelError);
      tunnelResponse.destroy();
    };
    const onTunnelError = () => {
      console.log('❌ Tunnel socket disconnect (WS)');
      socket.off('error', onSocketError);
      socket.off('end', onSocketEnd);
      socket.end();
      tunnelResponse.destroy();
    };

    socket.once('error', onSocketError);
    socket.once('end', onSocketEnd);
    tunnelSocket.once('disconnect', onTunnelError);

    socket.write(createSocketHttpHeader('HTTP/1.1 101 Switching Protocols', headers));
    tunnelResponse.pipe(socket).pipe(tunnelResponse);
  };

  tunnelResponse.once('requestError', onRequestError);
  tunnelResponse.once('response', onResponse);
});

// Admin API: List active tunnels
app.get('/tunnels', (req, res) => {
  res.json(tunnelSockets.map((s) => ({
    host: s.host,
    pathPrefix: s.pathPrefix,
    connected: s.socket.connected,
  })));
});

httpServer.listen(process.env.PORT || 3000, () => {
  console.log(`🚀 Server started at http://localhost:${process.env.PORT || 3000}`);
});
