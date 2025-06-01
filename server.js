const http = require('http');
const { v4: uuidV4 } = require('uuid');
const express = require('express');
const morgan = require('morgan');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const { TunnelRequest, TunnelResponse } = require('./lib');

const MAX_LOGS = 200;
const recentLogs = [];

const app = express();
const httpServer = http.createServer(app);
const webTunnelPath = '/$web_tunnel';
const io = new Server(httpServer, {
  path: webTunnelPath,
});

const dashboardNamespace = io.of('/dashboard');

// --- Hook console log ---
const consoleEmit = (type, args) => {
  const message = args.map(a => {
    if (typeof a === 'object') {
      try {
        return JSON.stringify(a, null, 2);
      } catch (err) {
        return '[Circular object]'; // tránh lỗi JSON
      }
    }
    return a;
  }).join(' ');

  const logData = {
    time: new Date().toISOString(),
    type,
    message
  };

  recentLogs.push(logData);

  // Giới hạn 200 log gần nhất
  if (recentLogs.length > MAX_LOGS) {
    recentLogs.shift(); // Xoá log cũ nhất
  }

  dashboardNamespace.emit('proxy-log', logData);
};

['log', 'error', 'warn', 'info', 'debug'].forEach(method => {
  const orig = console[method];
  console[method] = (...args) => {
    consoleEmit(method, args);
    orig.apply(console, args); // vẫn in ra console cũ
  };
});


dashboardNamespace.on('connection', (socket) => {
  console.log('Dashboard client connected');

  // Gửi 200 log cũ cho dashboard mới connect
  socket.emit('proxy-log-history', recentLogs);

  socket.on('disconnect', () => {
    console.log('Dashboard client disconnected');
  });
});

let tunnelSockets = [];

function getTunnelSocket(host, pathPrefix) {
  console.log('getTunnelSocket:', { host, pathPrefix });
  return tunnelSockets.find((s) =>
    s.host === host && s.pathPrefix === pathPrefix
  );
}

function setTunnelSocket(host, pathPrefix, socket) {
  console.log('setTunnelSocket:', { host, pathPrefix });
  tunnelSockets.push({
    host,
    pathPrefix,
    socket,
  });
  console.log('Current tunnelSockets:', tunnelSockets);
}

function removeTunnelSocket(host, pathPrefix) {
  console.log('removeTunnelSocket:', { host, pathPrefix });
  tunnelSockets = tunnelSockets.filter((s) =>
    !(s.host === host && s.pathPrefix === pathPrefix)
  );
  console.log('tunnelSockets after remove:', tunnelSockets);
}

function getAvailableTunnelSocket(host, url) {
  console.log('getAvailableTunnelSocket:', { host, url });
  const tunnels = tunnelSockets.filter((s) => {
    if (s.host !== host) {
      return false;
    }
    if (!s.pathPrefix) {
      return true;
    }
    return url.indexOf(s.pathPrefix) === 0;
  }).sort((a, b) => {
    if (!a.pathPrefix) {
      return 1;
    }
    if (!b.pathPrefix) {
      return -1;
    }
    return b.pathPrefix.length - a.pathPrefix.length;
  });
  console.log('Available tunnels:', tunnels);
  if (tunnels.length === 0) {
    console.warn('No available tunnelSocket found');
    return null;
  }
  console.log('Selected tunnelSocket:', tunnels[0]);
  return tunnels[0].socket;
}

io.use((socket, next) => {
  console.log('io.use - Authentication phase');
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  console.log('Auth connectHost:', connectHost, 'pathPrefix:', pathPrefix);
  if (getTunnelSocket(connectHost, pathPrefix)) {
    console.warn('Existing tunnel connection detected for host:', connectHost);
    return next(new Error(`${connectHost} has a existing connection`));
  }
  if (!socket.handshake.auth || !socket.handshake.auth.token){
    console.error('Missing authentication token!');
    next(new Error('Authentication error'));
  }
  jwt.verify(socket.handshake.auth.token, process.env.SECRET_KEY, function(err, decoded) {
    if (err) {
      console.error('JWT verification failed:', err);
      return next(new Error('Authentication error'));
    }
    if (decoded.token !== process.env.VERIFY_TOKEN) {
      console.error('Token mismatch!');
      return next(new Error('Authentication error'));
    }
    console.log('JWT verified successfully');
    next();
  });
});

io.on('connection', (socket) => {
  const connectHost = socket.handshake.headers.host;
  const pathPrefix = socket.handshake.headers['path-prefix'];
  console.log('New tunnel client connected:', { connectHost, pathPrefix });
  setTunnelSocket(connectHost, pathPrefix, socket);
  const onMessage = (message) => {
    console.log('Message from client:', message);
    if (message === 'ping') {
      socket.send('pong');
    }
  }
  const onDisconnect = (reason) => {
    console.log('Tunnel client disconnected:', reason);
    removeTunnelSocket(connectHost, pathPrefix);
    socket.off('message', onMessage);
  };
  socket.on('message', onMessage);
  socket.once('disconnect', onDisconnect);
});

app.use(morgan('tiny'));
app.get('/tunnel_jwt_generator', (req, res) => {
  console.log('/tunnel_jwt_generator called with:', req.query);
  process.env.JWT_GENERATOR_USERNAME = 'admin';
  process.env.JWT_GENERATOR_PASSWORD = 'admin';
  process.env.VERIFY_TOKEN = '123456';
  process.env.SECRET_KEY = '123456';
  if (!process.env.JWT_GENERATOR_USERNAME || !process.env.JWT_GENERATOR_PASSWORD) {
    console.warn('JWT generator credentials missing');
    res.status(404);
    res.send('Not found');
    return;
  }
  if (
    req.query.username === process.env.JWT_GENERATOR_USERNAME &&
    req.query.password === process.env.JWT_GENERATOR_PASSWORD
  ) {
    const jwtToken = jwt.sign({ token: process.env.VERIFY_TOKEN }, process.env.SECRET_KEY);
    console.log('JWT generated and sent');
    res.status(200);
    res.send(jwtToken);
    return;
  }
  console.warn('JWT generator authentication failed');
  res.status(401);
  res.send('Forbidden');
});

function getReqHeaders(req) {
  console.log('getReqHeaders for request:', req.url);
  const encrypted = !!(req.isSpdy || req.connection.encrypted || req.connection.pair);
  const headers = { ...req.headers };
  const url = new URL(`${encrypted ? 'https' : 'http'}://${req.headers.host}`);
  const forwardValues = {
    for: req.connection.remoteAddress || req.socket.remoteAddress,
    port: url.port || (encrypted ? 443 : 80),
    proto: encrypted ? 'https' : 'http',
  };
  ['for', 'port', 'proto'].forEach((key) => {
    const previousValue = req.headers[`x-forwarded-${key}`] || '';
    headers[`x-forwarded-${key}`] =
      `${previousValue || ''}${previousValue ? ',' : ''}${forwardValues[key]}`;
  });
  headers['x-forwarded-host'] = req.headers['x-forwarded-host'] || req.headers.host || '';
  return headers;
}

app.get('/dashboard', (req, res) => {
  console.log('Serving dashboard.html');
  res.sendFile(__dirname + '/dashboard.html');
});

app.use('/', (req, res) => {
  console.log('Incoming HTTP request:', req.method, req.url);
  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) {
    console.warn('No tunnelSocket available for request:', req.url);
    res.status(404);
    res.send('Not Found');
    return;
  }
  const requestId = uuidV4();
  console.log('Forwarding HTTP request with requestId:', requestId);
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
    console.error('HTTP request error:', e);
    tunnelRequest.destroy(new Error(e || 'Aborted'));
  }
  req.once('aborted', onReqError);
  req.once('error', onReqError);
  req.pipe(tunnelRequest);
  req.once('finish', () => {
    console.log('HTTP request finished:', req.url);
    req.off('aborted', onReqError);
    req.off('error', onReqError);
  });
  const tunnelResponse = new TunnelResponse({
    socket: tunnelSocket,
    responseId: requestId,
  });
  const onRequestError = () => {
    console.error('Tunnel response requestError');
    tunnelResponse.off('response', onResponse);
    tunnelResponse.destroy();
    res.status(502);
    res.end('Request error');
  };
  const onResponse = ({ statusCode, statusMessage, headers }) => {
    console.log('Tunnel response:', { statusCode, statusMessage });
    tunnelRequest.off('requestError', onRequestError)
    res.writeHead(statusCode, statusMessage, headers);
  };
  tunnelResponse.once('requestError', onRequestError)
  tunnelResponse.once('response', onResponse);
  tunnelResponse.pipe(res);
  const onSocketError = () => {
    console.error('Tunnel socket disconnected during response');
    res.off('close', onResClose);
    res.end(500);
  };
  const onResClose = () => {
    console.log('HTTP response closed');
    tunnelSocket.off('disconnect', onSocketError);
  };
  tunnelSocket.once('disconnect', onSocketError)
  res.once('close', onResClose);
});

function createSocketHttpHeader(line, headers) {
  return Object.keys(headers).reduce(function (head, key) {
    var value = headers[key];
    if (!Array.isArray(value)) {
      head.push(key + ': ' + value);
      return head;
    }
    for (var i = 0; i < value.length; i++) {
      head.push(key + ': ' + value[i]);
    }
    return head;
  }, [line])
  .join('\r\n') + '\r\n\r\n';
}

httpServer.on('upgrade', (req, socket, head) => {
  console.log('Incoming WebSocket upgrade request:', req.url);
  if (req.url.indexOf(webTunnelPath) === 0) {
    console.log('Upgrade for tunnel path, skip');
    return;
  }
  const tunnelSocket = getAvailableTunnelSocket(req.headers.host, req.url);
  if (!tunnelSocket) {
    console.warn('No tunnelSocket available for WebSocket upgrade:', req.url);
    return;
  }
  console.log('Proxying WebSocket upgrade for:', req.url);
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
    console.error('WebSocket tunnelResponse requestError');
    tunnelResponse.off('response', onResponse);
    tunnelResponse.destroy();
    socket.end();
  };
  const onResponse = ({ statusCode, statusMessage, headers, httpVersion }) => {
    console.log('WebSocket tunnelResponse:', { statusCode, statusMessage });
    tunnelResponse.off('requestError', onRequestError);
    if (statusCode) {
      socket.once('error', (err) => {
        console.error('WebSocket response error:', err);
      });
      socket.write(createSocketHttpHeader(`HTTP/${httpVersion} ${statusCode} ${statusMessage}`, headers));
      tunnelResponse.pipe(socket);
      return;
    }
    const onSocketError = (err) => {
      console.error('WebSocket error:', err);
      socket.off('end', onSocketEnd);
      tunnelSocket.off('disconnect', onTunnelError);
      tunnelResponse.destroy(err);
    };
    const onSocketEnd = () => {
      console.log('WebSocket end');
      socket.off('error', onSocketError);
      tunnelSocket.off('disconnect', onTunnelError);
      tunnelResponse.destroy();
    };
    const onTunnelError = () => {
      console.warn('Tunnel disconnected during WebSocket');
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
  }
  tunnelResponse.once('requestError', onRequestError)
  tunnelResponse.once('response', onResponse);
});

httpServer.listen(process.env.PORT || 3000);
console.log(`app start at http://localhost:${process.env.PORT || 3000}`);
