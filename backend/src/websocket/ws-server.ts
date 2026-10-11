import { Server as WSServer, Socket } from 'socket.io';
import { jwtService } from '../core/auth/jwt.js';
import { logger } from '../core/logging/logger.js';
import { cacheGet } from '../core/redis/client.js';

const connectedClients = new Map<string, Set<string>>();

export function setupWebSocket(wss: WSServer): void {
  wss.use(async (socket, next) => {
    try {
      const cookieHeader = socket.handshake.headers.cookie;
      const cookieToken = cookieHeader
        ? /(?:^|;\s*)access_token=([^;]+)/.exec(cookieHeader)?.[1]
        : undefined;
      const token = socket.handshake.auth.token
        || socket.handshake.headers.authorization?.replace('Bearer ', '')
        || (cookieToken ? decodeURIComponent(cookieToken) : undefined);
      if (!token) {
        return next(new Error('Authentication required'));
      }

      if (await jwtService.isBlacklisted(token)) {
        return next(new Error('Token has been revoked'));
      }

      const payload = jwtService.verifyAccessToken(token);
      (socket as any).userId = payload.sub;
      (socket as any).orgId = payload.org;
      (socket as any).role = payload.role;

      next();
    } catch (err) {
      next(new Error('Invalid token'));
    }
  });

  wss.on('connection', (socket: Socket) => {
    const userId = (socket as any).userId as string;
    const orgId = (socket as any).orgId as string;

    logger.info({ userId, socketId: socket.id }, 'WebSocket client connected');

    if (!connectedClients.has(orgId)) {
      connectedClients.set(orgId, new Set());
    }
    connectedClients.get(orgId)!.add(socket.id);

    socket.join(`org:${orgId}`);
    socket.join(`user:${userId}`);

    socket.emit('connected', {
      message: 'WebSocket connection established',
      userId,
      timestamp: new Date().toISOString(),
    });

    socket.on('subscribe', async (channels: string[]) => {
      if (!Array.isArray(channels)) return;
      for (const channel of channels) {
        if (typeof channel !== 'string') continue;
        if (channel.startsWith('org:') && channel !== `org:${orgId}`) continue;
        if (channel.startsWith('user:') && channel !== `user:${userId}`) continue;
        socket.join(channel);
        logger.debug({ userId, channel }, 'Client subscribed to channel');
      }

      const initialData = await getInitialData(channels, orgId);
      if (initialData) {
        socket.emit('initial-data', initialData);
      }
    });

    socket.on('unsubscribe', (channels: string[]) => {
      if (!Array.isArray(channels)) return;
      for (const channel of channels) {
        if (typeof channel !== 'string') continue;
        socket.leave(channel);
      }
    });

    socket.on('ping-server', () => {
      socket.emit('pong-server', { timestamp: Date.now() });
    });

    socket.on('disconnect', (reason) => {
      logger.info({ userId, socketId: socket.id, reason }, 'WebSocket client disconnected');

      const orgClients = connectedClients.get(orgId);
      if (orgClients) {
        orgClients.delete(socket.id);
        if (orgClients.size === 0) {
          connectedClients.delete(orgId);
        }
      }
    });

    socket.on('error', (err) => {
      logger.error({ userId, err }, 'WebSocket error');
    });
  });

  logger.info('WebSocket server configured');
}

export function broadcastToOrg(orgId: string, event: string, data: unknown): void {
  const wss = getWSSInstance();
  if (wss) {
    wss.to(`org:${orgId}`).emit(event, data);
  }
}

export function broadcastToUser(userId: string, event: string, data: unknown): void {
  const wss = getWSSInstance();
  if (wss) {
    wss.to(`user:${userId}`).emit(event, data);
  }
}

export function broadcastScanUpdate(orgId: string, scanId: string, update: Record<string, unknown>): void {
  broadcastToOrg(orgId, `scan:${scanId}:update`, update);
  broadcastToOrg(orgId, 'scan:updated', { scanId, ...update });
}

export function broadcastFindingUpdate(orgId: string, findingId: string, update: Record<string, unknown>): void {
  broadcastToOrg(orgId, `finding:${findingId}:update`, update);
  broadcastToOrg(orgId, 'finding:updated', { findingId, ...update });
}

export function broadcastJobProgress(orgId: string, jobId: string, progress: number, message: string): void {
  broadcastToOrg(orgId, `job:${jobId}:progress`, { progress, message });
}

let wssInstance: WSServer | null = null;

function getWSSInstance(): WSServer | null {
  return wssInstance;
}

export function setWSSInstance(wss: WSServer): void {
  wssInstance = wss;
}

async function getInitialData(channels: string[], orgId: string): Promise<Record<string, unknown> | null> {
  const data: Record<string, unknown> = {};
  let hasData = false;

  for (const channel of channels) {
    if (channel === 'dashboard:summary') {
      const summary = await cacheGet(`dashboard:summary:${orgId}`);
      if (summary) { data.dashboardSummary = summary; hasData = true; }
    }
    if (channel === 'scans:running') {
      const scans = await cacheGet(`scans:running:${orgId}`);
      if (scans) { data.runningScans = scans; hasData = true; }
    }
  }

  return hasData ? data : null;
}
