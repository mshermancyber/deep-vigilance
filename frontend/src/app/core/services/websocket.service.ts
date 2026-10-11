import { Injectable } from '@angular/core';
import { io, Socket } from 'socket.io-client';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class WebSocketService {
  private socket: Socket | null = null;

  connect(): Socket {
    if (this.socket?.connected) return this.socket;
    // Auth rides the HttpOnly cookie via the credentialed handshake — no token in JS.
    this.socket = io(environment.wsUrl, { withCredentials: true, transports: ['websocket'], reconnection: true, reconnectionDelay: 2000, reconnectionDelayMax: 10000 });
    this.socket.on('connect', () => console.log('[WS] Connected'));
    this.socket.on('disconnect', (reason) => console.log('[WS] Disconnected:', reason));
    this.socket.on('error', (err) => console.error('[WS] Error:', err));
    return this.socket;
  }

  subscribe(channel: string): void { this.connect().emit('subscribe', [channel]); }
  unsubscribe(channel: string): void { this.connect().emit('unsubscribe', [channel]); }
  on<T>(event: string, callback: (data: T) => void): void { this.connect().on(event, callback); }
  disconnect(): void { if (this.socket) { this.socket.disconnect(); this.socket = null; } }
}
