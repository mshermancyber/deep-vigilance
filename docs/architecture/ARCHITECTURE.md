# Architecture

## Overview

The Application Security Platform follows a **microservice architecture** with Docker containerization. Each service has a single responsibility and communicates over HTTPS (internally) and via Redis/BullMQ for async job processing.

## Design Principles

1. **Security-First** — All communication encrypted, zero-trust internal APIs, immutable audit logs
2. **Separation of Concerns** — Each service has one job
3. **Async by Default** — Heavy operations (scanning, reporting) are queue-driven
4. **Stateless API** — Backend is horizontally scalable
5. **Defense in Depth** — Multiple layers of security controls

## Component Details

### NGINX Reverse Proxy
- TLS termination with HSTS
- Rate limiting (per-IP and per-endpoint)
- Request buffering and caching
- WebSocket upgrade support
- Security headers injection

### Backend API (Express)
- JWT authentication with refresh token rotation
- Role-Based Access Control (7 roles, 30+ permissions)
- Input validation via Zod schemas
- Structured logging with Pino
- WebSocket server for real-time updates
- BullMQ integration for job dispatching

### Database (PostgreSQL 16)
- UUID primary keys throughout
- GIN indexes for full-text search (pg_trgm)
- JSONB for flexible metadata storage
- Immutable audit_log table
- Connection pooling

### Cache & Queue (Redis 7)
- Application cache (dashboard data, session tokens)
- BullMQ job queue backend
- Pub/sub for inter-service notifications
- LRU eviction with maxmemory policy
- AOF persistence

### Workers
- **SAST Worker**: Pattern-based static analysis across 25+ languages
- **DAST Worker**: Dynamic testing with HTTP request fuzzing
- **API Scanner Worker**: Endpoint discovery and parameter fuzzing
- **Report Worker**: PDF generation via Puppeteer
- **Backend Worker**: General job processing (notifications, integration syncs)

## Data Flow

```
1. User creates scan → Backend validates → Inserts DB record → Enqueues BullMQ job
2. Worker picks up job → Executes scan → Updates DB with findings → Publishes WebSocket event
3. Dashboard receives WS event → Updates UI in real-time
4. User generates report → Backend enqueues report job → Report worker generates PDF/HTML → User downloads
```

## Security Architecture

- **Authentication**: JWT (HS256) + refresh tokens, API key support for service accounts
- **Authorization**: RBAC with granular permissions, project/org isolation
- **Encryption**: AES-256-GCM for secrets at rest, TLS 1.2+ for transit
- **Audit**: Every action logged with user, IP, timestamp, changes
- **Hardening**: Helmet.js, CSP, HSTS, rate limiting, input sanitization, parameterized queries

## Scaling

- Backend API: Horizontal (stateless, add more instances behind nginx)
- Workers: Vertical (increase concurrency) or horizontal (add more worker containers)
- PostgreSQL: Read replicas for dashboards, connection pooling via PgBouncer
- Redis: Cluster mode for larger deployments
