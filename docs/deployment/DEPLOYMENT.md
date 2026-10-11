# Deployment Guide

## Prerequisites

- Docker Engine 24+ and Docker Compose v2+
- 8GB+ RAM available for containers
- 20GB+ free disk space
- Ports 8080 and 8443 free on the host (set `HTTP_PORT` / `HTTPS_PORT` in `.env` to change
  them). Only the nginx edge publishes a port; in development the override also publishes
  1025/8025 for MailHog.

## Production Deployment Checklist

### 1. Environment Configuration
Edit `.env` with strong, unique values:
- `DB_PASSWORD`: 32+ character random string
- `REDIS_PASSWORD`: 32+ character random string
- `JWT_SECRET`: 64+ character random string
- `JWT_REFRESH_SECRET`: 64+ character random string
- `ENCRYPTION_KEY`: Exactly 32 characters
- `ADMIN_EMAIL`: Real admin email
- `ADMIN_PASSWORD`: Strong initial password

### 2. TLS Certificates
Replace self-signed certs with real ones:
```bash
# Using Let's Encrypt
certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/ssl/server.crt
cp /etc/letsencrypt/live/your-domain.com/privkey.pem nginx/ssl/server.key
```

### 3. Database
- Use managed PostgreSQL in production or ensure proper backups
- Configure `pg_dump` cron jobs
- Set up read replicas for dashboard queries if needed

### 4. Backups
```bash
# Database backup
docker compose exec postgres pg_dump -U appsec_user appsec_platform > backup.sql

# Restore
docker compose exec -T postgres psql -U appsec_user appsec_platform < backup.sql
```

### 5. Monitoring
- All services have health checks in docker-compose
- Backend exposes `/api/health`, `/api/health/liveness`, `/api/health/readiness`
- Use Prometheus + Grafana for production metrics
- Structured JSON logging to stdout/stderr

### 6. Firewall
Only expose ports 8080 and 8443 to the internet. All other ports should be internal/firewall-blocked:
```bash
ufw allow 8443/tcp
ufw allow 8080/tcp
```

### 7. Resource Limits
Adjust in `docker-compose.yml` based on your hardware:
- SAST worker: 4-8GB RAM for large codebases
- DAST worker: 4GB RAM minimum
- Chromium: 4GB RAM recommended
- Backend: 2GB RAM

## Build & Launch

```bash
# Build all images
docker compose build --no-cache

# Start everything
docker compose up -d

# View logs
docker compose logs -f

# Check health
curl -k https://localhost:8443/api/health
```

## Updates

```bash
git pull
docker compose down
docker compose build --no-cache
docker compose up -d
```

## Troubleshooting

- Check logs: `docker compose logs <service-name>`
- Verify DB: `docker compose exec postgres psql -U appsec_user -d appsec_platform`
- Check Redis: `docker compose exec redis redis-cli -a $REDIS_PASSWORD ping`
- Restart service: `docker compose restart <service-name>`
