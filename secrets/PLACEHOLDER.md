# secrets

For Docker **Swarm** deployments only. `docker-compose.prod.yml` declares
`db_password`, `redis_password` and `jwt_secret` as `external: true` secrets, which
you create once from files kept here:

    docker secret create db_password    ./secrets/db_password.txt
    docker secret create redis_password ./secrets/redis_password.txt
    docker secret create jwt_secret     ./secrets/jwt_secret.txt

`*.txt` in this directory is git-ignored. **Never commit a real secret.** Delete the
local files once the Docker secrets are created.

Plain `docker compose` deployments do not use this directory at all — they read
secrets from `.env`.
