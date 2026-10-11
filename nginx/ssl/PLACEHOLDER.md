# nginx/ssl

Holds the TLS certificate nginx serves. Generated locally, never committed.

    ./scripts/generate-certs.sh

creates `server.crt` and `server.key` here. Replace them with a certificate from a
real CA for any deployment reachable from the internet, then:

    docker compose exec nginx nginx -s reload

This directory is bind-mounted read-only into the nginx container, so the files must
exist on the host before the first `docker compose up`.

This placeholder only keeps the directory in git. It is safe to delete once the
certificates exist.
