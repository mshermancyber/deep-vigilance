# data/postgres

PostgreSQL data directory, bind-mounted into the `postgres` container. Created on
first start.

**Back this up.** Deleting it destroys every project, scan and finding. Note that
restoring a backup also requires the `ENCRYPTION_KEY` from the `.env` in use when
it was taken, or stored integration credentials cannot be decrypted.

This placeholder only keeps the directory in git; its contents are ignored.
