# postgres/init

Optional `.sql` / `.sh` files run by the official PostgreSQL image the first time
the database is initialised, before migrations.

Schema belongs in `../migrations/` and seed data in `../seeds/`, both applied by the
backend on startup. Most installs leave this directory empty.

This placeholder only keeps the directory in git.
