-- STOCK WordPress lab — intentionally NO special grants.
-- The wp2shell chain (exploit.py) needs NO MySQL FILE privilege, NO cracked
-- password, NO victim interaction. The WP DB user keeps the docker-entrypoint
-- default (ALL on the `wordpress` database only, which does NOT include the
-- global FILE privilege) — the chain does not use it.
SELECT 1;
