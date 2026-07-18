# wp2shell — WordPress 6.9/7.0 pre-authentication RCE (**0-click, no preconditions**)

Anonymous, **no-plugin, stock-core** PoC that turns the wp2shell batch-route
confusion into **full remote code execution** on a default install — **without**
MySQL FILE privilege, **without** cracking a password, and **without** any victim
interaction.

- **GHSA-ff9f-jf42-662q** (CVE-2026-63030) — REST `/batch/v1` route confusion.
- **GHSA-fpp7-x2x2-2mjf** (CVE-2026-60137) — `WP_Query::author__not_in` SQLi.
- Discovered by **Adam Kues** (Assetnote / Searchlight Cyber).
- Affects **6.9.0–6.9.4, 7.0.0–7.0.1** (SQLi sink also 6.8.0–6.8.5). Fixed in
  **6.8.6 / 6.9.5 / 7.0.2**.

```
POST /?rest_route=/batch/v1  (anonymous)
  -> batch-route confusion -> author__not_in SQLi
  -> forge WP_Post rows into the object cache
  -> oEmbed cache updater + post_parent loop -> customize_changeset publish
  -> wp_set_current_user(admin)  [identity switch]
  -> do_action("parse_request") -> rest_api_loaded() re-entry (as admin)
  -> POST /wp/v2/users  =>  NEW ADMINISTRATOR
  -> plugin upload  =>  RCE as www-data
```

## Result (stock WP 7.0.0, no FILE grant, no plugin)

```
[+] RCE CONFIRMED — 0-click, no FILE, no crack, no victim
[+] administrator: w2s_xxxxxxxxxxxx:W2s!xxxxxxxxxxxxxxx
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Why this is the interesting part

The two CVEs alone only give an **anonymous, read-only** SQL injection. The hard
part — and the part the public write-ups withhold — is turning a read-only SQLi
into code execution with **zero preconditions**. The chain is a masterclass in
abusing WordPress's own bookkeeping; each step is a different, non-obvious gadget:

**1. Batch-route confusion → SQLi.** `serve_batch_request_v1()` builds a
`$matches[]` array of [route,handler] per sub-request, but a sub-request whose path
fails `wp_parse_url()` (e.g. `"http://"`) is appended to `$validation` **but not
`$matches`** — so `$matches` shifts by one. The dispatch loop then pairs each
sub-request with the **next** request's handler. A nested batch (the self-call)
plus a `categories` carrier whose `author_exclude` arg is never sanitized routes a
raw string into `WP_Query::author__not_in` → SQL injection. The 6.9.5/7.0.2 fix
appends to `$matches` on the error branch too, and `wp_parse_id_list()` now
sanitizes the value.

**2. UNION-forged `WP_Post` → object-cache poison.** The SQLi is a plain `SELECT`
(mysqli single-statement — no stacked queries, and no FILE priv, so no
`INTO OUTFILE`). But a `UNION SELECT` with the full 23 `wp_posts` columns returns
attacker-controlled rows, which `update_post_caches()` turns into `WP_Post`
objects and caches under **attacker-chosen IDs** in the per-request object cache.
(Requires a *non-persistent* cache — a stock install — because `wp_cache_add()`
won't overwrite an already-cached real row.)

**3. oEmbed cache updater → real DB write.** One forged row's `post_content` holds
an `[embed]` of the **target's own post** (WordPress is its own oEmbed provider —
no external infra). Rendering it drives `WP_Embed::shortcode()` → the oEmbed cache
updater `wp_update_post(ID, post_content=html)`. `wp_update_post` merges
`get_post(ID)` — the **forged** cached row — into the **real** DB row, so the real
row takes the forged `post_type` / `post_author` / `post_status` / `post_name`.

**4. `post_parent` loop → changeset publish.** A forged
`customize_changeset` row is given `post_parent = X`, and a second forged row `X`
is given `post_parent = <changeset>` — a hierarchy **loop**. When the updater
writes a row that participates in the loop, `wp_insert_post` calls
**`wp_check_post_hierarchy_for_loops()`**, which fires a **second, independent**
`wp_update_post` on the *changeset* — transitioning it `future → publish`
(`future` + a past `post_date` auto-publishes).

**5. Identity switch.** `transition_post_status` →
`_wp_customize_publish_changeset()` → `WP_Customize_Manager::publish_changeset_values()`,
which reads the changeset JSON (the oEmbed HTML we control) and, **per setting,
calls `wp_set_current_user($setting['user_id'])`** before `$setting->save()`. The
changeset's `user_id` is the (blind-exfiltrated) admin ID — so the setting saves
**as the administrator**. This is the auth bypass: the code switches identity to a
privileged user *inside* the publish.

**6. `do_action("parse_request")` → re-entrant dispatch.** A `nav_menu_item`
setting's `save()` writes a nav post via `wp_update_nav_menu_item()` →
`wp_insert_post()` → **another** hierarchy-loop write. One forged row is given
`post_status = "parse"` and `post_type = "request"`, so writing it fires the
dynamic hook `do_action("{$status}_{$type}")` = **`do_action("parse_request")`** —
which is hooked to **`rest_api_loaded()`**. `rest_api_loaded()` re-reads the
*global* `rest_route` (still `/batch/v1`) and **re-enters `serve_request()` for the
SAME batch request** — now running **as the admin** (the switch hasn't reverted).

**7. New administrator.** The re-entrant batch re-processes the batch body, which
contains a `POST /wp/v2/users` sub-request. Its `create_item_permissions_check`
calls `current_user_can('create_users')` — which now **passes** (admin) →
`wp_insert_user` + `add_role('administrator')` → **a new administrator is created
anonymously**. `rest_api_loaded()` then `die`s (so the `wp_set_current_user`
revert never runs — that's why the elevated identity persisted).

**8. RCE.** Log in as the new admin and upload a plugin → arbitrary PHP as
`www-data`.

The 7.0.2 release kills the chain at every step: `$matches` stays aligned
(confusion fix), `wp_parse_id_list()` sanitizes `author__not_in` (SQLi fix), and
`is_dispatching()` re-entrancy guards on both `serve_request()` and
`rest_api_loaded()` block step 6.

## Files

```
poc/
  compose.yaml   STOCK target: wordpress:7.0.0 + mysql:8.0 (NO plugin, NO FILE grant)
  init.sql       no-op (documents that no special grants are needed)
  exploit.py     the full 0-click chain (one mode: full pre-auth RCE)
  run.sh         up + install + exploit          (./run.sh down to tear down)
```

## Run

```bash
cd poc && ./run.sh                              # stock target up + install + full chain
WP_TARGET=http://host:port python3 exploit.py   # against any affected target
python3 exploit.py -c "id; uname -a"            # full chain + run a command
```

Stages (all anonymous, from the one `/batch/v1` entry):
1. **calibrate** — time-based blind oracle (`SELECT IF((cond),SLEEP(n),0)`),
   jitter-calibrated.
2. **seed** — forge a post holding 3 self-`[embed]`s to create 3 real
   `oembed_cache` rows.
3. **recover** — blind-extract the table prefix, an administrator's ID, and the 3
   `oembed_cache` row IDs (by `post_name = md5(embed_url . size)`).
4. **escalate** — fire the forge + escalation batch (steps 2–7 above) → new admin.
5. **RCE** — log in as the new admin, upload a one-shot command plugin, run the
   command (the plugin self-deletes afterwards).

The dropped plugin only runs the command you pass (`-c`) and removes itself —
**no persistent shell**, by design.

## References

- Discovery (Adam Kues / Searchlight Cyber): https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/
- WordPress 7.0.2 release: https://wordpress.org/news/2026/07/wordpress-7-0-2-release/
- Reference implementation that tipped the missing gadget (the
  `customize_changeset` + `parse_request` re-entry escalation):
  https://github.com/sergiointel/wp2shell-poc

For authorized security testing and education only.
