#!/usr/bin/env bash
# The timeout path of the ZAP Ajax Spider against real Docker: run one seed
# through the recon image and the docker broker, exactly as a scan does, with
# the per-seed timeout forced to 45 s so the crawl cannot finish. The helper
# must kill the container by name; afterwards no redamon-zap-ajax-* container
# may exist. Needs the stack (the broker) and this lab up.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"

curl -fsS -o /dev/null --max-time 5 http://192.88.95.10/ \
  || { echo "[!] lab is down: run 'docker compose up -d' in $HERE"; exit 2; }

# -i: the check is the heredoc below, read from stdin. Without it the container
# gets an empty script, runs nothing and exits 0, so the verdict lines are
# required as well.
out="$(docker run --rm -i \
  -v redamon_broker_socket:/var/run/broker \
  -e DOCKER_HOST=unix:///var/run/broker/docker.sock \
  -v /tmp/redamon:/tmp/redamon \
  -v "$REPO/recon:/app/recon:ro" \
  -e PYTHONPATH=/app -e PYTHONDONTWRITEBYTECODE=1 \
  --entrypoint python redamon-recon - <<'PY'
import json, os, subprocess, sys, tempfile, time, uuid

# A scan's recon container names its run to the broker (recon/entrypoint.sh
# writes this header into the Docker CLI's config); the broker lists only that
# run's containers, so without it the leftover check below would see nothing.
config = tempfile.mkdtemp(prefix="zaplab-docker-")
with open(os.path.join(config, "config.json"), "w") as f:
    json.dump({"HttpHeaders": {"X-Redamon-Run": f"full_recon:zaplab:{uuid.uuid4().hex}"}}, f)
os.environ["DOCKER_CONFIG"] = config

from recon.helpers.resource_enum import zap_ajax_spider_helpers as zap

zap._zap_seed_timeout = lambda max_duration: 45
started = time.time()
_, meta = zap.run_zap_ajax_spider(
    ["http://192.88.95.10/"], "ghcr.io/zaproxy/zaproxy:stable", [], [], [], 100,
    1, 3, 0, 1, "firefox-headless", 1000, 1000, True, True, False, True, "Strict")
elapsed = time.time() - started
time.sleep(5)
ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=redamon-zap-ajax-", "--format", "{{.Names}}"],
                    capture_output=True, text=True)
left = ps.stdout.split()
kinds = [e.get("type") for e in meta.get("errors", [])]
ok_timeout = kinds == ["timeout"]
ok_clean = ps.returncode == 0 and not left
print(f"  {'PASS' if ok_timeout else 'FAIL'}  the seed timed out after {elapsed:.0f}s (errors: {kinds})")
print(f"  {'PASS' if ok_clean else 'FAIL'}  no ZAP container left behind {left if left else ''}")
sys.exit(0 if ok_timeout and ok_clean else 1)
PY
)" || { echo "$out"; exit 1; }
echo "$out"
[ "$(grep -c '^  PASS' <<<"$out")" -eq 2 ] || { echo "[!] the check did not report both verdicts"; exit 1; }
