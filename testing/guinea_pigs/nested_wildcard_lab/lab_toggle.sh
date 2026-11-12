#!/usr/bin/env bash
# Switch a lab behaviour for the next run. Each writes or removes a runtime
# include under out/extra/ (gitignored) and reloads that host; the tracked
# configuration never changes.
#
#   lab_toggle.sh plain-fixed     plain.nwlab.test stops asking for Basic auth
#   lab_toggle.sh plain-auth      plain.nwlab.test asks for it again (default)
#   lab_toggle.sh x8443 on|off    X (web5) of two.nwlab.test listens on 8443 too
#   lab_toggle.sh dmarc drop|fixed|off   R-24: _dmarc.nwlab-two.test unanswered /
#                                 nwlab-two.test publishes DMARC / the default zones
#                                 (recreates labdns from a tracked Corefile variant)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out/extra/web4 out/extra/web5

case "${1:-}" in
    plain-fixed)
        echo 'set $plain_auth off;' > out/extra/web4/plain-fixed.conf
        docker exec redamon-nwlab-web4 nginx -s reload ;;
    plain-auth)
        rm -f out/extra/web4/plain-fixed.conf
        docker exec redamon-nwlab-web4 nginx -s reload ;;
    x8443)
        if [ "${2:-}" = on ]; then
            cat > out/extra/web5/x8443.conf <<'CONF'
server {
    access_log /dev/stdout nwlab;
    listen 8443 ssl;
    server_name _;
    default_type text/html;
    location = / {
        return 200 "<!doctype html><html><head><title>two.nwlab.test (X 8443)</title></head><body><h1>X 8443</h1></body></html>\n";
    }
}
CONF
        else
            rm -f out/extra/web5/x8443.conf
        fi
        docker exec redamon-nwlab-web5 nginx -s reload ;;
    dmarc)
        case "${2:-}" in
            drop)  conf=Corefile.dmarc-drop ;;
            fixed) conf=Corefile.dmarc-fixed ;;
            off)   conf=Corefile ;;
            *) echo "dmarc drop|fixed|off" >&2; exit 2 ;;
        esac
        NWLAB_COREFILE=$conf docker compose up -d --no-deps --force-recreate labdns ;;
    *)
        sed -n '2,13p' "$0"; exit 2 ;;
esac
# nginx -s reload only signals the master; give the new workers a moment
sleep 2
echo "[*] $*: done"
