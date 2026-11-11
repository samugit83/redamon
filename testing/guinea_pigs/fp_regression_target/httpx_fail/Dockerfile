# Tagged as projectdiscovery/httpx:latest for a few seconds by
# `e2e_fp.py --httpx-fail` (R-21): the probe container exits 3 and writes no
# output, as a broken httpx image would. e2e_fp.py puts the real tag back.
FROM busybox:1.37.0
ENTRYPOINT ["sh", "-c", "echo 'fp lab: httpx stand-in failing on purpose' >&2; exit 3", "httpx-fail"]
