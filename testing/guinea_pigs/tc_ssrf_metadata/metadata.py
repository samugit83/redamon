"""A fake cloud instance metadata service (the IMDSv1 paths of the common providers' style).

It lives on the lab's internal network only; the link-preview app routes 169.254.169.254
here. Every value is fake. The canary is the end of the role's SecretAccessKey, taken from
TC_CANARY so each lab instance of the matrix serves its own. The key names avoid the prefixes
real cloud keys start with, so no secret scanner mistakes them for one.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANARY = os.environ.get("TC_CANARY", "tcm-default-canary-0000")
ROLE = "tc-lab-preview-role"
CREDENTIAL = {
    "Code": "Success",
    "LastUpdated": "2099-01-01T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "TCLABFAKEACCESSKEYID",
    "SecretAccessKey": f"tc-lab-fake-secret-{CANARY}",
    "Token": "tc-lab-fake-session-token",
    "Expiration": "2099-01-01T06:00:00Z",
}
PATHS = {
    "/": "latest\n",
    "/latest/": "meta-data\nuser-data\n",
    "/latest/meta-data/": "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\n",
    "/latest/meta-data/ami-id": "ami-tclab0000\n",
    "/latest/meta-data/hostname": "preview-01.tc-lab.invalid\n",
    "/latest/meta-data/instance-id": "i-tclab000000000001\n",
    "/latest/meta-data/local-ipv4": "10.0.0.15\n",
    "/latest/meta-data/iam/": "info\nsecurity-credentials/\n",
    "/latest/meta-data/iam/info": json.dumps({"Code": "Success", "InstanceProfileArn": f"arn:tc-lab:iam::000000000000:instance-profile/{ROLE}"}),
    "/latest/meta-data/iam/security-credentials/": f"{ROLE}\n",
    f"/latest/meta-data/iam/security-credentials/{ROLE}": json.dumps(CREDENTIAL, indent=2),
    "/latest/user-data": "#!/bin/sh\necho preview service\n",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "EC2ws"

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            body, status = "ok", 200
        elif path in PATHS:
            body, status = PATHS[path], 200
        else:
            body, status = "Not Found", 404
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"[metadata] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
