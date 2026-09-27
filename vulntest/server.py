#!/usr/bin/env python3
"""Intentionally vulnerable server (OWNED, localhost only) used to verify the
AutoBounty detection -> triage -> report pipeline end to end."""
import http.server, socketserver, os

FAKE_GIT_CONFIG = b"""[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/owner/private-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
"""

FAKE_ENV = b"""AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://admin:SuperSecret123@db.internal:5432/prod
STRIPE_SECRET_KEY=sk_live_51Hb..."
"""

class V(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path.startswith("/.git/"):
            body = FAKE_GIT_CONFIG if path.endswith("config") else b"ref: refs/heads/main\n"
            self.send_response(200); self.end_headers(); self.wfile.write(body)
        elif path == "/.env":
            self.send_response(200); self.end_headers(); self.wfile.write(FAKE_ENV)
        elif path == "/.git/HEAD":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ref: refs/heads/main\n")
        else:
            self.send_response(404); self.end_headers(); self.wfile.write(b"not found")
    def log_message(self, *a): pass

if __name__ == "__main__":
    with socketserver.TCPServer(("127.0.0.1", 8899), V) as httpd:
        httpd.allow_reuse_address = True
        httpd.serve_forever()
