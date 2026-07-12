from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from urllib.parse import urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            body = b"<h1>Launch Card</h1><p>Results publish automatically.</p><a href='/result/demo'>Published</a>"
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body)
        elif path.startswith("/result/") or path.startswith("/results/"):
            body = b"<h1>Demo launch card</h1>"; self.send_response(200); self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers(); self.wfile.write(b"Not found")


def main():
    port = int(os.getenv("PORT", "8787"))
    print(f"Launch Card listening on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__": main()

