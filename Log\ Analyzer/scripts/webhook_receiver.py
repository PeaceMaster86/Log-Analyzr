from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"raw": body}

        print("WEBHOOK RECEIVED:", json.dumps(payload, indent=2), flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8081), Handler)
    print("Webhook receiver listening on :8081", flush=True)
    server.serve_forever()
