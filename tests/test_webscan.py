import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from owaspscan.webscan import scan_url


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # keep test output quiet

    def do_GET(self):
        if self.path.startswith("/.git/HEAD"):
            body = b"ref: refs/heads/main\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path.startswith("/search"):
            from urllib.parse import urlsplit, parse_qs
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            if "'" in q:
                body = ("Warning: mysqli_query(): SQL syntax error near "
                        "'" + q + "' at line 1").encode()
            else:
                body = f"<html><body>results for {q}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session=abc123; Path=/")
            self.send_header("Server", "Apache/2.2.14")
            self.end_headers()
            self.wfile.write(body)
            return

        # soft-404 catch-all
        body = b"<html>not found here</html>"
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WebScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), VulnHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_missing_security_headers(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3)
        ids = {f.rule_id for f in findings}
        self.assertIn("OWS-WEB-A05-001", ids)  # missing CSP/HSTS/etc.

    def test_server_banner_disclosed(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3)
        self.assertIn("OWS-WEB-A05-002", {f.rule_id for f in findings})

    def test_cookie_missing_httponly(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3)
        self.assertIn("OWS-WEB-A07-001", {f.rule_id for f in findings})

    def test_exposed_git_head(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3)
        self.assertIn("OWS-WEB-A01-001", {f.rule_id for f in findings})

    def test_sql_error_reflected(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3)
        self.assertIn("OWS-WEB-A03-002", {f.rule_id for f in findings})

    def test_xss_reflection(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3)
        self.assertIn("OWS-WEB-A03-001", {f.rule_id for f in findings})

    def test_path_probe_can_be_disabled(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3, path_probe=False)
        self.assertNotIn("OWS-WEB-A01-001", {f.rule_id for f in findings})

    def test_param_probe_can_be_disabled(self):
        findings = scan_url(f"{self.base}/search?q=hello", delay=0, timeout=3, param_probe=False)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("OWS-WEB-A03-001", ids)
        self.assertNotIn("OWS-WEB-A03-002", ids)


if __name__ == "__main__":
    unittest.main()
