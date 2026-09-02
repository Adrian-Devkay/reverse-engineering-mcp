from __future__ import annotations

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from web_recon import crawl, normalize_url  # noqa: E402


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/robots.txt":
            body = b"User-agent: *\nAllow: /\n"
            content_type = "text/plain"
        elif self.path == "/":
            body = b'<html><a href="/two?token=do-not-write">two</a><a href="https://outside.invalid/">outside</a></html>'
            content_type = "text/html"
        elif self.path.startswith("/two"):
            body = b"<html>fixture</html>"
            content_type = "text/html"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


class WebReconTests(unittest.TestCase):
    def test_scope_and_private_destination_guards(self) -> None:
        with self.assertRaises(ValueError):
            normalize_url("https://not-example.test/", ["example.test"])
        with self.assertRaises(ValueError):
            normalize_url("http://127.0.0.1/", ["127.0.0.1"])
        self.assertEqual(
            normalize_url("https://example.test/path?token=secret#fragment", ["example.test"], allow_private_network=True),
            "https://example.test/path?token=secret",
        )

    def test_local_fixture_is_bounded_and_redacts_query_values(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            result = crawl(
                [f"http://127.0.0.1:{port}/"],
                ["127.0.0.1"],
                max_pages=3,
                max_depth=1,
                max_response_bytes=4096,
                max_total_bytes=16384,
                timeout_seconds=2,
                delay_seconds=0,
                allow_private_network=True,
                allow_nonstandard_port=True,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result["summary"]["pages_observed"], 2)
        self.assertEqual(result["policy"]["method"], "GET")
        self.assertTrue(result["policy"]["credentials"] is False)
        serialized = str(result)
        self.assertNotIn("do-not-write", serialized)
        self.assertNotIn("outside.invalid", serialized)
        self.assertTrue(all("response_sha256" in page for page in result["pages"]))


if __name__ == "__main__":
    unittest.main()
