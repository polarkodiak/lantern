"""Offline tests for monitor.py. Run with: python -m unittest discover -s tests

Uses made-up keywords and pages only, and a fake Playwright (tests/fakepw),
so no browser or network access is needed.
"""

import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import zlib
from contextlib import redirect_stdout
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
FAKEPW = os.path.join(TESTS, "fakepw")
sys.path[:0] = [REPO, FAKEPW]

import monitor  # noqa: E402

URL = "https://www.example.invalid/notices"
PAGE_ENV = {
    "WATCH_URL": URL,
    "SECTION_START": "Current Notices",
    "SECTION_END": "Past Notices",
}
CHECK_ENV = {
    "WATCH_URL": URL,
    "KEYWORDS": "Maple Grove, oakdale ,OAKDALE,,pinecrest",
    "STATE_KEY": "k" * 40,
    "NTFY_TOPIC": "abcDEF123_random_topic",
}
PAGE_NONE = ("Menu Home Pinecrest Office\nCurrent\nNotices\n12 Elm St (Riverside)\n"
             "Past Notices\nOld one in Pinecrest\nFooter Pinecrest")
PAGE_MATCH = PAGE_NONE.replace("12 Elm St (Riverside)", "12 Elm St (Riverside)\n4 Birch Rd, Maple \nGrove area")
PAGE_MATCH_MORE = PAGE_MATCH.replace("Past", "9 Ash Ct (Riverside)\nPast")
PAGE_TWO = PAGE_MATCH.replace("Past", "Oakdale Blvd\nPast")


class Monitor:
    """Runs the fetch and check commands in a temporary directory, the way
    the two workflow jobs do, with notifications captured instead of sent."""

    def __init__(self, page_env=None, check_env=None):
        self.tmp = tempfile.mkdtemp()
        self.page_env = dict(PAGE_ENV, **(page_env or {}))
        self.check_env = dict(CHECK_ENV, **(check_env or {}))

    def path(self, name):
        return os.path.join(self.tmp, name)

    def fetch(self, page, final_url=None, goto_fails=0):
        with open(self.path("page.txt"), "w") as f:
            f.write(page)
        env = dict(self.page_env, FAKE_PAGE=self.path("page.txt"), FAKE_GOTO_FAILS=str(goto_fails))
        if final_url:
            env["FAKE_FINAL_URL"] = final_url
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(monitor, "PAGE_FILE", self.path("page.bin")), \
             mock.patch.object(monitor, "SECTION_TIMEOUT", 0), \
             mock.patch.object(monitor, "RETRY_PAUSE", 0), \
             redirect_stdout(io.StringIO()):
            monitor.run_fetch()

    def check(self, fail=None, duration=0):
        sent = []

        def fake_post(url, data, headers):
            if fail and fail in url:
                raise OSError("down")
            sent.append((url, data, headers))
            return b'{"status":1}'

        out = io.StringIO()
        with mock.patch.dict(os.environ, self.check_env, clear=True), \
             mock.patch.object(monitor, "post", fake_post), \
             mock.patch.object(monitor, "PAGE_FILE", self.path("page.bin")), \
             mock.patch.object(monitor, "STATE_FILE", self.path("state.json")), \
             mock.patch.object(monitor, "CHECK_DURATION", duration), \
             redirect_stdout(out):
            monitor.run_check()
        return sent, out.getvalue()

    def __call__(self, page, fail=None):
        self.fetch(page)
        return self.check(fail)

    def state(self):
        with open(self.path("state.json")) as f:
            return f.read()


class AlertTests(unittest.TestCase):
    def test_alert_lifecycle(self):
        m = Monitor()
        sent, out1 = m(PAGE_NONE)
        self.assertEqual(sent, [])  # keyword only in nav, past list and footer
        sent, out2 = m(PAGE_MATCH)
        self.assertEqual(len(sent), 1)  # matched across a line break and a non-breaking space
        self.assertEqual(out1, out2)  # same log output with or without a match
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(sent, [])  # nothing changed, no repeat
        sent, _ = m(PAGE_MATCH_MORE)
        self.assertEqual(len(sent), 1)  # section changed while still listed
        sent, _ = m(PAGE_TWO)
        self.assertEqual(len(sent), 1)
        sent, _ = m(PAGE_NONE)
        self.assertEqual(sent, [])  # removal never alerts
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(len(sent), 1)  # back again, alert again

    def test_default_message_has_title_and_link_but_no_areas(self):
        sent, _ = Monitor()(PAGE_MATCH)
        url, data, _ = sent[0]
        body = json.loads(data)
        self.assertEqual(url, "https://ntfy.sh/")
        self.assertEqual(body["topic"], CHECK_ENV["NTFY_TOPIC"])
        self.assertEqual(body["title"], "Watched page alert")
        self.assertEqual(body["click"], URL)
        self.assertNotIn("maple", body["message"].lower())

    def test_check_takes_the_same_time_with_or_without_an_alert(self):
        for page, alerts in ((PAGE_NONE, 0), (PAGE_MATCH, 1)):
            m = Monitor()
            m.fetch(page)
            with mock.patch.object(monitor.time, "sleep") as sleep:
                sent, _ = m.check(duration=20)
            self.assertEqual(len(sent), alerts)
            padded = sleep.call_args.args[0]
            self.assertTrue(19 < padded <= 20, padded)  # padded up to the fixed duration

    def test_alert_title_override(self):
        sent, _ = Monitor(check_env={"ALERT_TITLE": "Custom"})(PAGE_MATCH)
        self.assertEqual(json.loads(sent[0][1])["title"], "Custom")

    def test_details_and_both_channels(self):
        m = Monitor(check_env={"NOTIFY_DETAILS": "true", "PUSHOVER_TOKEN": "t",
                               "PUSHOVER_USER": "u", "NTFY_TOKEN": "tk_x"})
        sent, _ = m(PAGE_TWO)
        self.assertEqual(len(sent), 2)
        message = json.loads(sent[0][1])["message"]
        self.assertIn("maple grove", message)
        self.assertIn("oakdale", message)
        self.assertEqual(sent[0][2]["Authorization"], "Bearer tk_x")
        self.assertIn(b"token=t", sent[1][1])

    def test_failed_delivery_is_retried(self):
        m = Monitor()
        with self.assertRaises(monitor.AlertError) as ctx:
            m(PAGE_MATCH, fail="ntfy")
        self.assertIn("ntfy", str(ctx.exception))
        self.assertFalse(os.path.exists(m.path("state.json")))
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(len(sent), 1)

    def test_missing_end_marker_keeps_rest(self):
        sent, _ = Monitor()(PAGE_NONE.replace("Past Notices", "Something"))
        self.assertEqual(len(sent), 1)  # errs toward alerting


class StateTests(unittest.TestCase):
    def test_state_is_private_and_fixed_size(self):
        m = Monitor()
        m(PAGE_NONE)
        a = m.state()
        m(PAGE_NONE)
        b = m.state()
        m(PAGE_TWO)
        c = m.state()
        self.assertNotEqual(a, b)  # fresh salt each run
        self.assertEqual({len(a), len(b)}, {len(c)})
        for s in (a, b, c):
            self.assertNotIn("maple", s.lower())
            self.assertNotIn("oakdale", s.lower())

    def test_corrupt_state_counts_as_first_run(self):
        for bad in ["not json", "[]", '{"salt":"zz","page":"00","matches":"00"}',
                    '{"salt":"00","page":"\\u00e9","matches":"00"}', '{"salt":1}']:
            m = Monitor()
            with open(m.path("state.json"), "w") as f:
                f.write(bad)
            sent, _ = m(PAGE_MATCH)
            self.assertEqual(len(sent), 1, bad)

    def test_page_handover_is_fixed_size_and_round_trips(self):
        a = monitor.pack_section("short")
        b = monitor.pack_section("a much longer section " * 200)
        self.assertEqual(len(a), monitor.PAGE_BLOB_SIZE)
        self.assertEqual(len(b), monitor.PAGE_BLOB_SIZE)
        self.assertEqual(monitor.unpack_section(b), "a much longer section " * 200)
        with self.assertRaises(monitor.PageError):
            monitor.unpack_section(b[:-1])
        with self.assertRaises(monitor.PageError):
            monitor.unpack_section(b"\xff" * monitor.PAGE_BLOB_SIZE)
        with self.assertRaises(monitor.PageError):
            monitor.pack_section(os.urandom(70_000).hex())

    def test_unpacking_is_capped(self):
        with self.assertRaises(monitor.PageError):
            monitor.pack_section("a" * (monitor.MAX_SECTION_BYTES + 1))  # compresses small, still refused
        bomb = zlib.compress(b"a" * 10_000_000)  # a forged hand-over that expands to 10 MB
        blob = len(bomb).to_bytes(4, "big") + bomb
        blob += b"\0" * (monitor.PAGE_BLOB_SIZE - len(blob))
        with self.assertRaises(monitor.PageError):
            monitor.unpack_section(blob)
        valid = monitor.pack_section("short section")
        with self.assertRaises(monitor.PageError):  # declared length doesn't match the data
            monitor.unpack_section((999).to_bytes(4, "big") + valid[4:])


class PageTests(unittest.TestCase):
    def test_missing_section_fails_without_touching_state(self):
        m = Monitor()
        m(PAGE_MATCH)
        before = m.state()
        with self.assertRaises(monitor.PageError):
            m.fetch("Loading...")
        self.assertEqual(before, m.state())

    def test_one_failed_load_is_retried(self):
        m = Monitor()
        m.fetch(PAGE_MATCH, goto_fails=1)
        sent, _ = m.check()
        self.assertEqual(len(sent), 1)

    def test_two_failed_loads_fail_the_check(self):
        with self.assertRaises(RuntimeError):
            Monitor().fetch(PAGE_MATCH, goto_fails=2)

    def test_redirect_away_from_site_fails(self):
        m = Monitor()
        for final in ["https://evil.invalid/notices", "http://www.example.invalid/notices"]:
            with self.assertRaises(monitor.PageError, msg=final):
                m.fetch(PAGE_MATCH, final_url=final)
        m.fetch(PAGE_MATCH, final_url="https://example.invalid/moved")  # same site, www optional

    def test_fetch_needs_only_page_settings(self):
        with mock.patch.dict(os.environ, PAGE_ENV, clear=True):
            monitor.load_fetch_config()

    def test_check_never_imports_playwright(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        with mock.patch.dict(sys.modules, {"playwright": None, "playwright.sync_api": None}):
            sent, _ = m.check()
        self.assertEqual(len(sent), 1)


class ConfigTests(unittest.TestCase):
    def test_check_config_errors(self):
        cases = [
            {"KEYWORDS": " , "},
            {"STATE_KEY": "short"},
            {"WATCH_URL": "http://example.invalid"},
            {"WATCH_URL": "https://user:pw@example.invalid"},
            {"NTFY_SERVER": "http://ntfy.example"},
            {"NTFY_TOPIC": ""},
            {"PUSHOVER_TOKEN": "t"},
        ]
        for override in cases:
            with mock.patch.dict(os.environ, dict(CHECK_ENV, **override), clear=True):
                with self.assertRaises(monitor.ConfigError, msg=override):
                    monitor.load_check_config()

    def test_fetch_config_errors(self):
        for override in [{"WATCH_URL": "ftp://example.invalid"}, {"SECTION_START": ""}, {"WATCH_URL": ""}]:
            with mock.patch.dict(os.environ, dict(PAGE_ENV, **override), clear=True):
                with self.assertRaises(monitor.ConfigError, msg=override):
                    monitor.load_fetch_config()

    def test_add_mask_only_in_actions(self):
        out = io.StringIO()
        with mock.patch.dict(os.environ, CHECK_ENV, clear=True), redirect_stdout(out):
            monitor.load_check_config()
        self.assertEqual(out.getvalue(), "")
        out = io.StringIO()
        env = dict(CHECK_ENV, GITHUB_ACTIONS="true", WATCH_URL="https://x.invalid/a%20b")
        with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(out):
            monitor.load_check_config()
        lines = out.getvalue().splitlines()
        self.assertTrue(all(line.startswith("::add-mask::") for line in lines))
        self.assertIn("::add-mask::Maple Grove", lines)
        self.assertIn("::add-mask::https://x.invalid/a%2520b", lines)


class _Server(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        _Server.seen.append((self.path, self.headers.get("Authorization")))
        self.send_response(302)
        self.send_header("Location", "/elsewhere")
        self.end_headers()

    do_GET = do_POST

    def log_message(self, *args):
        pass


class NetworkTests(unittest.TestCase):
    def test_redirects_are_refused_and_token_not_forwarded(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _Server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/publish"
            with mock.patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"}):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    monitor.post(url, b"{}", {"Authorization": "Bearer secret"})
            ctx.exception.close()
            self.assertEqual(ctx.exception.code, 302)
            self.assertEqual(_Server.seen, [("/publish", "Bearer secret")])  # never followed
        finally:
            server.shutdown()
            server.server_close()


class CommandLineTests(unittest.TestCase):
    def run_cli(self, args, env, cwd):
        full_env = dict(env, PYTHONPATH=FAKEPW, PATH=os.environ["PATH"])
        return subprocess.run([sys.executable, os.path.join(REPO, "monitor.py"), *args],
                              cwd=cwd, env=full_env, capture_output=True, text=True)

    def test_errors_do_not_leak(self):
        tmp = tempfile.mkdtemp()
        page = os.path.join(tmp, "p.txt")
        with open(page, "w") as f:
            f.write(PAGE_MATCH)
        r = self.run_cli(["fetch"], dict(PAGE_ENV, FAKE_PAGE=page, FAKE_GOTO_FAIL="1"), tmp)
        self.assertEqual((r.returncode, r.stdout, r.stderr.strip()), (1, "", "Check failed: RuntimeError"))
        r = self.run_cli(["check"], {}, tmp)
        self.assertEqual((r.returncode, r.stderr.strip()), (1, "ConfigError: KEYWORDS is not set"))
        r = self.run_cli([], {}, tmp)
        self.assertEqual((r.returncode, r.stderr.strip()), (1, "ConfigError: usage: monitor.py fetch|check"))

    def test_fetch_then_check_end_to_end(self):
        tmp = tempfile.mkdtemp()
        page = os.path.join(tmp, "p.txt")
        with open(page, "w") as f:
            f.write(PAGE_NONE)
        r = self.run_cli(["fetch"], dict(PAGE_ENV, FAKE_PAGE=page), tmp)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "Page loaded."))
        out = io.StringIO()
        env = dict(CHECK_ENV, PATH=os.environ["PATH"])
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(monitor, "PAGE_FILE", os.path.join(tmp, monitor.PAGE_FILE)), \
             mock.patch.object(monitor, "STATE_FILE", os.path.join(tmp, monitor.STATE_FILE)), \
             mock.patch.object(monitor, "CHECK_DURATION", 0), redirect_stdout(out):
            monitor.main(["monitor.py", "check"])  # no match, so nothing is sent
        self.assertEqual(out.getvalue().strip(), "Check complete.")


if __name__ == "__main__":
    unittest.main()
