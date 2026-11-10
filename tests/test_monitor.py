"""Offline tests for monitor.py. Run with: python -m unittest discover -s tests

Uses made-up keywords and pages only, a fake Playwright (tests/fakepw) and
throwaway key pairs generated with openssl when the tests start, so no
browser, network access or real keys are needed.
"""

import base64
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zlib
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest import mock

TESTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TESTS)
FAKEPW = os.path.join(TESTS, "fakepw")
sys.path[:0] = [REPO, FAKEPW]

import monitor  # noqa: E402
from playwright import sync_api as fake_playwright  # noqa: E402

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

KEYS = {}


def make_key_pair(name, bits=3072, days=730):
    key, cert = os.path.join(KEYS["dir"], name + ".key"), os.path.join(KEYS["dir"], name + ".crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", f"rsa:{bits}", "-sha256", "-days", str(days),
                    "-nodes", "-subj", "/CN=test", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    with open(key) as f:
        return f.read(), cert


def setUpModule():
    KEYS["dir"] = tempfile.mkdtemp()
    KEYS["key"], KEYS["cert"] = make_key_pair("main")
    KEYS["other_key"], KEYS["other_cert"] = make_key_pair("other")


def tearDownModule():
    shutil.rmtree(KEYS["dir"], ignore_errors=True)


class Monitor:
    """Runs the fetch and check commands in a temporary directory, the way
    the two workflow jobs do, with notifications captured instead of sent."""

    def __init__(self, page_env=None, check_env=None):
        self.tmp = tempfile.mkdtemp()
        self.page_env = dict(PAGE_ENV, **(page_env or {}))
        self.check_env = {**CHECK_ENV, "HANDOVER_KEY": KEYS["key"], **(check_env or {})}
        self.extra_check_env = {}  # set by a test to override HANDOVER or PREVIOUS_STATE

    def path(self, name):
        return os.path.join(self.tmp, name)

    def fetch(self, page, final_url=None, goto_fails=0, changing=False, cert=None, fake=None):
        env = dict(self.page_env, FAKE_PAGE_TEXT=page, FAKE_GOTO_FAILS=str(goto_fails),
                   PATH=os.environ["PATH"], **(fake or {}))
        if final_url:
            env["FAKE_FINAL_URL"] = final_url
        if changing:
            env["FAKE_CHANGING"] = "1"
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(monitor, "PAGE_FILE", self.path("page.bin")), \
             mock.patch.object(monitor, "HANDOVER_CERT", cert or KEYS["cert"]), \
             mock.patch.object(monitor, "SECTION_TIMEOUT", 0), \
             mock.patch.object(monitor, "STABLE_TIMEOUT", 0), \
             mock.patch.object(monitor, "RETRY_PAUSE", 0), \
             redirect_stdout(out):
            monitor.run_fetch()
        return out.getvalue()

    def check(self, fail=None, duration=0, replies=None, delays=None):
        """Runs the check the way the workflow does: the hand-over and the
        previous state arrive base64-encoded in HANDOVER and PREVIOUS_STATE
        (empty when there's no saved state), and the new state is written to
        state.json. replies and delays override a service's reply or make it
        slow, keyed by "ntfy" or "pushover"."""
        sent = []

        def fake_post(url, data, headers, deadline):
            service = "ntfy" if "ntfy" in url else "pushover"
            if fail and fail in url:
                raise OSError("down")
            if delays and service in delays:
                time.sleep(delays[service])
            sent.append((url, data, headers))
            if replies and service in replies:
                return replies[service]
            if service == "ntfy":
                return json.dumps({"id": "abc", "event": "message", "topic": json.loads(data)["topic"]}).encode()
            return b'{"status":1}'

        env = dict(self.check_env, PATH=os.environ["PATH"])
        if os.path.exists(self.path("page.bin")):
            env["HANDOVER"] = base64.b64encode(self.handover()).decode()
        env["PREVIOUS_STATE"] = ""
        if os.path.exists(self.path("state.json")):
            with open(self.path("state.json"), "rb") as f:
                env["PREVIOUS_STATE"] = base64.b64encode(f.read()).decode()
        env.update(self.extra_check_env)
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(monitor, "post", fake_post), \
             mock.patch.object(monitor, "PAGE_FILE", self.path("page.bin")), \
             mock.patch.object(monitor, "STATE_FILE", self.path("state.json")), \
             mock.patch.object(monitor, "DELIVERY_FAILED_FILE", self.path("delivery-failed")), \
             mock.patch.object(monitor, "HANDOVER_CERT", KEYS["cert"]), \
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

    def handover(self):
        with open(self.path("page.bin"), "rb") as f:
            return f.read()

    def write_handover(self, data):
        with open(self.path("page.bin"), "wb") as f:
            f.write(data)


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
        self.assertEqual(body["tags"], ["warning"])
        self.assertNotIn("maple", body["message"].lower())

    def test_check_takes_the_same_time_whatever_happens(self):
        cases = [(PAGE_NONE, None, 0), (PAGE_MATCH, None, 1), (PAGE_TWO, "ntfy", 0)]
        for page, fail, alerts in cases:
            m = Monitor()
            m.fetch(page)
            with mock.patch.object(monitor.time, "sleep") as sleep:
                sent, out = m.check(fail=fail, duration=45)
            self.assertEqual(len(sent), alerts)
            self.assertEqual(out, "Check complete.\n")
            padded = sleep.call_args.args[0]
            self.assertTrue(44 < padded <= 45, (page[:20], fail, padded))

    def test_alert_title_override(self):
        sent, _ = Monitor(check_env={"ALERT_TITLE": "Custom"})(PAGE_MATCH)
        self.assertEqual(json.loads(sent[0][1])["title"], "Custom")

    def test_details_and_both_channels(self):
        m = Monitor(check_env={"NOTIFY_DETAILS": "true", "PUSHOVER_TOKEN": "t",
                               "PUSHOVER_USER": "u", "NTFY_TOKEN": "tk_x", "NTFY_TAGS": "warning, bell ,"})
        sent, _ = m(PAGE_TWO)
        self.assertEqual(len(sent), 2)
        # The two are sent at the same time, so they can arrive in either order.
        by_service = {("ntfy" if "ntfy" in url else "pushover"): (data, headers) for url, data, headers in sent}
        ntfy_data, ntfy_headers = by_service["ntfy"]
        self.assertEqual(json.loads(ntfy_data)["tags"], ["warning", "bell"])
        message = json.loads(ntfy_data)["message"]
        self.assertIn("maple grove", message)
        self.assertIn("oakdale", message)
        self.assertEqual(ntfy_headers["Authorization"], "Bearer tk_x")
        self.assertIn(b"token=t", by_service["pushover"][0])

    def test_failed_delivery_is_private_and_retried(self):
        m = Monitor()
        sent, out = m(PAGE_MATCH, fail="ntfy")  # doesn't raise: the public run stays green
        self.assertEqual((sent, out), ([], "Check complete.\n"))
        self.assertTrue(os.path.exists(m.path("delivery-failed")))  # the heartbeat reports it privately
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(len(sent), 1)  # the next run alerts again
        self.assertFalse(os.path.exists(m.path("delivery-failed")))  # and clears the old marker

    def test_failed_delivery_is_dropped_once_the_listing_is_gone(self):
        # Alerts describe the page as it is now: a failed alert is resent
        # only while a keyword is still listed.
        m = Monitor()
        m(PAGE_MATCH, fail="ntfy")
        sent, _ = m(PAGE_NONE)
        self.assertEqual(sent, [])
        self.assertFalse(os.path.exists(m.path("delivery-failed")))

    BOTH = {"PUSHOVER_TOKEN": "t", "PUSHOVER_USER": "u"}
    NTFY, PUSHOVER = "https://ntfy.sh/", "https://api.pushover.net/1/messages.json"

    def test_only_the_channel_that_failed_is_alerted_again(self):
        m = Monitor(check_env=self.BOTH)
        sent, _ = m(PAGE_MATCH, fail="pushover")
        self.assertEqual([url for url, _, _ in sent], [self.NTFY])  # ntfy confirmed
        self.assertTrue(os.path.exists(m.path("delivery-failed")))
        sent, _ = m(PAGE_MATCH)
        self.assertEqual([url for url, _, _ in sent], [self.PUSHOVER])  # same page: pushover only
        self.assertFalse(os.path.exists(m.path("delivery-failed")))
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(sent, [])  # both up to date
        sent, _ = m(PAGE_MATCH_MORE)
        self.assertEqual(len(sent), 2)  # a change alerts both again
        m(PAGE_NONE)
        m(PAGE_MATCH, fail="pushover")
        sent, _ = m(PAGE_NONE)
        self.assertEqual(sent, [])  # the failed one is dropped once the listing is gone
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(len(sent), 2)  # and both are alerted when it's back

    def test_a_channel_added_or_pointed_elsewhere_is_alerted_about_a_current_listing(self):
        m = Monitor()
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(len(sent), 1)
        m.check_env.update(self.BOTH)
        sent, _ = m(PAGE_MATCH)
        self.assertEqual([url for url, _, _ in sent], [self.PUSHOVER])  # the new one only
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(sent, [])
        # A new destination counts as a new channel; a new token doesn't.
        for setting, value, alerted in [("NTFY_TOPIC", "another_topic", [self.NTFY]),
                                        ("NTFY_SERVER", "https://ntfy.example.invalid/", ["https://ntfy.example.invalid/"]),
                                        ("PUSHOVER_USER", "u2", [self.PUSHOVER]),
                                        ("NTFY_TOKEN", "tk_new", []), ("PUSHOVER_TOKEN", "t2", [])]:
            m.check_env[setting] = value
            sent, _ = m(PAGE_MATCH)
            self.assertEqual([url for url, _, _ in sent], alerted, setting)
            sent, _ = m(PAGE_MATCH)
            self.assertEqual(sent, [], setting)

    def test_service_reply_must_confirm_the_message(self):
        both = {"PUSHOVER_TOKEN": "t", "PUSHOVER_USER": "u"}
        for service, reply in [("ntfy", b"<html>Welcome</html>"), ("ntfy", b'{"event":"message","topic":"other","id":"x"}'),
                               ("ntfy", b'{"event":"keepalive","topic":"abcDEF123_random_topic","id":"x"}'),
                               ("pushover", b"<html>"), ("pushover", b'{"status":0}'), ("pushover", b"[1]")]:
            m = Monitor(check_env=both)
            m.fetch(PAGE_MATCH)
            sent, _ = m.check(replies={service: reply})
            self.assertEqual(len(sent), 2, reply)  # both were tried
            self.assertTrue(os.path.exists(m.path("delivery-failed")), (service, reply))

    def test_slow_service_cant_stretch_the_check(self):
        m = Monitor(check_env={"PUSHOVER_TOKEN": "t", "PUSHOVER_USER": "u"})
        m.fetch(PAGE_MATCH)
        started = time.monotonic()
        with mock.patch.object(monitor, "SEND_BUDGET", 1):
            sent, _ = m.check(delays={"ntfy": 3})
        self.assertLess(time.monotonic() - started, 2.5)  # didn't wait for ntfy
        self.assertEqual([url for url, _, _ in sent], ["https://api.pushover.net/1/messages.json"])
        self.assertTrue(os.path.exists(m.path("delivery-failed")))  # ntfy counts as failed

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

    def test_state_neither_shows_a_failed_delivery_nor_can_be_forged(self):
        m = Monitor(check_env=AlertTests.BOTH)
        m(PAGE_MATCH)
        ok = m.state()
        m.fetch(PAGE_MATCH_MORE)
        m.check(fail="pushover")
        failed = m.state()
        self.assertEqual(len(ok), len(failed))
        self.assertEqual(set(json.loads(ok)), set(json.loads(failed)))
        for s in (ok, failed):
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", json.loads(s)[c]) for c in monitor.CHANNELS))
        # Copying ntfy's value into pushover's field doesn't make pushover up to date.
        state = json.loads(failed)
        state["pushover"] = state["ntfy"]
        with open(m.path("state.json"), "w") as f:
            json.dump(state, f)
        sent, _ = m(PAGE_MATCH_MORE)
        self.assertEqual([url for url, _, _ in sent], [AlertTests.PUSHOVER])
        # A damaged value errs toward alerting that channel, and only that one.
        state = json.loads(m.state())
        state["ntfy"] = "0" * 64
        with open(m.path("state.json"), "w") as f:
            json.dump(state, f)
        sent, _ = m(PAGE_MATCH_MORE)
        self.assertEqual([url for url, _, _ in sent], [AlertTests.NTFY])
        # A state in the earlier format, without the channel fields, counts as a first run.
        state = {k: v for k, v in json.loads(m.state()).items() if k not in monitor.CHANNELS}
        with open(m.path("state.json"), "w") as f:
            json.dump(state, f)
        sent, _ = m(PAGE_MATCH_MORE)
        self.assertEqual(len(sent), 2)

    def test_corrupt_state_counts_as_first_run(self):
        for bad in ["not json", "[]", '{"salt":"zz","page":"00","matches":"00"}',
                    '{"salt":"00","page":"\\u00e9","matches":"00"}', '{"salt":1}']:
            m = Monitor()
            with open(m.path("state.json"), "w") as f:
                f.write(bad)
            sent, _ = m(PAGE_MATCH)
            self.assertEqual(len(sent), 1, bad)

    RUN = (7).to_bytes(8, "big") + (1).to_bytes(4, "big")

    def test_old_future_or_altered_state_counts_as_first_run(self):
        now = time.time()
        for saved_at, label in [(now - monitor.MAX_STATE_AGE - 60, "too old"), (now + 3600, "from the future"),
                                (now - monitor.MAX_STATE_AGE + 60, "old but within the limit")]:
            m = Monitor()
            with mock.patch.object(monitor, "wall_clock", return_value=saved_at):
                sent, _ = m(PAGE_MATCH)  # this run's state is saved at saved_at
            self.assertEqual(len(sent), 1)
            sent, _ = m(PAGE_MATCH)  # same page, checked now
            self.assertEqual(len(sent), 0 if "within" in label else 1, label)
        # a state whose time was changed to look fresh no longer matches its HMACs
        m = Monitor()
        m(PAGE_MATCH)
        fresh = json.loads(m.state())
        fresh["time"] -= 1
        with open(m.path("state.json"), "w") as f:
            json.dump(fresh, f)
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(len(sent), 1)
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(sent, [])  # and the next run is back to normal

    def test_re_runs_are_refused(self):
        run = {"GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "2"}
        m = Monitor(page_env=run, check_env=run)
        m.fetch(PAGE_MATCH)
        with self.assertRaises(monitor.ConfigError) as ctx:
            m.check()
        self.assertIn("start a new run", str(ctx.exception))
        self.assertFalse(os.path.exists(m.path("state.json")))

    def test_state_must_come_from_the_previous_run(self):
        def run(m, number, page):
            m.check_env["GITHUB_RUN_NUMBER"] = str(number)
            return len(m(page)[0])

        m = Monitor()
        self.assertEqual(run(m, 5, PAGE_MATCH), 1)
        self.assertEqual(run(m, 6, PAGE_MATCH), 0)  # the next run: nothing new
        self.assertEqual(run(m, 6, PAGE_MATCH), 0)  # a re-run of the same run counts too
        self.assertEqual(run(m, 8, PAGE_MATCH), 1)  # run 7 left no state: alert again rather than trust an older one
        # The audit's case: A is saved, the save showing it gone is lost, and A
        # comes back. The older state must not hide the new alert.
        m = Monitor()
        self.assertEqual(run(m, 10, PAGE_MATCH), 1)
        with open(m.path("state.json")) as f:
            saved_a = f.read()
        self.assertEqual(run(m, 11, PAGE_NONE), 0)  # A gone; pretend this save was lost:
        with open(m.path("state.json"), "w") as f:
            f.write(saved_a)
        self.assertEqual(run(m, 12, PAGE_MATCH), 1)  # A is back, and alerts
        # a state edited to claim it came from a later run no longer matches its HMACs
        m = Monitor()
        run(m, 30, PAGE_MATCH)
        state = json.loads(m.state())
        state["run"] = 31
        with open(m.path("state.json"), "w") as f:
            json.dump(state, f)
        self.assertEqual(run(m, 32, PAGE_MATCH), 1)
        # a state from a later run (e.g. when an old run is re-run) isn't trusted either
        m = Monitor()
        run(m, 20, PAGE_MATCH)
        self.assertEqual(run(m, 19, PAGE_MATCH), 1)
        for bad in ("x", "-1", "1" * 19):
            with mock.patch.dict(os.environ, {"GITHUB_RUN_NUMBER": bad}):
                with self.assertRaises(monitor.ConfigError):
                    monitor.current_run_number()

    def test_untrusted_previous_state_input(self):
        m = Monitor()
        m(PAGE_MATCH)
        for bad in ["not base64!", base64.b64encode(b"x" * (monitor.MAX_STATE_BYTES + 1)).decode(),
                    base64.b64encode(b"[" * 4000).decode(),  # nested too deeply to parse
                    "A" * 10_000, base64.b64encode(b'{"salt": "00"}').decode()]:
            m.fetch(PAGE_MATCH)
            m.extra_check_env = {"PREVIOUS_STATE": bad}
            sent, _ = m.check()
            self.assertEqual(len(sent), 1, bad[:30])  # treated as no state, so it alerts
        m.extra_check_env = {}

    def test_page_packing_is_fixed_size_and_round_trips(self):
        a = monitor.pack_section("short", self.RUN)
        b = monitor.pack_section("a much longer section " * 200, self.RUN)
        self.assertEqual(len(a), monitor.PAGE_BLOB_SIZE)
        self.assertEqual(len(b), monitor.PAGE_BLOB_SIZE)
        self.assertEqual(monitor.unpack_section(b, self.RUN), "a much longer section " * 200)
        with self.assertRaises(monitor.PageError):
            monitor.unpack_section(b[:-1], self.RUN)
        with self.assertRaises(monitor.PageError):
            monitor.unpack_section(self.RUN + b"\xff" * (monitor.PAGE_BLOB_SIZE - 12), self.RUN)
        with self.assertRaises(monitor.PageError):
            monitor.pack_section(os.urandom(70_000).hex(), self.RUN)

    def test_unpacking_is_capped(self):
        with self.assertRaises(monitor.PageError):
            monitor.pack_section("a" * (monitor.MAX_SECTION_BYTES + 1), self.RUN)  # compresses small, still refused
        bomb = zlib.compress(b"a" * 10_000_000)  # a forged package that expands to 10 MB
        blob = self.RUN + len(bomb).to_bytes(4, "big") + bomb
        blob += b"\0" * (monitor.PAGE_BLOB_SIZE - len(blob))
        with self.assertRaises(monitor.PageError):
            monitor.unpack_section(blob, self.RUN)
        valid = monitor.pack_section("short section", self.RUN)
        with self.assertRaises(monitor.PageError):  # declared length doesn't match the data
            monitor.unpack_section(self.RUN + (999).to_bytes(4, "big") + valid[16:], self.RUN)

    def test_handover_from_another_run_or_attempt_is_refused(self):
        run = {"GITHUB_RUN_ID": "41350376145", "GITHUB_RUN_ATTEMPT": "1"}
        m = Monitor(page_env=run, check_env=run)
        m.fetch(PAGE_MATCH)
        sent, _ = m.check()
        self.assertEqual(len(sent), 1)  # same run and attempt: accepted
        old_run = m.handover()
        other_attempt = Monitor(page_env={**run, "GITHUB_RUN_ATTEMPT": "2"})
        other_attempt.fetch(PAGE_MATCH)
        for old in (old_run, other_attempt.handover()):
            later = {"GITHUB_RUN_ID": "41350376146", "GITHUB_RUN_ATTEMPT": "1"} if old is old_run else run
            m2 = Monitor(page_env=later, check_env=later)
            m2.fetch(PAGE_NONE)
            m2.write_handover(old)  # a hand-over from another run or attempt
            with mock.patch.object(monitor, "post") as post:
                with self.assertRaises(monitor.PageError) as ctx:
                    m2.check()
            self.assertIn("another run", str(ctx.exception))
            post.assert_not_called()
            self.assertFalse(os.path.exists(m2.path("state.json")))  # state untouched
        for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            for bad in ("abc", "-1", "1.5", "\u00b2", "\u0661", str(2 ** 63)):
                with mock.patch.dict(os.environ, {name: bad}):
                    with self.assertRaises(monitor.ConfigError, msg=(name, bad)):
                        monitor.current_run()


class EncryptionTests(unittest.TestCase):
    def test_handover_is_encrypted_with_the_required_algorithms(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        data = m.handover()
        section = monitor.extract_section(PAGE_MATCH, "current notices", "past notices")
        self.assertNotIn(b"notices", data)
        self.assertNotIn(b"birch", data)
        self.assertNotIn(zlib.compress(section.encode()), data)  # not just compressed
        info = subprocess.run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER"],
                              input=data, capture_output=True, check=True).stdout.decode()
        self.assertIn("aes-256-gcm", info.lower())
        self.assertIn("rsaesOaep", info)
        self.assertIn("sha256", info)

    def test_handover_size_doesnt_depend_on_the_page(self):
        sizes = set()
        for page in (PAGE_NONE, PAGE_TWO, PAGE_NONE.replace("12 Elm St", "a much longer line " * 300)):
            m = Monitor()
            m.fetch(page)
            sizes.add(len(m.handover()))
        self.assertEqual(len(sizes), 1)

    def test_tampered_handover_is_refused_and_none_of_it_is_used(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        data = bytearray(m.handover())
        data[len(data) // 2] ^= 0x01
        m.write_handover(bytes(data))
        with mock.patch.object(monitor, "unpack_section", wraps=monitor.unpack_section) as unpack, \
             mock.patch.object(monitor, "post") as post:
            with self.assertRaises(monitor.PageError):
                m.check()
        unpack.assert_not_called()  # not a byte of openssl's partial output reached the matching
        post.assert_not_called()

    def test_only_the_expected_encryption_format_is_accepted(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        blob = monitor.pack_section("current notices 4 birch rd", monitor.current_run())
        cbc = subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes256", "-recip", KEYS["cert"],
                              "-outform", "DER"], input=blob, capture_output=True, check=True).stdout
        m.write_handover(cbc)  # decryptable with the right key, but not authenticated
        with mock.patch.object(monitor, "decrypt_handover") as decrypt:
            with self.assertRaises(monitor.PageError) as ctx:
                m.check()
        self.assertIn("not in the expected format", str(ctx.exception))
        decrypt.assert_not_called()

    def test_other_oaep_hashes_are_refused(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        blob = monitor.pack_section("current notices 4 birch rd", monitor.current_run())
        for md in ("sha384", "sha1"):
            other = subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes-256-gcm", "-recip", KEYS["cert"],
                                    "-keyopt", "rsa_padding_mode:oaep", "-keyopt", f"rsa_oaep_md:{md}",
                                    "-keyopt", "rsa_mgf1_md:sha256", "-outform", "DER"],
                                   input=blob, capture_output=True, check=True).stdout
            m.write_handover(other)
            with self.assertRaises(monitor.PageError, msg=md) as ctx:
                m.check()
            self.assertIn("not in the expected format", str(ctx.exception))

    def test_largest_handover_fits_in_one_environment_variable(self):
        largest = (monitor.MAX_HANDOVER_BYTES + 2) // 3 * 4  # base64 of the largest accepted hand-over
        self.assertLess(len("HANDOVER=") + largest, 128 * 1024 - 16 * 1024)  # with room to spare
        m = Monitor()
        m.fetch(PAGE_NONE.replace("12 Elm St", "a much longer line " * 3000))
        self.assertLessEqual(len(m.handover()), monitor.MAX_HANDOVER_BYTES)

    def test_untrusted_handover_input(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        too_long = "A" * ((monitor.MAX_HANDOVER_BYTES + 2) // 3 * 4 + 4)
        for bad in ["", "not base64!", too_long, base64.b64encode(b"\x30\x00").decode()]:
            m.extra_check_env = {"HANDOVER": bad}
            with mock.patch.object(monitor, "post") as post:
                with self.assertRaises(monitor.PageError, msg=bad[:20]):
                    m.check()
            post.assert_not_called()
        m.extra_check_env = {}

    def test_large_key_value_cant_stall_openssl(self):
        # Larger than a pipe's buffer: openssl must already be reading.
        started = time.monotonic()
        with self.assertRaises(monitor.ConfigError):
            monitor.check_key_matches(b"x" * 300_000, KEYS["cert"])
        self.assertLess(time.monotonic() - started, 30)

    def test_decryption_output_is_discarded_on_failure(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        failing = subprocess.CompletedProcess([], 4, stdout=b"x" * monitor.PAGE_BLOB_SIZE, stderr=b"")
        with mock.patch.object(monitor, "run_openssl", return_value=failing):
            with self.assertRaises(monitor.PageError):
                monitor.decrypt_handover(m.handover(), KEYS["key"].encode(), KEYS["cert"])

    def test_oversized_or_empty_handover_is_refused_before_openssl(self):
        for data in (b"", b"x" * (monitor.MAX_HANDOVER_BYTES + 1)):
            with mock.patch.object(monitor, "run_openssl") as openssl:
                with self.assertRaises(monitor.PageError):
                    monitor.decrypt_handover(data, KEYS["key"].encode(), KEYS["cert"])
            openssl.assert_not_called()

    def test_missing_wrong_or_broken_key(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        for key, error in ((None, "HANDOVER_KEY is not set"), (KEYS["other_key"], "doesn't match"),
                           ("not a key", "doesn't match")):
            m2 = Monitor(check_env={"HANDOVER_KEY": key} if key else None)
            if key is None:
                m2.check_env.pop("HANDOVER_KEY")
            m2.write_handover(m.handover())
            with self.assertRaises(monitor.ConfigError) as ctx:
                m2.check()
            self.assertIn(error, str(ctx.exception))

    def test_openssl_never_sees_the_key_or_other_secrets(self):
        m = Monitor(check_env={"PUSHOVER_TOKEN": "pushover-token-123", "PUSHOVER_USER": "pushover-user-456",
                               "NTFY_TOKEN": "tk_ntfy789"})
        m.fetch(PAGE_MATCH)
        real_popen = subprocess.Popen
        calls = []

        def recording_popen(args, **kwargs):
            calls.append((" ".join(args), kwargs.get("env")))
            return real_popen(args, **kwargs)

        with mock.patch.object(monitor.subprocess, "Popen", recording_popen):
            sent, _ = m.check()
        self.assertEqual(len(sent), 2)
        self.assertTrue(any("/dev/fd/" in command for command, _ in calls))  # the key goes through a pipe
        secrets_given = [line for line in KEYS["key"].splitlines()[1:-1]]
        secrets_given += [v for k, v in m.check_env.items() if k != "WATCH_URL"]
        for command, env in calls:
            self.assertEqual(set(env), {"PATH"})  # nothing else from the environment
            for value in secrets_given:
                self.assertNotIn(value, command)
                self.assertNotIn(value, env["PATH"])

    def test_damaged_or_padded_key_secret(self):
        m = Monitor()
        m.fetch(PAGE_MATCH)
        lines = KEYS["key"].splitlines()
        cases = {
            "\n".join(lines[:len(lines) // 2]): "doesn't match",  # cut off partway through
            "\n".join(lines[:-1]): "doesn't match",  # missing its END line
            "Generating a private key\nwriting new private key\n" + KEYS["key"]: None,  # extra text first
        }
        for key, error in cases.items():
            m2 = Monitor(check_env={"HANDOVER_KEY": key})
            m2.write_handover(m.handover())
            if error:
                with self.assertRaises(monitor.ConfigError) as ctx:
                    m2.check()
                self.assertIn(error, str(ctx.exception))
            else:
                sent, _ = m2.check()
                self.assertEqual(len(sent), 1)

    def test_rotation_mismatch_fails_safely_and_keeps_state(self):
        # Mid-rotation, the secret is new but the certificate is still old:
        # that run must fail without touching the state, so the run after the
        # rotation neither repeats nor misses an alert.
        m = Monitor()
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(len(sent), 1)
        before = m.state()
        m.fetch(PAGE_MATCH)
        m.check_env["HANDOVER_KEY"] = KEYS["other_key"]
        with mock.patch.object(monitor, "post") as post:
            with self.assertRaises(monitor.ConfigError):
                m.check()
        post.assert_not_called()
        self.assertEqual(before, m.state())
        m.check_env["HANDOVER_KEY"] = KEYS["key"]  # rotation finished
        sent, _ = m(PAGE_MATCH)
        self.assertEqual(sent, [])  # nothing changed on the page: no repeat
        sent, _ = m(PAGE_TWO)
        self.assertEqual(len(sent), 1)  # and a new match still alerts

    def test_weak_or_expired_certificate_is_refused(self):
        _, weak = make_key_pair("weak", bits=2048)
        with self.assertRaises(monitor.ConfigError):
            Monitor().fetch(PAGE_MATCH, cert=weak)
        with self.assertRaises(monitor.ConfigError):
            monitor.check_certificate(KEYS["cert"], now=datetime.now(timezone.utc) + timedelta(days=731))
        with self.assertRaises(monitor.ConfigError):
            Monitor().fetch(PAGE_MATCH, cert=os.path.join(KEYS["dir"], "missing.crt"))

    def test_certificate_expiry_warning(self):
        out = io.StringIO()
        with redirect_stdout(out):
            monitor.check_certificate(KEYS["cert"], now=datetime.now(timezone.utc) + timedelta(days=710))
        self.assertIn("::warning::", out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out):
            monitor.check_certificate(KEYS["cert"])
        self.assertEqual(out.getvalue(), "")


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

    def test_section_must_stop_changing(self):
        with self.assertRaises(monitor.PageError) as ctx:
            Monitor().fetch(PAGE_MATCH, changing=True)
        self.assertIn("kept changing", str(ctx.exception))

    def test_error_status_fails(self):
        for status in ("503", "404"):
            m = Monitor()
            with self.assertRaises(monitor.PageError, msg=status) as ctx:
                m.fetch(PAGE_MATCH, fake={"FAKE_STATUS": status})
            self.assertIn("did not load successfully", str(ctx.exception))
            self.assertFalse(os.path.exists(m.path("page.bin")))  # nothing handed over

    def test_unrelated_loading_doesnt_block_a_check(self):
        # Pages with embedded videos, surveys or analytics may never stop
        # loading, and their other requests can fail; neither may stop a
        # check (and so a real alert) when the section itself is fine.
        for fake in ({"FAKE_NEVER_IDLE": "1"}, {"FAKE_DATA_FAIL": "status"}, {"FAKE_DATA_FAIL": "failed"},
                     {"FAKE_DATA_FAIL": "elsewhere"}):
            m = Monitor()
            m.fetch(PAGE_MATCH, fake=fake)
            sent, _ = m.check()
            self.assertEqual(len(sent), 1, fake)

    def test_listing_or_empty_message_must_show(self):
        settings = {"SECTION_ITEM": "(Riverside)", "SECTION_EMPTY": "Nothing listed right now"}
        empty = PAGE_NONE.replace("12 Elm St (Riverside)", "Nothing listed right now")
        blank = PAGE_NONE.replace("12 Elm St (Riverside)", "")
        Monitor(page_env=settings).fetch(PAGE_NONE)  # a listing
        Monitor(page_env=settings).fetch(empty)  # the empty message
        with self.assertRaises(monitor.PageError) as ctx:
            Monitor(page_env=settings).fetch(blank)  # neither: the list may not have loaded
        self.assertIn("neither a listing nor the empty message", str(ctx.exception))
        Monitor().fetch(blank)  # without the settings, there's no such check
        # An empty message that repeats the heading's words isn't a second heading.
        repeats = PAGE_NONE.replace("12 Elm St (Riverside)", "There are no Current Notices")
        with self.assertRaises(monitor.PageError):
            Monitor().fetch(repeats)  # without SECTION_EMPTY it looks like a repeated heading
        Monitor(page_env={"SECTION_ITEM": "(Riverside)", "SECTION_EMPTY": "There are no Current Notices"}).fetch(repeats)
        for only in ({"SECTION_ITEM": "x"}, {"SECTION_EMPTY": "x"}):
            with mock.patch.dict(os.environ, dict(PAGE_ENV, **only), clear=True):
                with self.assertRaises(monitor.ConfigError):
                    monitor.load_fetch_config()

    def test_ambiguous_section_headings_fail(self):
        menu = "Menu: Current Notices | Past Notices\n" + PAGE_MATCH  # e.g. headings repeated in a menu
        for page, error in [(menu, "start text appears more than once"),
                            (PAGE_MATCH.replace("Past Notices", "Past Notices\nsee Past Notices"),
                             "end text appears more than once")]:
            with self.assertRaises(monitor.PageError) as ctx:
                Monitor().fetch(page)
            self.assertIn(error, str(ctx.exception))

    def test_redirect_away_from_site_fails(self):
        m = Monitor()
        for final in ["https://evil.invalid/notices", "http://www.example.invalid/notices",
                      "https://www.example.invalid:8443/notices", "chrome-error://chromewebdata/"]:
            with self.assertRaises(monitor.PageError, msg=final):
                m.fetch(PAGE_MATCH, final_url=final)
        m.fetch(PAGE_MATCH, final_url="https://example.invalid:443/moved")  # same site, www optional

    def test_offsite_navigation_is_blocked_before_it_loads(self):
        fake_playwright.cdp_sessions.clear()
        Monitor().fetch(PAGE_MATCH)
        cdp = fake_playwright.cdp_sessions[0]
        enable = [p for method, p in cdp.sent if method == "Fetch.enable"][0]
        self.assertEqual(enable["patterns"][0]["resourceType"], "Document")
        handler = cdp.handlers["Fetch.requestPaused"]
        for url, frame, expected in [("https://evil.invalid/", "main", "Fetch.failRequest"),
                                     ("https://www.example.invalid:8443/", "main", "Fetch.failRequest"),
                                     ("https://example.invalid/other", "main", "Fetch.continueRequest"),
                                     ("https://ads.invalid/frame", "child", "Fetch.continueRequest")]:
            cdp.sent.clear()
            handler({"requestId": "r1", "frameId": frame, "request": {"url": url}})
            self.assertEqual(cdp.sent[0][0], expected, url)
        with mock.patch.object(cdp, "send", side_effect=RuntimeError("request gone")):
            handler({"requestId": "r2", "frameId": "main", "request": {"url": "https://evil.invalid/"}})

    def test_fetch_needs_only_page_settings(self):
        with mock.patch.dict(os.environ, PAGE_ENV, clear=True):
            monitor.load_fetch_config()
        out = io.StringIO()
        with mock.patch.dict(os.environ, dict(PAGE_ENV, GITHUB_ACTIONS="true"), clear=True), redirect_stdout(out):
            monitor.load_fetch_config()
        self.assertEqual(out.getvalue().splitlines(), [
            "::add-mask::" + URL, "::add-mask::current notices", "::add-mask::past notices"])

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
            {"HANDOVER_KEY": ""},
            {"HANDOVER_KEY": "k" * (monitor.MAX_KEY_BYTES + 1)},
        ]
        for override in cases:
            env = {**CHECK_ENV, "HANDOVER_KEY": "k", **override}
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(monitor.ConfigError, msg=override):
                    monitor.load_check_config()

    def test_fetch_config_errors(self):
        for override in [{"WATCH_URL": "ftp://example.invalid"}, {"SECTION_START": ""}, {"WATCH_URL": ""}]:
            with mock.patch.dict(os.environ, dict(PAGE_ENV, **override), clear=True):
                with self.assertRaises(monitor.ConfigError, msg=override):
                    monitor.load_fetch_config()

    def test_add_mask_only_in_actions(self):
        env = dict(CHECK_ENV, HANDOVER_KEY="k")
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(out):
            monitor.load_check_config()
        self.assertEqual(out.getvalue(), "")
        out = io.StringIO()
        env = dict(env, GITHUB_ACTIONS="true", WATCH_URL="https://x.invalid/a%20b")
        with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(out):
            monitor.load_check_config()
        lines = out.getvalue().splitlines()
        self.assertTrue(all(line.startswith("::add-mask::") for line in lines))
        self.assertIn("::add-mask::Maple Grove", lines)
        self.assertIn("::add-mask::https://x.invalid/a%2520b", lines)


def workflow_text(name):
    with open(os.path.join(REPO, ".github", "workflows", name)) as f:
        return f.read()


def workflow_jobs(name="monitor.yml"):
    """Each job of a workflow as text, keyed by job name."""
    body = workflow_text(name).split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([a-z]+):\n", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def step_text(job, name):
    return job.split(f"- name: {name}\n", 1)[1].split("\n      - ", 1)[0]


def step_env(job, name):
    return set(re.findall(r"^          ([A-Z_]+):", step_text(job, name), re.M))


def step_script(job, name):
    """The shell script of a step's `run: |` block."""
    lines = step_text(job, name).split("run: |\n", 1)[1].splitlines()
    return "\n".join(line[10:] for line in lines if line.startswith("          ") or not line.strip()) + "\n"


class WorkflowTests(unittest.TestCase):
    def test_browser_job_gets_only_the_page_settings(self):
        jobs = workflow_jobs()
        self.assertEqual(set(jobs), {"fetch", "state", "check"})
        self.assertEqual(set(re.findall(r"secrets\.([A-Z_]+)", jobs["fetch"])),
                         {"WATCH_URL", "SECTION_START", "SECTION_END", "SECTION_ITEM", "SECTION_EMPTY"})
        self.assertEqual(re.findall(r"secrets\.", jobs["state"]), [])  # no secrets at all
        self.assertNotIn("actions/checkout", jobs["state"])  # and no code from the repo

    def test_check_job_never_unpacks_a_cache(self):
        self.assertIn("uses: ./.github/workflows/check.yml", workflow_jobs()["check"])
        check = workflow_text("check.yml")
        self.assertNotIn("cache/restore", check)
        self.assertNotIn("download-artifact", check)

    def test_hand_over_and_state_arrive_as_secrets(self):
        # Passed as secrets, GitHub shows them only as *** in the check job's
        # log; passed any other way, it would print them.
        caller = workflow_jobs()["check"]
        self.assertIn("HANDOVER: ${{ needs.fetch.outputs.handover }}", caller.split("    secrets:\n", 1)[1])
        self.assertIn("PREVIOUS_STATE: ${{ needs.state.outputs.state }}", caller.split("    secrets:\n", 1)[1])
        self.assertNotIn("inherit", caller)  # only the secrets listed, never all of them
        check = workflow_jobs("check.yml")["check"]
        self.assertIn("HANDOVER: ${{ secrets.HANDOVER }}", step_text(check, "Check page"))
        self.assertIn("PREVIOUS_STATE: ${{ secrets.PREVIOUS_STATE }}", step_text(check, "Check page"))
        self.assertNotIn("outputs.", workflow_text("check.yml"))

    def test_every_setting_the_code_reads_is_passed(self):
        with open(os.path.join(REPO, "monitor.py")) as f:
            source = f.read()

        def names(function):
            body = source.split(f"def {function}(", 1)[1].split("\ndef ", 1)[0]
            return set(re.findall(r'env\("([A-Z_]+)"', body))

        jobs = workflow_jobs()
        self.assertEqual(step_env(jobs["fetch"], "Load page"), names("load_fetch_config"))
        check_text = workflow_text("check.yml")
        check = workflow_jobs("check.yml")["check"]
        self.assertEqual(step_env(check, "Check page"), names("load_check_config") | {"HANDOVER", "PREVIOUS_STATE"})
        declared = set(re.findall(r"^      ([A-Z_]+):\n        required: false$", check_text, re.M))
        passed = set(re.findall(r"^      ([A-Z_]+): \$\{\{", jobs["check"], re.M))
        used = set(re.findall(r"secrets\.([A-Z_]+)", check_text))
        self.assertEqual(declared, passed)  # every secret check.yml declares is passed, and no others
        self.assertLessEqual(used, declared)
        self.assertLessEqual(names("load_check_config"), declared)

    def test_nothing_is_handed_over_with_debug_logging(self):
        # With debug logging on, GitHub prints job outputs as they're set.
        jobs = workflow_jobs()
        for job, step, input_file in (("fetch", "Hand over page", ".page-section.bin"),
                                      ("state", "Hand over state", ".monitor-state.json")):
            script = step_script(jobs[job], step)
            for debug, expect_code, expect_output in (("1", 1, False), ("", 0, True)):
                tmp = tempfile.mkdtemp()
                with open(os.path.join(tmp, input_file), "w") as f:
                    f.write("{}")
                out = os.path.join(tmp, "out")
                open(out, "w").close()
                r = subprocess.run(["bash", "-e", "-c", script], cwd=tmp, capture_output=True, text=True,
                                   env={"PATH": os.environ["PATH"], "GITHUB_OUTPUT": out, "RUNNER_DEBUG": debug})
                with open(out) as f:
                    written = f.read()
                self.assertEqual((r.returncode, bool(written)), (expect_code, expect_output), (job, debug))
                shutil.rmtree(tmp)


class OpenerTests(unittest.TestCase):
    def test_alerts_never_go_through_a_proxy(self):
        # Proxies are read from the environment when the opener is built.
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}):
            opener = monitor.make_opener()
        for h in opener.handlers:
            self.assertFalse(getattr(h, "proxies", None), type(h).__name__)
        self.assertTrue(any(isinstance(h, monitor.NoRedirects) for h in opener.handlers))


class _Server(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        _Server.seen.append((self.path, self.headers.get("Authorization")))
        self.rfile.read(int(self.headers.get("Content-Length") or 0))  # read the request before answering
        if self.path == "/huge":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * (monitor.MAX_RESPONSE_BYTES + 10))
            return
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
                    monitor.post(url, b"{}", {"Authorization": "Bearer secret"}, time.monotonic() + 10)
            ctx.exception.close()
            self.assertEqual(ctx.exception.code, 302)
            self.assertEqual(_Server.seen, [("/publish", "Bearer secret")])  # never followed
            with mock.patch.dict(os.environ, {"NO_PROXY": "*", "no_proxy": "*"}):
                with self.assertRaises(monitor.AlertError):  # replies are size-capped
                    monitor.post(url.replace("/publish", "/huge"), b"{}", {}, time.monotonic() + 10)
                with self.assertRaises(TimeoutError):  # nothing is sent once the time is up
                    monitor.post(url, b"{}", {}, time.monotonic() - 1)
            self.assertEqual(len(_Server.seen), 2)
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
        shutil.copy(KEYS["cert"], os.path.join(tmp, "handover.crt"))
        r = self.run_cli(["fetch"], dict(PAGE_ENV, FAKE_PAGE_TEXT=PAGE_MATCH, FAKE_GOTO_FAIL="1"), tmp)
        self.assertEqual((r.returncode, r.stdout, r.stderr.strip()), (1, "", "Check failed: RuntimeError"))
        r = self.run_cli(["check"], {}, tmp)
        self.assertEqual((r.returncode, r.stderr.strip()), (1, "ConfigError: KEYWORDS is not set"))
        r = self.run_cli([], {}, tmp)
        self.assertEqual((r.returncode, r.stderr.strip()), (1, "ConfigError: usage: monitor.py fetch|check"))

    def test_fetch_then_check_end_to_end(self):
        tmp = tempfile.mkdtemp()
        shutil.copy(KEYS["cert"], os.path.join(tmp, "handover.crt"))
        r = self.run_cli(["fetch"], dict(PAGE_ENV, FAKE_PAGE_TEXT=PAGE_NONE), tmp)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "Page loaded."))
        with open(os.path.join(tmp, monitor.PAGE_FILE), "rb") as f:
            handover = base64.b64encode(f.read()).decode()
        os.remove(os.path.join(tmp, monitor.PAGE_FILE))  # as on the check machine: only the output arrives
        env = dict(CHECK_ENV, HANDOVER_KEY=KEYS["key"], HANDOVER=handover, PREVIOUS_STATE="")
        out = io.StringIO()
        with mock.patch.dict(os.environ, dict(env, PATH=os.environ["PATH"]), clear=True), \
             mock.patch.object(monitor, "PAGE_FILE", os.path.join(tmp, monitor.PAGE_FILE)), \
             mock.patch.object(monitor, "STATE_FILE", os.path.join(tmp, monitor.STATE_FILE)), \
             mock.patch.object(monitor, "HANDOVER_CERT", os.path.join(tmp, "handover.crt")), \
             mock.patch.object(monitor, "CHECK_DURATION", 0), redirect_stdout(out):
            monitor.main(["monitor.py", "check"])  # no match, so nothing is sent
        self.assertEqual(out.getvalue().strip(), "Check complete.")
        self.assertTrue(os.path.exists(os.path.join(tmp, monitor.STATE_FILE)))


if __name__ == "__main__":
    unittest.main()
