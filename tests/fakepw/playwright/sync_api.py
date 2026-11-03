"""Minimal stand-in for playwright.sync_api, so the tests run without a
browser. The page text comes from the file named by FAKE_PAGE.
FAKE_GOTO_FAIL makes every page load fail; FAKE_GOTO_FAILS=N fails only the
first N loads; FAKE_FINAL_URL sets where the page ends up; FAKE_STATUS sets
the HTTP status (default 200); FAKE_NEVER_IDLE makes the page keep loading;
FAKE_CHANGING makes the watched section different on every read;
FAKE_DATA_FAIL makes a background data request fail: "status" (an HTTP
error from the same site), "failed" (no answer from the same site) or
"elsewhere" (an HTTP error from another site)."""

import os

_loads = {"count": 0, "reads": 0}
cdp_sessions = []


class TimeoutError(Exception):
    pass


class _CDPSession:
    def __init__(self):
        self.sent = []
        self.handlers = {}

    def send(self, method, params=None):
        self.sent.append((method, params))
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "main"}}}
        return {}

    def on(self, event, handler):
        self.handlers[event] = handler


class _Request:
    def __init__(self, url, resource_type):
        self.url = url
        self.resource_type = resource_type


class _Response:
    def __init__(self, status, request=None):
        self.status = status
        self.ok = 200 <= status <= 299
        self.request = request


class _Context:
    def new_cdp_session(self, page):
        session = _CDPSession()
        cdp_sessions.append(session)
        return session


class _Page:
    url = ""
    context = _Context()

    def __init__(self):
        self.handlers = {}

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)

    def _emit(self, event, arg):
        for handler in self.handlers.get(event, []):
            handler(arg)

    def goto(self, url, **kwargs):
        _loads["count"] += 1
        if os.environ.get("FAKE_GOTO_FAIL") or _loads["count"] <= int(os.environ.get("FAKE_GOTO_FAILS", "0")):
            raise RuntimeError(f"net::ERR_FAILED at {url}")
        self.url = os.environ.get("FAKE_FINAL_URL", url)
        failure = os.environ.get("FAKE_DATA_FAIL")
        same_site = url.rstrip("/") + "/api/list"
        if failure == "status":
            self._emit("response", _Response(500, _Request(same_site, "fetch")))
        elif failure == "failed":
            self._emit("requestfailed", _Request(same_site, "xhr"))
        elif failure == "elsewhere":
            self._emit("response", _Response(500, _Request("https://analytics.invalid/x", "xhr")))
        self._emit("response", _Response(200, _Request(same_site.replace("list", "ok"), "fetch")))
        return _Response(int(os.environ.get("FAKE_STATUS", "200")))

    def wait_for_timeout(self, ms):
        pass

    def wait_for_load_state(self, state, timeout=None):
        if os.environ.get("FAKE_NEVER_IDLE"):
            raise TimeoutError("never idle")

    def inner_text(self, selector):
        with open(os.environ["FAKE_PAGE"]) as f:
            text = f.read()
        if os.environ.get("FAKE_CHANGING"):
            _loads["reads"] += 1
            text = text.replace("Notices\n", f"Notices\nupdate {_loads['reads']}\n", 1)
        return text

    def close(self):
        pass


class _Browser:
    def new_page(self):
        return _Page()

    def close(self):
        pass


class _Chromium:
    def launch(self, **kwargs):
        assert kwargs.get("channel") == "chrome"
        assert kwargs.get("chromium_sandbox") is True, "Chrome's sandbox must be on"
        return _Browser()


class _Playwright:
    chromium = _Chromium()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def sync_playwright():
    _loads["count"] = 0
    _loads["reads"] = 0
    return _Playwright()
