"""Minimal stand-in for playwright.sync_api, so the tests run without a
browser. The page text comes from the file named by FAKE_PAGE.
FAKE_GOTO_FAIL makes every page load fail; FAKE_GOTO_FAILS=N fails only the
first N loads."""

import os

_loads = {"count": 0}


class TimeoutError(Exception):
    pass


class _Page:
    url = ""

    def goto(self, url, **kwargs):
        _loads["count"] += 1
        if os.environ.get("FAKE_GOTO_FAIL") or _loads["count"] <= int(os.environ.get("FAKE_GOTO_FAILS", "0")):
            raise RuntimeError(f"net::ERR_FAILED at {url}")
        self.url = os.environ.get("FAKE_FINAL_URL", url)

    def wait_for_timeout(self, ms):
        pass

    def wait_for_load_state(self, state, timeout=None):
        raise TimeoutError("never idle")

    def inner_text(self, selector):
        with open(os.environ["FAKE_PAGE"]) as f:
            return f.read()

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
        return _Browser()


class _Playwright:
    chromium = _Chromium()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def sync_playwright():
    _loads["count"] = 0
    return _Playwright()
