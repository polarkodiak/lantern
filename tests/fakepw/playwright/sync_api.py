"""Minimal stand-in for playwright.sync_api, so the tests run without a
browser. The page text comes from the file named by FAKE_PAGE."""

import os


class TimeoutError(Exception):
    pass


class _Page:
    url = ""

    def goto(self, url, **kwargs):
        if os.environ.get("FAKE_GOTO_FAIL"):
            raise RuntimeError(f"net::ERR_FAILED at {url}")
        self.url = os.environ.get("FAKE_FINAL_URL", url)

    def wait_for_timeout(self, ms):
        pass

    def wait_for_load_state(self, state, timeout=None):
        raise TimeoutError("never idle")

    def inner_text(self, selector):
        with open(os.environ["FAKE_PAGE"]) as f:
            return f.read()


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
    return _Playwright()
