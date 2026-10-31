"""Check a JavaScript-rendered page for watched keywords and send a push
notification when one appears.

Each check runs as two commands on two separate machines:

  monitor.py fetch  loads the page in Chrome and saves the watched section.
                    It is given only the page address and section headings,
                    so a malicious page, a browser exploit or a tampered
                    package can't reach the keywords or credentials.
  monitor.py check  matches the keywords, keeps state and sends alerts. It
                    uses only the Python standard library and never runs a
                    browser.

Everything that would identify what is being watched (the page, the
keywords, the notification channels) comes from environment variables that
the workflow fills from repository secrets. The script never prints any of
it, and the state it keeps between runs is salted HMACs that reveal nothing
without STATE_KEY.
"""

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.parse
import urllib.request
import zlib

STATE_FILE = ".monitor-state.json"
PAGE_FILE = ".page-section.bin"
PAGE_BLOB_SIZE = 64 * 1024
SECTION_TIMEOUT = 45
FETCH_ATTEMPTS = 2
RETRY_PAUSE = 5
HTTP_TIMEOUT = 30
DEFAULT_ALERT_TITLE = "Watched page alert"
EXCERPT_CONTEXT = 120
PUSHOVER_MESSAGE_LIMIT = 1024


class ConfigError(Exception):
    """A setting is missing or invalid. Messages name settings, never values."""


class PageError(Exception):
    """The page did not render the way the monitor expects."""


class AlertError(Exception):
    """A configured notification channel did not accept the alert."""


def env(name, required=False):
    value = os.environ.get(name, "").strip()
    if required and not value:
        raise ConfigError(f"{name} is not set")
    return value


def https_url(name, value):
    parts = urllib.parse.urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise ConfigError(f"{name} must be an https:// address")
    return value


def same_site(host_a, host_b):
    return host_a.lower().removeprefix("www.") == host_b.lower().removeprefix("www.")


def normalize(text):
    # casefold() is a stricter lower(), and split()/join collapses newlines,
    # tabs and non-breaking spaces, so "Maple\nGrove" still matches
    # "maple grove".
    return " ".join(text.casefold().split())


def mask(value):
    """Hide value in the GitHub Actions log, which is public on a public repo.

    Nothing here prints secrets on purpose; this covers error messages from
    libraries that might.
    """
    if value and os.environ.get("GITHUB_ACTIONS") == "true":
        escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::add-mask::{escaped}", flush=True)


# --- fetch: runs the browser, knows only the page settings -----------------

def load_fetch_config():
    cfg = {
        "url": https_url("WATCH_URL", env("WATCH_URL", required=True)),
        "section_start": normalize(env("SECTION_START", required=True)),
        "section_end": normalize(env("SECTION_END")),
    }
    mask(cfg["url"])
    return cfg


def wait_for_section(page, marker):
    # Polled from Python so the heading is matched by exactly the same rules
    # as the keywords. Don't treat a half-rendered page as "no matches": that
    # would overwrite the state and re-send an old alert on the next run.
    deadline = time.monotonic() + SECTION_TIMEOUT
    while marker not in normalize(page.inner_text("body")):
        if time.monotonic() >= deadline:
            raise PageError("section start text never appeared")
        page.wait_for_timeout(1000)


def check_final_url(expected, actual):
    final = urllib.parse.urlsplit(actual)
    if final.scheme != "https" or not same_site(final.hostname or "", urllib.parse.urlsplit(expected).hostname):
        raise PageError("page was redirected away from the watched site")


def load_page(page, url, section_start):
    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    page.goto(url, wait_until="domcontentloaded", timeout=60_000)
    wait_for_section(page, section_start)
    try:
        page.wait_for_load_state("networkidle", timeout=15_000)
    except PlaywrightTimeout:
        pass  # Some pages poll forever; use what has rendered.
    check_final_url(url, page.url)
    return page.inner_text("body")


def fetch_page_text(url, section_start):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        # Google Chrome is preinstalled on GitHub's Ubuntu runners, so this
        # skips a ~150 MB browser download on every run.
        browser = p.chromium.launch(channel="chrome")
        try:
            for attempt in range(1, FETCH_ATTEMPTS + 1):
                page = browser.new_page()
                try:
                    return load_page(page, url, section_start)
                except Exception:
                    # A slow or half-loaded page is usually a passing hiccup
                    # on the site, so try once more before failing the check.
                    if attempt == FETCH_ATTEMPTS:
                        raise
                    time.sleep(RETRY_PAUSE)
                finally:
                    page.close()
        finally:
            browser.close()


def extract_section(text, start, end):
    text = normalize(text)
    begin = text.find(start)
    if begin == -1:
        raise PageError("section start text not found")
    section = text[begin:]
    if end:
        stop = section.find(end, len(start))
        # A missing end marker keeps the rest of the page: an extra alert is
        # better than a missed one.
        if stop != -1:
            section = section[:stop]
    return section


def pack_section(section):
    data = zlib.compress(section.encode())
    if len(data) > PAGE_BLOB_SIZE - 4:
        raise PageError("watched section is too large")
    # Random padding to a fixed size, so the cached file's size never
    # reveals anything about the page.
    padding = secrets.token_bytes(PAGE_BLOB_SIZE - 4 - len(data))
    return len(data).to_bytes(4, "big") + data + padding


def unpack_section(blob):
    if len(blob) != PAGE_BLOB_SIZE:
        raise PageError("page data from the fetch job is invalid")
    size = int.from_bytes(blob[:4], "big")
    try:
        return zlib.decompress(blob[4:4 + size]).decode()
    except (zlib.error, UnicodeDecodeError):
        raise PageError("page data from the fetch job is invalid") from None


def run_fetch():
    cfg = load_fetch_config()
    text = fetch_page_text(cfg["url"], cfg["section_start"])
    section = extract_section(text, cfg["section_start"], cfg["section_end"])
    with open(PAGE_FILE, "wb") as f:
        f.write(pack_section(section))
    print("Page loaded.")


# --- check: matches, keeps state and alerts; standard library only ---------

def load_check_config():
    raw_keywords = [kw.strip() for kw in env("KEYWORDS", required=True).split(",")]
    keywords = []
    for kw in map(normalize, raw_keywords):
        if kw and kw not in keywords:
            keywords.append(kw)
    if not keywords:
        raise ConfigError("KEYWORDS has no usable entries")

    state_key = env("STATE_KEY", required=True)
    if len(state_key) < 32:
        raise ConfigError("STATE_KEY must be at least 32 characters")

    cfg = {
        "url": https_url("WATCH_URL", env("WATCH_URL", required=True)),
        "keywords": keywords,
        "state_key": state_key.encode(),
        "ntfy_server": https_url("NTFY_SERVER", env("NTFY_SERVER") or "https://ntfy.sh"),
        "ntfy_topic": env("NTFY_TOPIC"),
        "ntfy_token": env("NTFY_TOKEN"),
        "pushover_token": env("PUSHOVER_TOKEN"),
        "pushover_user": env("PUSHOVER_USER"),
        "details": env("NOTIFY_DETAILS").lower() in ("1", "true", "yes"),
        "title": env("ALERT_TITLE") or DEFAULT_ALERT_TITLE,
    }
    if bool(cfg["pushover_token"]) != bool(cfg["pushover_user"]):
        raise ConfigError("set both PUSHOVER_TOKEN and PUSHOVER_USER, or neither")
    if not (cfg["ntfy_topic"] or cfg["pushover_token"]):
        raise ConfigError("no notification channel: set NTFY_TOPIC and/or PUSHOVER_TOKEN + PUSHOVER_USER")

    for value in [*raw_keywords, *keywords, state_key, cfg["url"], cfg["ntfy_topic"],
                  cfg["ntfy_token"], cfg["pushover_token"], cfg["pushover_user"]]:
        mask(value)
    return cfg


def digest(key, salt, label, value):
    msg = b"\0".join([salt, label.encode(), value.encode()])
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def load_state(path):
    try:
        with open(path) as f:
            state = json.load(f)
        for field in ("salt", "page", "matches"):
            bytes.fromhex(state[field])
        return state
    except FileNotFoundError:
        return None
    except (ValueError, KeyError, TypeError):
        return None  # Unreadable state counts as a first run.


def unchanged(key, state, label, value):
    if state is None:
        return False
    expected = digest(key, bytes.fromhex(state["salt"]), label, value)
    return hmac.compare_digest(expected, state[label])


def save_state(path, key, page, matches_text):
    # A fresh random salt every run means two states never look alike, even
    # when nothing changed, and the file is always the same size.
    salt = secrets.token_bytes(16)
    state = {
        "salt": salt.hex(),
        "page": digest(key, salt, "page", page),
        "matches": digest(key, salt, "matches", matches_text),
    }
    with open(path, "w") as f:
        json.dump(state, f)


def build_message(cfg, section, matches):
    if not cfg["details"]:
        return "A watched keyword is on the page. Tap to open it."
    lines = [f"Matched: {', '.join(matches)}"]
    for kw in matches:
        i = section.find(kw)
        excerpt = section[max(0, i - EXCERPT_CONTEXT):i + len(kw) + EXCERPT_CONTEXT]
        lines.append(f"...{excerpt}...")
    return "\n\n".join(lines)[:PUSHOVER_MESSAGE_LIMIT]


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects, so a request carrying a token can never be passed on
    to another address. A refused redirect surfaces as an HTTP error."""

    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirects)


def post(url, data, headers):
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with OPENER.open(request, timeout=HTTP_TIMEOUT) as response:
        return response.read()


def send_ntfy(cfg, message):
    headers = {"Content-Type": "application/json"}
    if cfg["ntfy_token"]:
        headers["Authorization"] = f"Bearer {cfg['ntfy_token']}"
    body = {
        "topic": cfg["ntfy_topic"],
        "title": cfg["title"],
        "message": message,
        "priority": 4,
        "tags": ["warning", "droplet"],
        "click": cfg["url"],
    }
    post(cfg["ntfy_server"].rstrip("/") + "/", json.dumps(body).encode(), headers)


def send_pushover(cfg, message):
    data = urllib.parse.urlencode({
        "token": cfg["pushover_token"],
        "user": cfg["pushover_user"],
        "title": cfg["title"],
        "message": message,
        "url": cfg["url"],
        "url_title": "Open page",
        "priority": 1,
    }).encode()
    reply = json.loads(post("https://api.pushover.net/1/messages.json", data, {}))
    if reply.get("status") != 1:
        raise AlertError("pushover rejected the message")


def send_alerts(cfg, message):
    channels = []
    if cfg["ntfy_topic"]:
        channels.append(("ntfy", send_ntfy))
    if cfg["pushover_token"]:
        channels.append(("pushover", send_pushover))
    failed = []
    for name, send in channels:
        try:
            send(cfg, message)
        except Exception as exc:
            status = getattr(exc, "code", None)
            failed.append(f"{name} (HTTP {status})" if status else f"{name} ({type(exc).__name__})")
    if failed:
        # Leaving the state alone makes the next run retry, so a failed
        # delivery can't silently swallow an alert.
        raise AlertError("delivery failed: " + ", ".join(failed))


def run_check():
    cfg = load_check_config()
    with open(PAGE_FILE, "rb") as f:
        section = unpack_section(f.read())
    matches = [kw for kw in cfg["keywords"] if kw in section]
    matches_text = "\n".join(sorted(matches))

    key = cfg["state_key"]
    state = load_state(STATE_FILE)
    changed = not (unchanged(key, state, "page", section)
                   and unchanged(key, state, "matches", matches_text))
    if matches and changed:
        send_alerts(cfg, build_message(cfg, section, matches))

    save_state(STATE_FILE, key, section, matches_text)
    # Same output whether or not anything matched, so the public run log
    # can't be used to tell when anything matched.
    print("Check complete.")


COMMANDS = {"fetch": run_fetch, "check": run_check}


def main(argv):
    command = argv[1] if len(argv) == 2 else ""
    if command not in COMMANDS:
        raise ConfigError("usage: monitor.py fetch|check")
    COMMANDS[command]()


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (ConfigError, PageError, AlertError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        # Type only: library messages can include URLs or page text.
        print(f"Check failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
