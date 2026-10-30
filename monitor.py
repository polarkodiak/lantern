"""Check a JavaScript-rendered page for watched keywords and send a push
notification when one appears.

Everything that would identify what is being watched (the page, the
keywords, the notification channels) comes from environment variables that
the workflow fills from repository secrets, and the script never prints any
of it, and the state it keeps between runs is salted HMACs that reveal nothing
without STATE_KEY.
"""

import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request

STATE_FILE = ".monitor-state.json"
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


def load_config():
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
        "url": env("WATCH_URL", required=True),
        "keywords": keywords,
        "state_key": state_key.encode(),
        "section_start": normalize(env("SECTION_START", required=True)),
        "section_end": normalize(env("SECTION_END")),
        "ntfy_server": env("NTFY_SERVER") or "https://ntfy.sh",
        "ntfy_topic": env("NTFY_TOPIC"),
        "ntfy_token": env("NTFY_TOKEN"),
        "pushover_token": env("PUSHOVER_TOKEN"),
        "pushover_user": env("PUSHOVER_USER"),
        "details": env("NOTIFY_DETAILS").lower() in ("1", "true", "yes"),
        "title": env("ALERT_TITLE") or DEFAULT_ALERT_TITLE,
    }
    for name, value in (("WATCH_URL", cfg["url"]), ("NTFY_SERVER", cfg["ntfy_server"])):
        if not value.startswith("https://"):
            raise ConfigError(f"{name} must start with https://")
    if bool(cfg["pushover_token"]) != bool(cfg["pushover_user"]):
        raise ConfigError("set both PUSHOVER_TOKEN and PUSHOVER_USER, or neither")
    if not (cfg["ntfy_topic"] or cfg["pushover_token"]):
        raise ConfigError("no notification channel: set NTFY_TOPIC and/or PUSHOVER_TOKEN + PUSHOVER_USER")

    for value in [*raw_keywords, *keywords, state_key, cfg["url"], cfg["ntfy_topic"],
                  cfg["ntfy_token"], cfg["pushover_token"], cfg["pushover_user"]]:
        mask(value)
    return cfg


def fetch_page_text(url, section_start):
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        # Google Chrome is preinstalled on GitHub's Ubuntu runners, so this
        # skips a ~150 MB browser download on every run.
        browser = p.chromium.launch(channel="chrome")
        try:
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=60_000)
            try:
                page.wait_for_function(
                    """marker => document.body &&
                        document.body.innerText.toLowerCase().replace(/\\s+/g, " ").includes(marker)""",
                    arg=section_start,
                    timeout=45_000,
                )
            except PlaywrightTimeout:
                # Don't treat a half-rendered page as "no matches": that would
                # overwrite the state and re-send an old alert on the next run.
                raise PageError("section start text never appeared") from None
            try:
                page.wait_for_load_state("networkidle", timeout=15_000)
            except PlaywrightTimeout:
                pass  # Some pages poll forever; use what has rendered.
            return page.inner_text("body")
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


def post(url, data, headers):
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
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


def main():
    cfg = load_config()
    text = fetch_page_text(cfg["url"], cfg["section_start"])
    section = extract_section(text, cfg["section_start"], cfg["section_end"])
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


if __name__ == "__main__":
    try:
        main()
    except (ConfigError, PageError, AlertError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        # Type only: library messages can include URLs or page text.
        print(f"Check failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
