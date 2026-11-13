"""Check a JavaScript-rendered page for watched keywords and send a push
notification when one appears.

Each check runs as two commands on two separate machines:

  monitor.py fetch  loads the page in Chrome (sandboxed, and refusing to
                    navigate to any other site) and saves the watched
                    section, encrypted to the public certificate
                    handover.crt. It is given only the page address and
                    section headings, so a malicious page, a browser exploit
                    or a tampered package can't reach the keywords or
                    credentials.
  monitor.py check  decrypts the section with the private key HANDOVER_KEY,
                    matches the keywords, keeps state and sends alerts. It
                    uses only the Python standard library and the runner's
                    openssl tool, and never runs a browser.

Everything that would identify what is being watched (the page, the
keywords, the notification channels) comes from environment variables that
the workflow fills from repository secrets. The script never prints any of
it, and the state it keeps between runs is salted HMACs that reveal nothing
without STATE_KEY. When a command fails, it leaves a fixed category of the
reason (never the error's text) in REASON_FILE, for the workflow's heartbeat
step to report privately.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import resource
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone

STATE_FILE = ".monitor-state.json"
MAX_STATE_BYTES = 4096
# A saved state older than this is ignored, as if it were missing: that errs
# toward alerting, and limits how far an old state could be played back.
MAX_STATE_AGE = 2 * 60 * 60
PAGE_FILE = ".page-section.bin"
DELIVERY_FAILED_FILE = ".delivery-failed"
REASON_FILE = ".failure-reason"
# Every notification channel, configured or not: the state records each
# one's delivery, so it always has the same fields.
CHANNELS = ("ntfy", "pushover")
HANDOVER_CERT = "handover.crt"
# The encrypted hand-over reaches the check job as a base64 environment
# variable, and Linux limits one variable to 128 KiB; a test keeps the
# largest possible hand-over well under that.
PAGE_BLOB_SIZE = 64 * 1024
MAX_SECTION_BYTES = 1024 * 1024
MAX_HANDOVER_BYTES = PAGE_BLOB_SIZE + 16 * 1024
MIN_RSA_BITS = 3072
MAX_KEY_BYTES = 16 * 1024
CERT_WARNING_DAYS = 30
OPENSSL_TIMEOUT = 60
OPENSSL_MEMORY = 512 * 1024 * 1024
SECTION_TIMEOUT = 45
STABLE_PAUSE_MS = 2000
STABLE_TIMEOUT = 30
# Pauses between attempts to load the page: a quick retry for a half-loaded
# page, then a longer one so a DNS or network blip of about a minute, the
# usual shape of a runner's resolver hiccup, doesn't fail the check.
RETRY_PAUSES = (5, 30)
FETCH_ATTEMPTS = len(RETRY_PAUSES) + 1
HTTP_TIMEOUT = 15
MAX_RESPONSE_BYTES = 64 * 1024
# All deliveries must finish within SEND_BUDGET seconds of the check starting,
# and the check step is padded to CHECK_DURATION, so it normally takes the
# same time whether or not an alert was sent, or failed.
SEND_BUDGET = 35
CHECK_DURATION = 45
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


def site_of(url):
    """(scheme, host without "www.", port) of a URL, or None if it has no
    usable host or port."""
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return None
    if not parts.hostname:
        return None
    default_port = {"https": 443, "http": 80}.get(parts.scheme)
    return parts.scheme, parts.hostname.lower().removeprefix("www."), port or default_port


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
        # Optional, page-specific: text every listing contains, and the text
        # the page shows when there are none. With both set, a section that
        # shows neither is refused as incomplete.
        "section_item": normalize(env("SECTION_ITEM")),
        "section_empty": normalize(env("SECTION_EMPTY")),
    }
    if bool(cfg["section_item"]) != bool(cfg["section_empty"]):
        raise ConfigError("set both SECTION_ITEM and SECTION_EMPTY, or neither")
    for value in (cfg["url"], cfg["section_start"], cfg["section_end"], cfg["section_item"], cfg["section_empty"]):
        mask(value)
    return cfg


def check_section_contents(section, start, item, empty):
    if item and item not in section[len(start):] and empty not in section[len(start):]:
        raise PageError("watched section shows neither a listing nor the empty message")


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
    if urllib.parse.urlsplit(actual).scheme != "https" or site_of(actual) != site_of(expected):
        raise PageError("page was redirected away from the watched site")


def block_offsite_navigation(page, url):
    """Refuse every main-frame navigation to another site before its request
    is sent, including server-side redirects, so another site's page never
    loads. Images, scripts and data the page itself loads are unaffected."""
    allowed = site_of(url)
    cdp = page.context.new_cdp_session(page)
    main_frame = cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]

    def on_paused(event):
        offsite = event.get("frameId") == main_frame and site_of(event["request"]["url"]) != allowed
        try:
            if offsite:
                cdp.send("Fetch.failRequest", {"requestId": event["requestId"], "errorReason": "BlockedByClient"})
            else:
                cdp.send("Fetch.continueRequest", {"requestId": event["requestId"]})
        except Exception:
            pass  # The request was already cancelled. A request left paused never loads.

    cdp.on("Fetch.requestPaused", on_paused)
    cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "resourceType": "Document", "requestStage": "Request"}]})


def wait_for_stable_section(page, start, end, empty=""):
    # A list that is still loading must not be read as a short one, which
    # could miss an alert, so re-read until two reads in a row agree.
    deadline = time.monotonic() + STABLE_TIMEOUT
    previous = extract_section(page.inner_text("body"), start, end, empty)
    while True:
        page.wait_for_timeout(STABLE_PAUSE_MS)
        current = extract_section(page.inner_text("body"), start, end, empty)
        if current == previous:
            return current
        if time.monotonic() >= deadline:
            raise PageError("watched section kept changing")
        previous = current


def load_page(page, url, start, end, item="", empty=""):
    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    block_offsite_navigation(page, url)
    response = page.goto(url, wait_until="domcontentloaded", timeout=60_000)
    if response is None or not response.ok:
        raise PageError("page did not load successfully")
    wait_for_section(page, start)
    try:
        # A chance for the page's scripts to finish. Some pages never stop
        # loading (embedded videos, surveys, analytics), so this doesn't
        # stop the check: the section must still pass the checks below. A
        # check that failed on unrelated loading could block a real alert.
        page.wait_for_load_state("networkidle", timeout=15_000)
    except PlaywrightTimeout:
        pass
    check_final_url(url, page.url)
    section = wait_for_stable_section(page, start, end, empty)
    check_section_contents(section, start, item, empty)
    return section


# Why each failed attempt to load the page failed, as fixed categories, for
# the failure report. Cleared when a fetch starts.
FETCH_ATTEMPT_FAILURES = []


def fetch_page_section(url, start, end, item="", empty=""):
    from playwright.sync_api import sync_playwright

    FETCH_ATTEMPT_FAILURES.clear()
    with sync_playwright() as p:
        # Google Chrome is preinstalled on GitHub's Ubuntu runners, so this
        # skips a ~150 MB browser download on every run. Playwright turns
        # Chrome's own sandbox off by default; it works on the runners, so
        # it stays on.
        browser = p.chromium.launch(channel="chrome", chromium_sandbox=True)
        try:
            for attempt in range(1, FETCH_ATTEMPTS + 1):
                page = browser.new_page()
                try:
                    return load_page(page, url, start, end, item, empty)
                except Exception as exc:
                    # A slow or half-loaded page, or a name that briefly won't
                    # resolve, is usually a passing hiccup, so try again
                    # before failing the check.
                    FETCH_ATTEMPT_FAILURES.append(failure_category(exc))
                    if attempt == FETCH_ATTEMPTS:
                        raise
                    time.sleep(RETRY_PAUSES[attempt - 1])
                finally:
                    page.close()
        finally:
            browser.close()


def extract_section(text, start, end, empty=""):
    text = normalize(text)
    # A heading that appears twice (say, also in a menu) or an end heading
    # that appears twice could make the wrong text count as the section and
    # hide a listing, so either one stops the check instead of guessing. The
    # empty message may repeat the heading's words, so it isn't counted.
    if (text.replace(empty, " ") if empty else text).count(start) > 1:
        raise PageError("section start text appears more than once")
    begin = text.find(start)
    if begin == -1:
        raise PageError("section start text not found")
    section = text[begin:]
    if end:
        if section.count(end, len(start)) > 1:
            raise PageError("section end text appears more than once")
        stop = section.find(end, len(start))
        # A missing end marker keeps the rest of the page: that can only add
        # text, so it can cause an extra alert but never hide one.
        if stop != -1:
            section = section[:stop]
    return section


def current_run_number():
    """GitHub's count of this workflow's runs: each run is one higher."""
    value = os.environ.get("GITHUB_RUN_NUMBER") or "0"
    if not re.fullmatch(r"[0-9]{1,18}", value):
        raise ConfigError("GITHUB_RUN_NUMBER is not a valid number")
    return int(value)


def current_run():
    """GitHub's ID and attempt number for this workflow run, shared by its
    fetch and check jobs, as one value."""
    run = b""
    for name, size in (("GITHUB_RUN_ID", 8), ("GITHUB_RUN_ATTEMPT", 4)):
        value = os.environ.get(name) or "0"
        if not re.fullmatch(r"[0-9]{1,19}", value) or int(value) >= 2 ** (8 * size - 1):
            raise ConfigError(f"{name} is not a valid number")
        run += int(value).to_bytes(size, "big")
    return run


def pack_section(section, run):
    raw = section.encode()
    data = zlib.compress(raw)
    # The run ID and attempt, encrypted along with the page, tie the
    # hand-over to this run, so an old hand-over put back in the cache can't
    # pass for the current page and hide a change.
    header = run + len(data).to_bytes(4, "big")
    if len(raw) > MAX_SECTION_BYTES or len(header) + len(data) > PAGE_BLOB_SIZE:
        raise PageError("watched section is too large")
    # Random padding to a fixed size, so the cached file's size never
    # reveals anything about the page.
    padding = secrets.token_bytes(PAGE_BLOB_SIZE - len(header) - len(data))
    return header + data + padding


def unpack_section(blob, run):
    if len(blob) != PAGE_BLOB_SIZE:
        raise PageError("page data from the fetch job is invalid")
    if not hmac.compare_digest(blob[:len(run)], run):
        raise PageError("page hand-over is from another run")
    blob = blob[len(run):]
    size = int.from_bytes(blob[:4], "big")
    try:
        # Unpack at most MAX_SECTION_BYTES, so a tampered hand-over can't make
        # the check job expand it into something huge.
        unpacker = zlib.decompressobj()
        raw = unpacker.decompress(blob[4:4 + size], MAX_SECTION_BYTES)
        if unpacker.unconsumed_tail or unpacker.unused_data or not unpacker.eof:
            raise ValueError
        return raw.decode()
    except (zlib.error, ValueError):
        raise PageError("page data from the fetch job is invalid") from None


def _limit_memory():
    resource.setrlimit(resource.RLIMIT_AS, (OPENSSL_MEMORY, OPENSSL_MEMORY))


def _write_key(fd, key):
    try:
        with os.fdopen(fd, "wb") as pipe:
            pipe.write(key)
    except OSError:
        pass  # openssl stopped reading, e.g. because it already failed


def run_openssl(args, data=b"", key=None):
    """Run the runner's openssl tool with bounded time and memory. A private
    key is passed through a pipe and referred to as "{key}" in args, so it
    never appears in an argument, a file or a log."""
    read_fd = write_fd = None
    if key is not None:
        read_fd, write_fd = os.pipe()
        args = [f"/dev/fd/{read_fd}" if arg == "{key}" else arg for arg in args]
    try:
        # Only PATH from the environment, so openssl never receives the
        # keywords, tokens or keys that the workflow passes to this job.
        proc = subprocess.Popen(["openssl", *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                                pass_fds=() if read_fd is None else (read_fd,), preexec_fn=_limit_memory)
    except BaseException:
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)
        raise
    writer = None
    if key is not None:
        os.close(read_fd)
        # Written while openssl runs, so a key larger than the pipe's buffer
        # can't block before the time limit starts.
        writer = threading.Thread(target=_write_key, args=(write_fd, key), daemon=True)
        writer.start()
    try:
        stdout, stderr = proc.communicate(data, timeout=OPENSSL_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    finally:
        if writer:
            writer.join(1)
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def check_certificate(path, now=None):
    if not os.path.isfile(path):
        raise ConfigError(f"{path} is missing")
    info = run_openssl(["x509", "-in", path, "-noout", "-text", "-enddate"])
    text = info.stdout.decode(errors="replace")
    bits = re.search(r"Public-Key: \((\d+) bit\)", text)
    if info.returncode or "rsaEncryption" not in text or not bits or int(bits.group(1)) < MIN_RSA_BITS:
        raise ConfigError(f"{path} must be a certificate for an RSA key of at least {MIN_RSA_BITS} bits")
    try:
        ends = re.search(r"^notAfter=(.+)$", text, re.M).group(1)
        expiry = datetime.strptime(" ".join(ends.split()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (AttributeError, ValueError):
        raise ConfigError(f"{path} has no readable expiry date") from None
    days_left = (expiry - (now or datetime.now(timezone.utc))).total_seconds() / 86400
    if days_left <= 0:
        raise ConfigError(f"{path} has expired: rotate the key pair")
    if days_left <= CERT_WARNING_DAYS:
        print(f"::warning::{path} expires in {int(days_left)} days: rotate the key pair")


def encrypt_handover(blob, cert):
    # AES-256-GCM for the content, RSA-OAEP with SHA-256 for its key, all set
    # explicitly rather than left to openssl's defaults.
    result = run_openssl(["cms", "-encrypt", "-binary", "-aes-256-gcm", "-recip", cert,
                          "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256",
                          "-keyopt", "rsa_mgf1_md:sha256", "-outform", "DER"], blob)
    if result.returncode or not result.stdout:
        raise PageError("page hand-over could not be encrypted")
    return result.stdout


def check_key_matches(key, cert):
    from_key = run_openssl(["pkey", "-in", "{key}", "-pubout"], key=key)
    from_cert = run_openssl(["x509", "-in", cert, "-noout", "-pubkey"])
    if from_key.returncode or from_cert.returncode or from_key.stdout.strip() != from_cert.stdout.strip():
        raise ConfigError(f"HANDOVER_KEY doesn't match {cert}: rotate both together")


def read_handover():
    """The encrypted hand-over: from the HANDOVER variable (base64), which the
    workflow fills from the fetch job's output, or from PAGE_FILE when run by
    hand."""
    encoded = os.environ.get("HANDOVER")
    if encoded is None:
        with open(PAGE_FILE, "rb") as f:
            return f.read(MAX_HANDOVER_BYTES + 1)
    if len(encoded) > (MAX_HANDOVER_BYTES + 2) // 3 * 4:
        raise PageError("page hand-over is invalid")
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise PageError("page hand-over is invalid") from None


def check_handover_format(data):
    """Accept only the format this monitor writes: authenticated encryption
    (AES-256-GCM) with the key wrapped by RSA-OAEP using SHA-256."""
    if not data or len(data) > MAX_HANDOVER_BYTES:
        raise PageError("page hand-over is invalid")
    info = run_openssl(["cms", "-cmsout", "-print", "-noout", "-inform", "DER"], data)
    text = info.stdout.decode(errors="replace")
    # Exactly these algorithms and nothing else: checking only that the
    # expected names appear would also accept, say, OAEP with SHA-384,
    # whose MGF1 part still names SHA-256.
    content_types = set(re.findall(r"^\s*contentType: (\S+)", text, re.M))
    algorithms = sorted(re.findall(r"^\s*algorithm: (\S+)", text, re.M))
    oaep_objects = sorted(re.findall(r"\bprim:\s+OBJECT\s+:(\S+)", text))
    if (info.returncode or content_types != {"id-smime-ct-authEnvelopedData", "pkcs7-data"}
            or algorithms != ["aes-256-gcm", "rsaesOaep"] or oaep_objects != ["mgf1", "sha256", "sha256"]):
        raise PageError("page hand-over is not in the expected format")


def decrypt_handover(data, key, cert):
    if not data or len(data) > MAX_HANDOVER_BYTES:
        raise PageError("page hand-over is invalid")
    result = run_openssl(["cms", "-decrypt", "-binary", "-inform", "DER", "-inkey", "{key}",
                          "-recip", cert], data, key)
    # openssl can write part of the plaintext before it detects tampering, so
    # nothing it wrote is used unless it reports success.
    if result.returncode != 0:
        raise PageError("page hand-over could not be decrypted")
    if len(result.stdout) != PAGE_BLOB_SIZE:
        raise PageError("page hand-over is invalid")
    return result.stdout


def run_fetch():
    cfg = load_fetch_config()
    run = current_run()
    check_certificate(HANDOVER_CERT)
    section = fetch_page_section(cfg["url"], cfg["section_start"], cfg["section_end"],
                                 cfg["section_item"], cfg["section_empty"])
    with open(PAGE_FILE, "wb") as f:
        f.write(encrypt_handover(pack_section(section, run), HANDOVER_CERT))
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
        # Icons on the notification. A secret, because an icon can hint at
        # what is watched.
        "ntfy_tags": [tag.strip() for tag in env("NTFY_TAGS").split(",") if tag.strip()] or ["warning"],
        "pushover_token": env("PUSHOVER_TOKEN"),
        "pushover_user": env("PUSHOVER_USER"),
        "details": env("NOTIFY_DETAILS").lower() in ("1", "true", "yes"),
        "title": env("ALERT_TITLE") or DEFAULT_ALERT_TITLE,
        "handover_key": env("HANDOVER_KEY", required=True).encode() + b"\n",
    }
    if len(cfg["handover_key"]) > MAX_KEY_BYTES:
        raise ConfigError("HANDOVER_KEY is too long to be a private key")
    if bool(cfg["pushover_token"]) != bool(cfg["pushover_user"]):
        raise ConfigError("set both PUSHOVER_TOKEN and PUSHOVER_USER, or neither")
    # Each configured channel and where it delivers to. A channel pointed
    # somewhere new is alerted again about a listing that's already there.
    cfg["channels"] = {}
    if cfg["ntfy_topic"]:
        cfg["channels"]["ntfy"] = cfg["ntfy_server"].rstrip("/") + "/" + cfg["ntfy_topic"]
    if cfg["pushover_token"]:
        cfg["channels"]["pushover"] = cfg["pushover_user"]
    if not cfg["channels"]:
        raise ConfigError("no notification channel: set NTFY_TOPIC and/or PUSHOVER_TOKEN + PUSHOVER_USER")

    for value in [*raw_keywords, *keywords, state_key, cfg["url"], cfg["ntfy_topic"],
                  cfg["ntfy_token"], cfg["pushover_token"], cfg["pushover_user"]]:
        mask(value)
    return cfg


def wall_clock():
    return time.time()


def digest(key, salt, label, saved_at, run_number, value):
    # The save time and run number are inside every HMAC, so neither can be
    # changed to make an old state look current.
    msg = b"\0".join([salt, label.encode(), str(saved_at).encode(), str(run_number).encode(), value.encode()])
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def parse_state(raw, now, run_number):
    """The saved state, or None if it's missing, unreadable, too old or too
    new, or not saved by the previous run. None counts as a first run, which
    errs toward alerting: if a run failed or its save was lost, an older
    state could otherwise hide an alert that has come back."""
    if not raw or len(raw) > MAX_STATE_BYTES:
        return None
    try:
        state = json.loads(raw)
    except (ValueError, RecursionError):  # RecursionError: absurdly nested input
        return None
    if not isinstance(state, dict) or set(state) != {"salt", "time", "run", "page", "matches", *CHANNELS}:
        return None
    if not (isinstance(state["salt"], str) and re.fullmatch(r"[0-9a-f]{32}", state["salt"])):
        return None
    if not all(isinstance(state[f], str) and re.fullmatch(r"[0-9a-f]{64}", state[f])
               for f in ("page", "matches", *CHANNELS)):
        return None
    if type(state["time"]) is not int or not -300 <= now - state["time"] <= MAX_STATE_AGE:
        return None
    # The previous run, or this one if it's being re-run.
    if type(state["run"]) is not int or not run_number - 1 <= state["run"] <= run_number:
        return None
    return state


def load_state(path, now, run_number):
    """The previous run's state: from the PREVIOUS_STATE variable (base64),
    which the workflow fills from the state job's output, or from path when
    run by hand. It's untrusted input either way."""
    encoded = os.environ.get("PREVIOUS_STATE")
    if encoded is None:
        try:
            with open(path, "rb") as f:
                raw = f.read(MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            return None
    else:
        if len(encoded) > (MAX_STATE_BYTES + 2) // 3 * 4:
            return None
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return None
    return parse_state(raw, now, run_number)


def unchanged(key, state, label, value):
    if state is None:
        return False
    expected = digest(key, bytes.fromhex(state["salt"]), label, state["time"], state["run"], value)
    return hmac.compare_digest(expected, state[label])


def save_state(path, key, page, matches_text, up_to_date, now, run_number):
    """up_to_date maps each channel that has this page and these matches to
    the destination that has them."""
    # A fresh random salt every run means two states never look alike, even
    # when nothing changed, and the file is always the same size.
    salt = secrets.token_bytes(16)
    saved_at = int(now)
    state = {
        "salt": salt.hex(),
        "time": saved_at,
        "run": run_number,
        "page": digest(key, salt, "page", saved_at, run_number, page),
        "matches": digest(key, salt, "matches", saved_at, run_number, matches_text),
    }
    for name in CHANNELS:
        # A channel whose destination has this page and these matches gets an
        # HMAC of that destination; any other (a failed delivery, or not
        # configured) gets random bytes of the same size, so the state
        # doesn't show which.
        state[name] = (digest(key, salt, name, saved_at, run_number, up_to_date[name]) if name in up_to_date
                       else secrets.token_hex(32))
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


def make_opener():
    # No proxies either, even if the environment names one: alerts and their
    # tokens go straight to the service.
    return urllib.request.build_opener(NoRedirects, urllib.request.ProxyHandler({}))


OPENER = make_opener()


def post(url, data, headers, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("no time left to send")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with OPENER.open(request, timeout=min(HTTP_TIMEOUT, remaining)) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise AlertError("reply too large")
    return body


def send_ntfy(cfg, message, deadline):
    headers = {"Content-Type": "application/json"}
    if cfg["ntfy_token"]:
        headers["Authorization"] = f"Bearer {cfg['ntfy_token']}"
    body = {
        "topic": cfg["ntfy_topic"],
        "title": cfg["title"],
        "message": message,
        "priority": 4,
        "tags": cfg["ntfy_tags"],
        "click": cfg["url"],
    }
    reply = post(cfg["ntfy_server"].rstrip("/") + "/", json.dumps(body).encode(), headers, deadline)
    # ntfy answers with the stored message; anything else (such as a web
    # page from a misconfigured server) is not a delivery.
    try:
        stored = json.loads(reply)
    except ValueError:
        raise AlertError("ntfy sent an unexpected reply") from None
    if (not isinstance(stored, dict) or stored.get("event") != "message"
            or stored.get("topic") != cfg["ntfy_topic"] or not stored.get("id")):
        raise AlertError("ntfy did not confirm the message")


def send_pushover(cfg, message, deadline):
    data = urllib.parse.urlencode({
        "token": cfg["pushover_token"],
        "user": cfg["pushover_user"],
        "title": cfg["title"],
        "message": message,
        "url": cfg["url"],
        "url_title": "Open page",
        "priority": 1,
    }).encode()
    try:
        reply = json.loads(post("https://api.pushover.net/1/messages.json", data, {}, deadline))
    except ValueError:
        raise AlertError("pushover sent an unexpected reply") from None
    if not isinstance(reply, dict) or reply.get("status") != 1:
        raise AlertError("pushover rejected the message")


def send_alerts(cfg, message, channels, deadline):
    """Send to each named channel at once, each in its own thread, and wait
    no later than deadline. Returns the channels that confirmed the message
    by then; any other counts as failed, so a slow service can't stretch the
    check step."""
    senders = {"ntfy": send_ntfy, "pushover": send_pushover}
    confirmed = set()

    def attempt(name):
        try:
            senders[name](cfg, message, deadline)
        except Exception:
            return
        confirmed.add(name)

    threads = [threading.Thread(target=attempt, args=(name,), daemon=True) for name in channels]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    return set(confirmed)


def run_check():
    started = time.monotonic()
    if os.path.exists(DELIVERY_FAILED_FILE):
        os.remove(DELIVERY_FAILED_FILE)  # only this run's failures count
    cfg = load_check_config()
    run = current_run()
    run_number = current_run_number()
    if int.from_bytes(run[8:], "big") > 1:
        # A re-run could restore a state older than one its earlier attempt
        # failed to save, so start a new run instead.
        raise ConfigError("re-running a run isn't supported: start a new run instead")
    check_key_matches(cfg["handover_key"], HANDOVER_CERT)
    encrypted = read_handover()
    check_handover_format(encrypted)
    section = unpack_section(decrypt_handover(encrypted, cfg["handover_key"], HANDOVER_CERT), run)
    matches = [kw for kw in cfg["keywords"] if kw in section]
    matches_text = "\n".join(sorted(matches))

    key = cfg["state_key"]
    now = wall_clock()
    state = load_state(STATE_FILE, now, run_number)
    # A channel whose destination confirmed an alert for this same page and
    # these same matches (or had nothing to deliver) is up to date and isn't
    # alerted again. Every other configured channel is due one: the page or
    # the matches changed, its last delivery failed, or it's new or points
    # somewhere new.
    same = unchanged(key, state, "page", section) and unchanged(key, state, "matches", matches_text)
    channels = cfg["channels"]
    up_to_date = {name: to for name, to in channels.items() if same and unchanged(key, state, name, to)}
    due = [name for name in channels if name not in up_to_date]
    if not matches:
        up_to_date = dict(channels)
    elif due:
        for name in send_alerts(cfg, build_message(cfg, section, matches), due, started + SEND_BUDGET):
            up_to_date[name] = channels[name]

    save_state(STATE_FILE, key, section, matches_text, up_to_date, now, run_number)
    failed = [name for name in due if name not in up_to_date] if matches else []
    if failed:
        # A failed delivery must not show in the public run: the state
        # records which channels still haven't confirmed, so the next run
        # alerts them again if a keyword is still listed, and a marker names
        # them for the heartbeat step to report privately.
        with open(DELIVERY_FAILED_FILE, "w") as f:
            f.write("".join(f"delivery_failed:{name}\n" for name in failed))
    # Same output and the same duration whether or not anything matched, or
    # an alert was sent or failed, so neither the public run log nor the
    # public step timings show any of it.
    time.sleep(max(0.0, CHECK_DURATION - (time.monotonic() - started)))
    print("Check complete.")


# --- failure reasons: fixed categories for the private heartbeat report ----

def slug(text):
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:80]


def failure_category(exc):
    """Why something failed, as a fixed label that carries no data: the kind
    of browser or network error, never its message, which can name the page.
    The workflow's heartbeat step reports it privately."""
    if isinstance(exc, (ConfigError, PageError, AlertError)):
        # Fixed messages that the public log prints anyway.
        return f"{type(exc).__name__.replace('Error', '').lower()}_error:{slug(str(exc))}"
    text = str(exc)
    name = type(exc).__name__
    net = re.search(r"net::(ERR_[A-Z0-9_]+)", text)  # Chromium's fixed error names
    if net:
        return f"net_error:{net.group(1)}"
    if name == "TimeoutError" or isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        return "timeout"
    lowered = text.lower()
    if "closed" in lowered or "crashed" in lowered:
        return "browser_closed"
    if "execution context was destroyed" in lowered or "detached" in lowered or "navigation" in lowered:
        return "page_navigated"
    if name == "Error":  # Playwright's own error class
        return "browser_error"
    return f"error:{name}"


def record_failure(exc):
    """Leave the reason for this command's failure in REASON_FILE: one line
    per failed attempt to load the page, then the final failure if it was
    something else."""
    lines = [f"attempt_{i}:{category}" for i, category in enumerate(FETCH_ATTEMPT_FAILURES, 1)]
    final = failure_category(exc)
    if not lines or lines[-1].split(":", 1)[1] != final:
        lines.append(final)
    try:
        with open(REASON_FILE, "w") as f:
            f.write("".join(line + "\n" for line in lines))
    except OSError:
        pass


COMMANDS = {"fetch": run_fetch, "check": run_check}


def main(argv):
    if os.path.exists(REASON_FILE):
        os.remove(REASON_FILE)  # only this command's failure counts
    command = argv[1] if len(argv) == 2 else ""
    if command not in COMMANDS:
        raise ConfigError("usage: monitor.py fetch|check")
    COMMANDS[command]()


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (ConfigError, PageError, AlertError) as exc:
        record_failure(exc)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        record_failure(exc)
        # Type only: library messages can include URLs or page text.
        print(f"Check failed: {type(exc).__name__}", file=sys.stderr)
        sys.exit(1)
