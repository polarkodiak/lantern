# Page watch

Checks a JavaScript-rendered web page every 10 minutes and sends a push
notification (ntfy and/or Pushover) when any watched keyword appears in a
chosen section of it.

The repository holds no details of what is being watched. The page address,
section headings, keywords and notification credentials live only in
repository secrets. The run log prints the same lines whether or not anything
matched. In a public repository, anyone can still see that the account runs
this monitor, when each run happened, how long each step took and whether it
passed; see [Public repository](#public-repository).

Each check runs as three jobs on separate machines:

- **fetch** loads the page in Chrome, with Chrome's own sandbox on. It
  receives only `WATCH_URL`, `SECTION_START` and `SECTION_END`, never the
  keywords, keys or credentials. Navigation of the page itself to another
  site, including a server redirect, is refused before the request is sent,
  and the page must end up on the same `https://` site and port. Images,
  scripts, frames and data the page loads from other sites are not
  restricted. The page must load with a successful HTTP status and stop
  making network requests, none of its own data requests may fail, each
  section heading must appear exactly once, and the section is read only once
  two reads two seconds apart agree. With `SECTION_ITEM` and `SECTION_EMPTY`
  set, the section must also show a listing or the page's empty message.
  These are checks against a half-loaded or wrong page, not proof that the
  page is complete. The section is then padded to a fixed size, encrypted to the
  public certificate `handover.crt`, and handed to the check job as a job
  output: text that is never unpacked into files.
- **state** restores the previous run's state from the Actions cache.
  Restoring a cache unpacks an archive, which could write files anywhere on
  its machine, so this job holds no secrets and runs no code from the
  repository; it passes on only the state's text.
- **check** decrypts the hand-over with the private key `HANDOVER_KEY`,
  matches the keywords, keeps state, sends alerts and pings the heartbeat. It
  uses only the Python standard library and the runner's `openssl`, never
  runs a browser and never unpacks a cache. It treats both the hand-over and
  the previous state as untrusted input.

The check step prints the same line every time and is padded to 45 seconds,
and the heartbeat step makes one request of the same kind in every case and
is padded to 15 seconds.
Deliveries run in parallel against a 35-second deadline, so the step normally
takes 45 seconds whether no alert was due, an alert was sent or a delivery
failed. A failed delivery or a state that couldn't be saved doesn't fail the
public run; it's reported privately through `HEARTBEAT_URL`. Alerts describe
the page as it is now: after a failed delivery, the next run alerts again if
a keyword is still listed, but not if the listing is gone by then. A page
that doesn't load properly is retried once before the check fails.
Notification requests never follow redirects, their replies are size-capped
and must confirm the message, and every address must be `https://`.

### Page hand-over encryption

Only the public certificate is in the repository; the private key is only in
the `HANDOVER_KEY` secret, which the fetch job never receives. The hand-over
is CMS with AES-256-GCM, its content key wrapped by RSA-OAEP using SHA-256,
and the check job accepts no other format.

- The key is passed to `openssl` through a pipe while it runs, never in a
  command argument, a file or the log, and `openssl` gets none of the job's
  other environment variables, so it never sees the keywords or tokens.
- Decryption runs in memory. Anything `openssl` writes is discarded unless it
  reports success, so a tampered hand-over is refused and none of it is used.
- `openssl` runs with a time and memory limit, and the hand-over and the
  unpacked section are both size-capped.
- Decrypted content is still treated as untrusted page text: it is only ever
  searched for keywords and hashed.
- The run ID and attempt number are encrypted along with the page and
  checked, so a hand-over from another run is refused.
- The certificate must be RSA of at least 3,072 bits. The fetch job refuses
  an expired certificate, warns on the run within 30 days of expiry, and the
  check job fails if `HANDOVER_KEY` doesn't match `handover.crt`.

Encryption keeps the page text private in transit; it doesn't prove who made
a hand-over, since anyone can encrypt to a public certificate. A compromised
fetch job could therefore report a false page, which could hide an alert. It
can't run code with the check job's secrets.

### State

State is three salted HMAC-SHA256 values, which can't be reversed without
`STATE_KEY`, plus the time and the run number it was saved at, both inside
the HMACs. A state that is missing, unreadable, older than two hours, from
the future, or not saved by the previous run counts as a first run, which
errs toward alerting: after a failed run or a lost save, an older state could
otherwise hide an alert that has come back. After saving, the check job
confirms the new state is in the cache and reports it privately if not. This
is best-effort persistence in GitHub's cache, which keeps state for 7 days
after it was last used. Re-running a run is refused, because a re-run could
restore a state older than one its earlier attempt failed to save; start a
new run instead.

## Setup

1. Add these under **Settings → Secrets and variables → Actions → Secrets**:

   | Secret | Value |
   |---|---|
   | `WATCH_URL` | Full `https://` address of the page |
   | `SECTION_START` | Heading text where the part of the page to watch begins |
   | `KEYWORDS` | Comma-separated, case-insensitive substrings |
   | `STATE_KEY` | Output of `openssl rand -hex 32` |
   | `HANDOVER_KEY` | Private key matching `handover.crt` (see [Hand-over key](#hand-over-key)) |
   | `NTFY_TOPIC` | Output of `openssl rand -hex 24` (ntfy topics are readable by anyone who knows the name) |
   | `PUSHOVER_TOKEN`, `PUSHOVER_USER` | Pushover application token and user key |

   At least one of ntfy or Pushover is required. Optional:

   | Secret | Value |
   |---|---|
   | `SECTION_END` | Heading text of whatever follows the watched part, so later sections don't match |
   | `ALERT_TITLE` | Notification title, default `Watched page alert` |
   | `NOTIFY_DETAILS` | `true` to include the matched keywords and an excerpt in the notification. Off by default, so the notification services never see which keywords matched. They always see the alert title and the page link. |
   | `NTFY_SERVER` | Self-hosted ntfy server, default `https://ntfy.sh` |
   | `NTFY_TOKEN` | ntfy access token, for a protected topic |
   | `NTFY_TAGS` | Comma-separated ntfy tags, which show as icons on the notification, default `warning`. A secret because an icon can hint at what is watched. |
   | `SECTION_ITEM`, `SECTION_EMPTY` | Set both or neither: text that every listing in the section contains, and the text the page shows when there are none. A section showing neither is then refused as incomplete. |
   | `HEARTBEAT_URL` | `https://` ping URL of an uptime check (e.g. a dead-man's switch). Runs started through the API or by hand ping it on success; scheduled runs send `/log`, which doesn't count as success; any run pings it with `/fail` if a job failed, an alert couldn't be delivered or the state wasn't saved. You're therefore alerted if the outside trigger stops, even while GitHub's own schedule keeps running. If the ping can't be delivered, the run fails. Without it, an undelivered alert or unsaved state fails the run instead. |

2. Commit the public certificate as `handover.crt` (see
   [Hand-over key](#hand-over-key)).

3. Open **Actions → Page watch → Run workflow** and check that the run
   succeeds. A failed run means a setting is missing, the page layout changed
   or the hand-over key doesn't match. GitHub emails you about failed
   scheduled runs.

## Hand-over key

Generate the key pair on your own computer and send the private key straight
into the repository secret with the [GitHub CLI](https://cli.github.com), so
it's never written to a file, shown or copied to the clipboard:

```
cd "$(mktemp -d)"
openssl req -x509 -newkey rsa:4096 -sha256 -days 730 -nodes \
  -subj "/CN=handover" -keyout /dev/stdout -out handover.crt \
  | gh secret set HANDOVER_KEY --repo OWNER/REPO
```

`-nodes` leaves the key without a passphrase, which the workflow needs to use
it unattended; the key only ever exists in the pipe and the secret. Commit
`handover.crt` to the repository, delete the local copy, and if you signed in
to the GitHub CLI just for this, sign out and revoke its access. The private
key is never needed again.

To rotate: pause whatever starts the workflow from outside, disable the
workflow (**Actions → Page watch → ⋯ → Disable workflow**), and wait until no
run is in progress or queued. Then run the same command, commit the new
certificate, enable the workflow, run it once and resume the outside trigger.
No check runs while the secret and the certificate don't match, so none
fails, but nothing is checked during the pause either: keep it short.

The certificate is valid for 2 years, the longest NIST SP 800-57 recommends
for this kind of key. Rotate before it expires: the run shows a warning from
30 days before, and from the expiry date the fetch job fails until you do.
If the secret and the certificate don't match, the check job fails with a
message saying so.

## Tests

`python -m unittest discover -s tests` runs the offline tests. They use
made-up keywords, a fake Playwright and throwaway key pairs generated with
`openssl`, so no browser, network access or secrets are needed.
The **Tests** workflow runs them on every change to `main` and on pull
requests.

## Updating Playwright

`requirements.txt` pins every package to exact SHA-256 checksums. To update,
change the version in `requirements.in`, then regenerate with Python 3.13:

```
pip install pip-tools
pip-compile --generate-hashes --no-strip-extras --output-file=requirements.txt requirements.in
```

## Public repository

Checks every 10 minutes are about 4,300 runs a month, each with three jobs
that are billed separately and rounded up to whole minutes. That is free only
in a public repository; in a private one it's several times the minutes the
free plans include. A public repository shows anyone the account, the code,
and each run's time, duration and result, though not what is watched or
whether anything matched. If the repository is public:

- Under **Settings → Actions → General**, set log retention to 1 day.
- On the same page, make fork pull request workflows need your approval for
  all outside contributors.
- The `Keepalive` workflow commits a dated file once a month so GitHub
  doesn't switch off the schedule after 60 days without a commit.

## Recommended repository settings

- **Advanced Security:** Dependabot alerts, malware alerts and security
  updates on; secret scanning and push protection on; CodeQL default setup
  (Extended queries, remote and local sources). Leave Dependabot version
  updates and private vulnerability reporting off.
- **Actions → General:** allow only actions created by GitHub, require actions
  to be pinned to a full-length commit SHA, and keep workflow permissions
  read-only without permission to create pull requests.
- **Rules:** a ruleset on all branches that restricts deletions and blocks
  force pushes, with only the repository admin allowed to bypass.
