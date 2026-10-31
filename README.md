# Page watch

Checks a JavaScript-rendered web page every 10 minutes and sends a push
notification (ntfy and/or Pushover) when any watched keyword appears in a
chosen section of it.

The repository holds no details of what is being watched. The page address,
section headings, keywords and notification credentials live only in
repository secrets. The run log prints the same line whether or not anything
matched. State is kept in the Actions cache as salted HMACs, which can't be
reversed without `STATE_KEY`.

Each check runs as two jobs on separate machines:

- **fetch** loads the page in Chrome. It receives only `WATCH_URL`,
  `SECTION_START` and `SECTION_END`, so a malicious page, a browser exploit or
  a tampered package can't reach the keywords or credentials. It hands the
  watched section over through the Actions cache, padded to a fixed size.
- **check** matches the keywords, keeps state, sends alerts and pings the
  heartbeat. It uses only the Python standard library and never runs a
  browser.

Both jobs run on every check, whether or not anything matched. A page that
doesn't load properly is retried once before the check fails. Notification
requests never follow redirects, and every address must be `https://`.

## Setup

1. Add these under **Settings → Secrets and variables → Actions → Secrets**:

   | Secret | Value |
   |---|---|
   | `WATCH_URL` | Full `https://` address of the page |
   | `SECTION_START` | Heading text where the part of the page to watch begins |
   | `KEYWORDS` | Comma-separated, case-insensitive substrings |
   | `STATE_KEY` | Output of `openssl rand -hex 32` |
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
   | `HEARTBEAT_URL` | `https://` ping URL of an uptime check (e.g. a dead-man's switch), pinged after every run (with `/fail` if a job failed) so you're alerted if the checks stop |

2. Open **Actions → Page watch → Run workflow** and check that the run
   succeeds. A failed run means a setting is missing, the page layout changed,
   or a notification was not delivered. GitHub emails you about failed
   scheduled runs.

## Tests

`python -m unittest discover -s tests` runs the offline tests. They use
made-up keywords and a fake Playwright, so no browser or secrets are needed.
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

Every-10-minute checks need about 4,300 Actions minutes a month, which is free
only in a public repository. If the repository is public:

- Under **Settings → Actions → General**, set log retention to 1 day.
- On the same page, make fork pull request workflows need your approval for
  all outside contributors.
- The monthly `keepalive` job commits a dated file so GitHub doesn't switch
  off the schedule after 60 days without a commit.

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
