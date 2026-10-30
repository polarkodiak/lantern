# Page watch

Checks a JavaScript-rendered web page every 10 minutes and sends a push
notification (ntfy and/or Pushover) when any watched keyword appears in a
chosen section of it.

The repository holds no details of what is being watched. The page address,
section headings, keywords and notification credentials live only in
repository secrets. The run log prints the same line whether or not anything
matched. State is kept in the Actions cache as salted HMACs, which can't be
reversed without `STATE_KEY`.

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
   | `NOTIFY_DETAILS` | `true` to include the matched keywords and an excerpt in the notification. Off by default, so the notification services never see what you watch |
   | `NTFY_SERVER` | Self-hosted ntfy server, default `https://ntfy.sh` |
   | `NTFY_TOKEN` | ntfy access token, for a protected topic |

2. Open **Actions → Page watch → Run workflow** and check that the run
   succeeds. A failed run means a setting is missing, the page layout changed,
   or a notification was not delivered. GitHub emails you about failed
   scheduled runs.

## Public repository

Every-10-minute checks need about 4,300 Actions minutes a month, which is free
only in a public repository. If the repository is public:

- Under **Settings → Actions → General**, set log retention to 1 day.
- On the same page, make fork pull request workflows need your approval for
  all outside contributors.
- The monthly `keepalive` job commits a dated file so GitHub doesn't switch
  off the schedule after 60 days without a commit.
