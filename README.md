# Page watch

Checks a JavaScript-rendered web page and sends a push notification (ntfy
and/or Pushover) when any watched keyword appears in a chosen section of it.
An outside service starts a check about every 10 minutes; GitHub's own
schedule is only a slower backup, and neither is a real-time guarantee.

The repository holds no details of what is being watched. The page address,
section headings, keywords and notification credentials live only in
repository secrets. The run log prints the same lines whether or not anything
matched. In a public repository, anyone can still see that the account runs
this monitor, when each run happened, how long each step took and whether it
passed; see [Public repository](#public-repository).

Each check runs as three jobs on separate machines:

- **fetch** loads the page in Chrome, with Chrome's own sandbox on. It
  receives only `WATCH_URL`, `SECTION_START`, `SECTION_END` and the optional
  `SECTION_ITEM` and `SECTION_EMPTY`, never the keywords, keys or credentials. Navigation of the page itself to another
  site, including a server redirect, is refused before the request is sent,
  and the page must end up on the same `https://` site and port. Images,
  scripts, frames and data the page loads from other sites are not
  restricted. The page must load with a successful HTTP status, each section
  heading must appear exactly once, and the section is read only once two
  reads two seconds apart agree. Scripts get up to 15 seconds to finish, but a
  page that never stops loading (embedded videos, surveys, analytics) is
  still read, and failures of the page's other requests don't stop the
  check, since either could otherwise block a real alert. With `SECTION_ITEM` and `SECTION_EMPTY`
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
  The check job is a separate, reusable workflow (`check.yml`), so that the
  hand-over and the previous state can be passed to it as secrets, together
  with exactly the secrets it needs (never all of them). GitHub then shows
  them only as `***` in its log, as it does the real secrets; passed any
  other way, it would print them. With step debug logging on (a re-run with
  debug logging, or an `ACTIONS_STEP_DEBUG` setting), GitHub also prints
  every job output as it's set, so the fetch and state jobs then refuse to
  hand anything over and the run fails; only the failure reason, a fixed
  category that carries no data, is still passed on. Runner diagnostic
  logging on its own doesn't print outputs (tested), so it isn't blocked.

The check step prints the same line every time and is padded to 45 seconds,
and the heartbeat step makes one ping, with the same kind of request and
the same retry rules in every case, and is padded to about 15 seconds
whether or not a heartbeat is set or valid.
Deliveries run in parallel against a 35-second deadline, so the step normally
takes 45 seconds whether no alert was due, an alert was sent or a delivery
failed. A failed delivery or a state that couldn't be saved doesn't fail the
public run; it's reported privately through `HEARTBEAT_URL`. Alerts describe
the page as it is now: after a failed delivery, the next run alerts that
channel again if a keyword is still listed, but not if the listing is gone by
then; a channel that confirmed the alert isn't repeated. A service can accept
a message and still answer too late, which counts as a failure and repeats
the alert on that channel on the next run, and on every run it keeps
happening. A channel added to the settings later, or pointed at a new
topic, server or user key, is alerted on its first run if a keyword is
listed then. A page that doesn't load properly is retried once before the
check fails.
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

State is salted HMAC-SHA256 values of the page section and of the matches,
plus one per notification channel, of its destination, that verifies only if
that destination is up to date with them (it confirmed the alert, or there
was nothing to deliver); a channel that isn't, or isn't configured, gets
random bytes of the same size instead, so the state doesn't show a failed
delivery either. None of it
can be reversed or forged without `STATE_KEY`, and the time and the run
number it was saved at are inside every HMAC. A state that is missing,
unreadable, older than two hours, from
the future, or not saved by the previous run counts as a first run, which
errs toward alerting: after a failed run or a lost save, an older state could
otherwise hide an alert that has come back. After saving, the check job
confirms the new state is in the cache and reports it privately if not. This
is best-effort persistence in GitHub's cache, which keeps state for 7 days
after it was last used. Re-running a run is refused, because a re-run could
restore a state older than one its earlier attempt failed to save; start a
new run instead.

### Failure reasons

When a run fails, or an alert or a state save fails privately, the `/fail`
ping to `HEARTBEAT_URL` carries a short body, which healthchecks.io and
similar services keep in the check's log: the run number, then one line per
failure. Each line is a fixed category chosen by the code, never an error
message, which could name the page, so the body is safe to keep anywhere.
The public run shows none of it; its log still says only which step failed.

| Line | Meaning |
|---|---|
| `run:951` | GitHub's run number, to find the run |
| `fetch:attempt_1:net_error:ERR_CONNECTION_RESET;attempt_2:timeout` | The page couldn't be loaded; each attempt's reason. `net_error:ERR_…` is Chromium's name for a network error, `timeout` a page that didn't finish loading, `page_navigated` a page that reloaded or moved while being read, `browser_closed` a browser that went away, `browser_error` any other browser error, `error:Name` any other kind of error, and `page_error:…` or `config_error:…` the same fixed message the public log shows |
| `fetch:install_failed`, `fetch:load_failed`, `fetch:job_failed`, `fetch:debug_logging_on`, `fetch:cancelled` | The fetch job failed outside the script, or was cancelled |
| `state:restore_failed`, `state:debug_logging_on`, `state:cancelled` | The state job failed or was cancelled |
| `check:…` | The check step failed, with the same kinds of reason |
| `state_save_failed`, `state_not_saved` | The new state couldn't be saved, or wasn't found in the cache afterwards |
| `delivery_failed:ntfy`, `delivery_failed:pushover` | That channel didn't confirm the alert |
| `job_failed` | The check job failed outside its own steps, such as in the checkout |

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
   | `HEARTBEAT_URL` | `https://` ping URL of an uptime check (e.g. a dead-man's switch). Runs started through the API or by hand ping it on success; scheduled runs send `/log`, which doesn't count as success; any run pings it with `/fail` if a job failed, an alert couldn't be delivered or the state wasn't saved, and that ping's body says why (see [Failure reasons](#failure-reasons)). You're therefore alerted if the outside trigger stops, even while GitHub's own schedule keeps running. If the ping can't be delivered, the run fails. Without it, an undelivered alert or unsaved state fails the run instead. |

2. Commit the public certificate as `handover.crt` (see
   [Hand-over key](#hand-over-key)).

3. Open **Actions → Page watch → Run workflow** and check that the run
   succeeds. A failed run means a setting is missing, the page layout changed
   or the hand-over key doesn't match. GitHub's notices about failed
   scheduled runs go to the user it treats as the workflow's owner, which can
   change when the workflow is re-enabled or its schedule edited. Re-enable
   it yourself to take ownership, then check your notification settings and
   that a notice actually arrives.

4. Test an alert. A successful run shows that the settings were accepted
   and the page was read, not that notifications arrive: a failed delivery
   is kept out of the public result and reported only through
   `HEARTBEAT_URL`. Add a word that is in the watched section right now to
   `KEYWORDS`, start a run, and check that every configured channel gets a
   notification. Then put `KEYWORDS` back exactly as it was. If one of the
   original keywords is listed at that moment, putting it back causes one
   more alert, because the matched keywords change.

5. Set up the [outside trigger](#outside-trigger).

## Outside trigger

GitHub's own schedule runs late and often only about once an hour, so
something outside GitHub (a cron job, a scheduled task on another host, an
uptime service with a webhook) should start the workflow every 10 minutes
through GitHub's API:

```
POST https://api.github.com/repos/OWNER/REPO/actions/workflows/monitor.yml/dispatches
Authorization: Bearer TOKEN
{"ref": "main"}
```

Give that service a fine-grained personal access token (**Settings →
Developer settings → Personal access tokens → Fine-grained tokens**) with:

- **Repository access:** only this repository.
- **Permissions:** Actions: Read and write, and nothing else. Starting a
  workflow needs no other permission.
- **Expiration:** the shortest that suits you, at most a year. GitHub emails
  you before it expires; set your own reminder too, since an expired token
  stops the checks and only the heartbeat notices.

Don't use a classic token: its `repo` and `workflow` scopes reach every
repository the account can, not just this one. Whoever holds the
fine-grained token can start, cancel, re-run and disable this repository's
workflows, so it could stop the checks until you enable them again (the
heartbeat notices); it can also read its run logs (public anyway in a public
repository) and delete its Actions caches, which loses the state and causes
at most an extra alert. It can't read the secrets or change the code. If the
service is ever
compromised, revoke the token on the same settings page. The token exists
only in that service: never commit it, and never pass it to the workflow.

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
made-up keywords, a fake Playwright, throwaway key pairs generated with
`openssl` and a local TLS server standing in for the heartbeat service, so
no browser, network access or secrets are needed.
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
  doesn't switch off the schedule after 60 days without a commit. Run it
  once by hand (**Actions → Keepalive → Run workflow**) after setting the
  repository rules, to confirm that it can push under them: a ruleset that
  requires pull requests or signed commits would stop it, and GitHub only
  emails about the failure.

## Recommended repository settings

- **Advanced Security:** Dependabot alerts, malware alerts and security
  updates on; secret scanning and push protection on; CodeQL default setup
  (Extended queries, remote and local sources). Leave Dependabot version
  updates and private vulnerability reporting off.
- **Actions → General:** allow only actions created by GitHub, require actions
  to be pinned to a full-length commit SHA, and keep workflow permissions
  read-only without permission to create pull requests.
- **Rules:** a ruleset on all branches that restricts deletions and blocks
  force pushes, with an empty bypass list.
