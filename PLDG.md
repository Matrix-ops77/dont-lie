# Don't-Lie · No-Phone-Home Pledge

**Effective version: 0.3.3 · 2026-07-29**

Don't-Lie is a local-first receipt vault. The whole point of the tool is
that **you** can prove what an LLM said without trusting Don't-Lie, the
LLM vendor, or any third party. A tool that phoned home would betray
that promise on day one.

This document is the binding pledge. It is enforced by
`test_phone_home.py` (run as part of `python3 -m unittest discover`).

## The pledge

The Don't-Lie **core commands** listed below make **zero outbound
network calls** of any kind — no analytics, no telemetry, no update
checks, no "phone home to verify the license," no third-party fonts,
no CDN fetches, nothing. You can verify this on an air-gapped forensic
workstation with the network cable unplugged.

The core commands are:

| Command | What it does | Network? |
|---|---|---|
| `dontlie doctor`        | environment diagnostics | **offline** |
| `dontlie version`       | print version           | **offline** |
| `dontlie list`          | list recent receipts    | **offline** |
| `dontlie show <id>`     | show one receipt        | **offline** |
| `dontlie search <q>`    | search receipts         | **offline** |
| `dontlie verify`        | verify the chain        | **offline** |
| `dontlie verify --bundle path.jsonl` | verify a portable bundle | **offline** |
| `dontlie trust-score`   | compute trust score     | **offline** |
| `dontlie export`        | export to local file    | **offline** |
| `dontlie backup`        | snapshot the vault      | **offline** |
| `dontlie demo`          | run the offline proof   | **offline** |
| `dontlie web`           | launch local HTTP UI    | binds local port only, **no outbound** |
| `dontlie ui`            | launch the TUI          | **offline** |

## The opt-in commands (which DO make network calls)

These commands require an explicit user action and cannot fire by
accident. Each one prints a clear notice before it touches the
network.

| Command | What it does | Network target | Opt-in |
|---|---|---|---|
| `dontlie proxy --upstream https://api.openai.com` | MITM proxy for an LLM SDK | the upstream LLM API | explicit `--upstream` flag required |
| `dontlie witness-attest <id>` | co-sign a receipt with a third-party witness | the configured witness URL | explicit command + key fingerprint printed first |
| `dontlie witness-coverage` | co-sign every receipt in the namespace | the configured witness URL | explicit command |
| `dontlie anchor --remote` | anchor to an external TSA | the configured TSA URL | `--remote` flag required |
| `dontlie import --from-url <url>` | import a remote export | the URL | `--from-url` flag required |
| `dontlie web --public` | bind web UI on 0.0.0.0 | local network | `--public` flag required |

Every opt-in command also respects the `DONTLIE_OFFLINE=1` environment
variable. If that is set, the opt-in command will refuse to make the
network call and exit with a clear error.

## The web UI (`site/index.html` and `site/demo.html`)

The public site is two static HTML files in the `site/` folder. The
operator hosts them where they choose — S3, GitHub Pages, Cloudflare
Pages, or `python -m http.server` on their own laptop. There is no
"Don't-Lie-operated" hosting of these files; the operator picks
the host.

The shipped pages contain:

- No analytics scripts (no GA, no Plausible, no Fathom)
- No third-party fonts (uses the system font stack)
- No CDN fetches (every byte is in the file)
- No "call home" to check for updates
- No cookies, no localStorage of any user data
- No service worker (so it cannot run in the background)

You can confirm this by:

1. Opening the file in a browser (`file://` works for both files)
2. Opening the Network panel in DevTools
3. Watching the page load

The only network requests you'll see are for the static assets
themselves, served by the host the operator chose. There are no
requests to any other origin.

## How to verify the pledge yourself

```bash
# 1. Run the test suite — includes test_phone_home.py
cd /path/to/dontlie
python3 -m unittest discover -p "test_phone_home.py" -v

# 2. Try it on an air-gapped machine
sudo ifconfig en0 down     # or unplug the ethernet cable
dontlie list
dontlie verify
dontlie trust-score
sudo ifconfig en0 up

# 3. Audit site/index.html and site/demo.html
# Open the file in a browser (file:// or via any static host)
# Open DevTools -> Network
# Verify there are zero third-party requests
```

## What happens if the pledge is broken

If a future version of Don't-Lie adds a network call to a core
command without an opt-in flag, the test suite will fail. CI will go
red. The CHANGELOG entry will be the diff. This is auditable.

If a future version adds a network call to a core command WITH an
opt-in flag but the default is "on," that is also a violation. The
default for core commands is `network=off`, and that defaults to
"off" must be preserved.

## How to report a violation

If you find a network call that shouldn't be there, file an issue at
the project repository with:

1. The exact command you ran
2. The network call you observed (URL, method, headers, body)
3. The Don't-Lie version (`dontlie version`)

The maintainers will treat this as a security issue and respond
within 48 hours.

---

*This pledge is part of the Don't-Lie project. The text is MIT
licensed. You are free to copy it, fork it, and use it as a
template for your own local-first projects.*
