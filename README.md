<div align="center">

# keyspill

**Find the secrets your AI coding agents have already seen.**

[![npm version](https://img.shields.io/npm/v/keyspill?color=FFCF33&labelColor=121417)](https://www.npmjs.com/package/keyspill)
[![tests](https://github.com/kazbekaskarov/keyspill/actions/workflows/test.yml/badge.svg)](https://github.com/kazbekaskarov/keyspill/actions/workflows/test.yml)
[![dependencies](https://img.shields.io/badge/dependencies-0-FFCF33?labelColor=121417)](package.json)
[![license](https://img.shields.io/npm/l/keyspill?color=FFCF33&labelColor=121417)](LICENSE)

[Website](https://kazbekaskarov.github.io/keyspill/) · [npm](https://www.npmjs.com/package/keyspill) · [Changelog](CHANGELOG.md) · [Report a false positive](https://github.com/kazbekaskarov/keyspill/issues/new?template=false-positive.yml)

<img src="docs/terminal.png" alt="keyspill output in a terminal" width="760">

</div>

Coding agents read files to do their job, and your `.env` is a file. Every time Claude Code reads it, Codex runs `cat ~/.aws/credentials`, or you paste a key into Cursor to "just debug this one thing", that secret is sent to a model provider and stays in plain text in a session log on your disk.

keyspill reads those logs locally and tells you which keys to rotate, where they came from, and how they got there.

```bash
npx keyspill
```

No install, no config, no account. Requires Node.js 18 or later.

## Contents

- [Features](#features)
- [Usage](#usage)
- [Supported agents](#supported-agents)
- [What it detects](#what-it-detects)
- [Prevent future leaks](#prevent-future-leaks)
- [Privacy and security](#privacy-and-security)
- [Scripting and CI](#scripting-and-ci)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Seven agents in one command.** Claude Code, Codex, Cursor, GitHub Copilot CLI, Gemini CLI, opencode, and Cline / Roo Code / Kilo Code, on macOS, Linux and Windows.
- **Tells you how each secret leaked.** The agent read it from a file, you pasted it into chat, or the agent wrote it into a command.
- **Actionable output.** Severity, agent, project, last-seen date, and a direct link to rotate each key.
- **Low noise by design.** Documentation example keys, placeholders, public keys and code references are filtered out.
- **Private.** Runs entirely offline, never shows a full secret, never modifies your files.
- **Small and auditable.** Zero dependencies and about 850 lines of plain JavaScript.

## Usage

```bash
npx keyspill                  # scan and print a report
npx keyspill --card           # also write an HTML report with a shareable card, and open it
npx keyspill protect          # preview rules that stop agents reading secrets
npx keyspill protect --apply  # write those rules
```

### Example output

```
  keyspill · what your AI agents have already seen
  Scanned 1,284 session files (412 MB) from Claude Code, Codex, Cursor in 3.1s · 100% local, nothing uploaded

   9 secrets seen by your agents   3 critical · 5 high · 1 medium

  CRITICAL
  ● Stripe live secret key         sk_live_••••••••fnwh
      1× · Claude Code · ~/work/shop · last 2026-11-02
      agent read it 1×
      → rotate: https://dashboard.stripe.com/apikeys
  ● Database URL with password     postgres://app:••••••Ri@db.prod.acme-internal.net:5432
      1× · Claude Code · ~/work/shop · last 2026-11-02
      agent read it 1×

  HIGH
  ● GitHub token                   ghp_••••••••VKby
      1× · Codex · ~/oss/nanotab · last 2026-11-05
      agent read it 1×
      → rotate: https://github.com/settings/tokens
  ● OpenAI API key                 sk-proj-••••••••u9Bn
      1× · Claude Code · ~/work/shop · last 2026-11-02
      you pasted it 1×
      → rotate: https://platform.openai.com/api-keys
```

### Options

| Option | Description |
|---|---|
| `--card` | Write `keyspill-report.html` with the full masked report and a share card, then open it |
| `--html <file>` | Write the HTML report to a specific path |
| `--json` | Print machine-readable JSON (masked values only) |
| `--path <dir>` | Also scan another file or folder. Repeatable |
| `--all` | List every finding instead of the top ones per severity |
| `--no-open` | Don't open the HTML report automatically |
| `--no-color` | Plain output. `NO_COLOR` is also respected |
| `-v`, `--version` | Print the version |
| `-h`, `--help` | Print help |

### Share card

`npx keyspill --card` produces a local HTML report. Click **Download share card** to get a PNG that shows the number of findings and key types only, never values.

<img src="docs/card.png" alt="keyspill share card: 11 secrets my AI agents have already seen" width="560">

## Supported agents

| Agent | Where keyspill looks |
|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` (respects `CLAUDE_CONFIG_DIR`) |
| Codex | `~/.codex/sessions/**`, `~/.codex/history.jsonl` (respects `CODEX_HOME`) |
| Cursor | `state.vscdb` in Cursor's global and workspace storage, `~/.cursor/chats` |
| GitHub Copilot CLI | `~/.copilot/session-state`, `~/.copilot/history-session-state` |
| Gemini CLI | `~/.gemini/tmp/**` |
| opencode | `~/.local/share/opencode/storage` (respects `XDG_DATA_HOME`) |
| Cline / Roo Code / Kilo Code | `globalStorage/<extension>/tasks/*` in VS Code, VS Code Insiders, Cursor, Windsurf and VSCodium |

Editor storage resolves to `~/Library/Application Support` on macOS, `%APPDATA%` on Windows and `~/.config` on Linux.

Missing your agent? [Open an issue](https://github.com/kazbekaskarov/keyspill/issues/new?template=new-agent.yml) with where it keeps its history.

## What it detects

30 rules, grouped by severity.

| Severity | Secrets |
|---|---|
| **Critical** | AWS access keys, AWS secret keys, private keys (PEM), Stripe live keys, database URLs with passwords (Postgres, MySQL, MongoDB, Redis, AMQP, MSSQL), Supabase `service_role` keys |
| **High** | OpenAI, Anthropic, GitHub, GitLab, Google API, Slack tokens and webhooks, Telegram, Discord, SendGrid, Twilio, npm, PyPI, Hugging Face, Shopify, DigitalOcean, Stripe webhook secrets, Groq, Replicate, Supabase access tokens, Mailgun, AWS temporary keys |
| **Medium** | Unexpired JWTs, Stripe test keys, local database passwords, `*_SECRET` / `*_PASSWORD` / `*_TOKEN` / `*_API_KEY` values in env and config files |

### What it ignores on purpose

A false alarm in a security tool costs more trust than a miss, so keyspill skips:

- documentation example keys such as `AKIAIOSFODNN7EXAMPLE`
- placeholders: `your_api_key`, `xxxx`, `<token>`, `${SECRET}`, `USER:PASSWORD@HOST`
- Supabase `anon` keys, which are public by design
- expired JWTs
- default local credentials such as `postgres:postgres@localhost`
- code references such as `API_KEY = process.env.API_KEY`
- `NEXT_PUBLIC_*`, `VITE_*` and other public-by-convention variables

The same credential seen many times is reported once, with a count.

## Prevent future leaks

```bash
npx keyspill protect          # show what would change
npx keyspill protect --apply  # write it
```

This adds `permissions.deny` rules to `~/.claude/settings.json` so Claude Code can't read `.env*`, `*.pem`, `*.key`, `secrets/`, `~/.aws`, `~/.ssh` or `~/.config/gcloud`, and adds a `.cursorignore` to the current project. Your existing settings are merged, not replaced, and backed up first. Running it twice changes nothing.

> [!NOTE]
> Deny rules cover file reads, not shell commands like `cat .env`. Keep reading the commands you approve.

## Privacy and security

- **Offline.** keyspill makes no network requests. The HTML report loads no fonts, scripts or analytics.
- **Never shows a full secret.** Terminal, JSON and HTML output show a masked value (`sk_live_••••••••fnwh`) and a short SHA-256 fingerprint. The test suite checks that no 10-character fragment of a secret reaches any output.
- **Read-only.** Session files are never modified, copied or uploaded. keyspill writes only what you ask for: the HTML report with `--card` / `--html`, and the two files listed above with `protect --apply`.
- **Auditable.** Zero runtime dependencies. Read [`src/`](src) in about fifteen minutes.

Found a security issue? Please report it privately, see [SECURITY.md](SECURITY.md).

## Scripting and CI

keyspill exits with code `1` when it finds a critical or high secret, `0` otherwise, and `2` on usage errors.

```bash
npx keyspill --json > keyspill.json
```

```json
{
  "version": 1,
  "summary": { "total": 9, "critical": 3, "high": 5, "medium": 1 },
  "findings": [
    {
      "rule": "stripe-live",
      "label": "Stripe live secret key",
      "severity": "critical",
      "masked": "sk_live_••••••••fnwh",
      "fingerprint": "3f9a1c0b7e21",
      "count": 1,
      "tools": ["Claude Code"],
      "origins": { "tool": 1, "user": 0, "assistant": 0, "unknown": 0 },
      "lastSeen": "2026-11-02",
      "rotate": "https://dashboard.stripe.com/apikeys"
    }
  ]
}
```

Use `--path` to scan exported transcripts or logs anywhere on disk:

```bash
npx keyspill --path ./exported-sessions --json
```

## FAQ

<details>
<summary><b>It found a key. What should I do?</b></summary>

Rotate it with the provider. Deleting the session log does not undo what the provider already received. Each critical and high finding includes a link to the right settings page.
</details>

<details>
<summary><b>Does keyspill send my data anywhere?</b></summary>

No. It reads local files and prints to your terminal. There is no telemetry and no network code.
</details>

<details>
<summary><b>Why wasn't my secret detected?</b></summary>

keyspill only reports formats it can identify with high confidence. If a real secret was missed, [open an issue](https://github.com/kazbekaskarov/keyspill/issues/new?template=false-positive.yml) describing its format. Never paste the secret itself.
</details>

<details>
<summary><b>How long does a scan take?</b></summary>

Usually seconds. Large histories (around 800 MB) take 20–30 seconds. Progress is shown while it runs.
</details>

## Contributing

Contributions are welcome, especially new agents, new rules and false-positive fixes. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup and guidelines.

```bash
git clone https://github.com/kazbekaskarov/keyspill.git
cd keyspill
npm test
```

## License

[MIT](LICENSE) © Kazbek Askarov
