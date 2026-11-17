# keyspill

[![npm](https://img.shields.io/npm/v/keyspill)](https://www.npmjs.com/package/keyspill) [![test](https://github.com/kazbekaskarov/keyspill/actions/workflows/test.yml/badge.svg)](https://github.com/kazbekaskarov/keyspill/actions/workflows/test.yml) ![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

**Find the secrets your AI coding agents have already seen.** · [Website](https://kazbekaskarov.github.io/keyspill/)

![keyspill output in a terminal](docs/terminal.png)

Every time Claude Code reads your `.env`, Codex runs `cat ~/.aws/credentials`, or you paste a key into Cursor to "just debug this one thing", that secret goes to a model provider and stays in a session log on your disk. keyspill reads those logs and tells you exactly which keys to rotate.

```bash
npx keyspill
```

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
  ● Supabase service_role key      ••••••••4cmU
  ...
  HIGH
  ● GitHub token                   ghp_••••••••VKby
      1× · Codex · ~/oss/nanotab · last 2026-11-05
  ● OpenAI API key                 sk-proj-••••••••u9Bn
      you pasted it 1×
```

## Why

Coding agents read files to do their job. Your `.env` is a file. Once a key is in a session it was sent to the model provider, sits in plain text in `~/.claude`, `~/.codex` and friends, and often gets synced to backups. Most people have never looked.

## What it does

- **Scans 7 agents**: Claude Code, Codex, Cursor, Gemini CLI, opencode, Copilot CLI, Cline / Roo Code / Kilo Code (VS Code, Cursor, Windsurf).
- **30 high-signal rules**: AWS, Stripe, OpenAI, Anthropic, GitHub, GitLab, Google, Slack, Telegram, Discord, SendGrid, Twilio, npm, PyPI, Hugging Face, Supabase, DigitalOcean, database URLs, private keys, and `SECRET=`/`PASSWORD=` lines in env files.
- **Tells you how it got there**: the agent read it from a file, you pasted it, or the agent wrote it into a command.
- **Tells you where**: which agent, which project, when it was last seen, and a direct link to rotate it.
- **Low noise**: ignores documentation example keys, placeholders, Supabase anon keys (public by design), expired JWTs, local `postgres:postgres@localhost`, and code like `API_KEY = process.env.API_KEY`. Tested against 216 MB of real Python and Node source with zero false positives.

## Privacy

- Runs entirely on your machine. No network requests. Zero dependencies, under 900 lines you can read in fifteen minutes.
- Never prints, stores or uploads a full secret. Output shows a masked value (`sk_live_••••••••fnwh`) and a short SHA-256 fingerprint.
- Never modifies your session files.

## Share card

```bash
npx keyspill --card
```

Writes `keyspill-report.html` and opens it: the full masked report plus a share card with counts and key types only. Click **Download share card** to get a PNG.

## Stop it happening again

```bash
npx keyspill protect          # show what it would change
npx keyspill protect --apply  # write it
```

Adds `permissions.deny` rules to `~/.claude/settings.json` so Claude Code can't read `.env*`, `*.pem`, `*.key`, `secrets/`, `~/.aws` or `~/.ssh`, and adds a `.cursorignore` to the current project. Your old settings are backed up first. Deny rules cover file reads, not shell commands such as `cat .env`, so keep reading what you approve.

## Options

| Flag | |
|---|---|
| `--card` | write and open the HTML report with the share card |
| `--html <file>` | write the HTML report to a specific file |
| `--json` | machine-readable output (masked values only) |
| `--path <dir>` | also scan another folder or file, repeatable |
| `--all` | list every finding |
| `--no-open`, `--no-color` | |

Exit code is `1` when a critical or high secret is found, so it works in scripts.

## Where it looks

| Agent | Location |
|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` (respects `CLAUDE_CONFIG_DIR`) |
| Codex | `~/.codex/sessions/**`, `~/.codex/history.jsonl` (respects `CODEX_HOME`) |
| Cursor | `state.vscdb` in Cursor's global and workspace storage, `~/.cursor/chats` |
| Gemini CLI | `~/.gemini/tmp/**` |
| opencode | `~/.local/share/opencode/storage` |
| Copilot CLI | `~/.copilot/session-state` |
| Cline / Roo / Kilo | `globalStorage/<extension>/tasks/*` in VS Code, Cursor, Windsurf |

Missing your agent? Open an issue with where it keeps its history, or a PR adding a source in `src/sources.js`.

## Contributing

```bash
git clone https://github.com/kazbekaskarov/keyspill && cd keyspill
npm test
```

Rules live in `src/rules.js`. A new rule needs a test in `test/`. Test fixtures build fake keys at runtime, so please don't commit token-shaped strings.

## License

MIT
