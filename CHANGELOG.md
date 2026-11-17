# Changelog

All notable changes to this project are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/).

## 0.1.1 — 2026-11-17

- Database URLs now mask the login and hostname as well as the password, so screenshots of a report don't reveal internal infrastructure: `mongodb+srv://ka•••:••••••@••••.mongodb.net`. Only the provider's domain stays readable.
- Package `homepage` now points to the website.

## 0.1.0 — 2026-11-18

First release.

- Scans local session history of Claude Code, Codex, Cursor, Gemini CLI, opencode, Copilot CLI and Cline / Roo / Kilo Code.
- 30 detection rules with placeholder, documentation-example and expired-token filtering.
- Shows how each secret got into a session (agent read it, you pasted it, agent wrote it), which project, when, and where to rotate it.
- Terminal, `--json` and HTML report with a shareable card that contains counts only.
- `keyspill protect` adds Claude Code deny rules and a `.cursorignore`.
