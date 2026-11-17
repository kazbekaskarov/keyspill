# Contributing to keyspill

Thanks for helping. keyspill is small on purpose, and the bar for changes is simple: fewer false positives, more agents, no new risk to users' secrets.

## Ground rules

These protect the people who run keyspill on their most sensitive files. Pull requests that break them won't be merged.

1. **Never commit a real secret**, not even an expired or revoked one. Test fixtures build token-shaped strings at runtime from pieces (see [`test/fixtures.js`](test/fixtures.js)), so scanners and GitHub push protection stay quiet.
2. **No runtime dependencies.** Node.js built-ins only.
3. **No network access.** keyspill must never make a request, including from the HTML report.
4. **Never output a full secret.** Anything shown to the user goes through masking in [`src/rules.js`](src/rules.js).
5. **Read-only by default.** Only `protect --apply` and an explicitly requested HTML report may write files.

## Development setup

Requirements: Node.js 18 or later and git.

```bash
git clone https://github.com/kazbekaskarov/keyspill.git
cd keyspill
npm test
```

Run your local copy:

```bash
node bin/keyspill.js                 # scan your real history
node bin/keyspill.js --home /tmp/x   # scan a fake home directory instead
```

There is no build step. The code is plain ES modules.

## Project structure

```
bin/keyspill.js   CLI entry: argument parsing, exit codes
src/sources.js    where each agent keeps its history, per platform
src/scan.js       file readers (JSONL, JSON, binary) and the matcher
src/rules.js      detection rules, placeholder filters, masking
src/report.js     terminal and JSON output
src/html.js       self-contained HTML report and share card
src/protect.js    `keyspill protect`
test/fixtures.js  builds a fake home directory with fake sessions
test/*.test.js    tests (node:test)
docs/             website (GitHub Pages) and README images
```

## Common contributions

### Fixing a false positive

1. Reproduce it in `test/fixtures.js` by adding the non-secret string to a fake session.
2. Add an assertion in `test/scan.test.js` that it is **not** reported.
3. Tighten the rule's regex or its `check()` function in `src/rules.js`, or extend `looksPlaceholder()`.
4. Make sure every existing test still passes. A fix that hides real secrets is worse than the false positive.

### Adding a detection rule

Rules live in the `RULES` array in [`src/rules.js`](src/rules.js):

```js
{
  id: 'acme-token',              // stable, kebab-case; appears in --json output
  label: 'Acme API token',       // shown to the user
  severity: 'high',              // critical | high | medium
  re: /\b(acme_[A-Za-z0-9]{32})\b/g,  // capture group 1 is the secret
  prefix: 'acme_',               // non-secret part that is safe to show
  rotate: 'https://acme.example/settings/tokens',
}
```

Guidelines:

- **Prefer formats with a fixed, documented prefix.** Generic "looks random" rules create noise.
- **Severity:** `critical` for keys that grant production or billing access, `high` for API tokens, `medium` for things that are risky only in context.
- **Add a `rotate` link** to the provider's key management page when one exists.
- **Add a test** that the secret is found and that its full value never appears in the output. The existing leak test covers new entries in `SECRETS` automatically.

### Adding an agent

Sources live in [`src/sources.js`](src/sources.js). Each one lists root paths per platform and a filename filter:

```js
{
  id: 'acme-agent', name: 'Acme Agent',
  roots: [path.join(home, '.acme', 'sessions')],
  match: (f) => f.endsWith('.jsonl'),
}
```

If the agent's log format marks tool output, user messages or the working directory differently from the agents already supported, extend `TOOL_TYPES`, `USER_TYPES` or the `cwd` lookup in [`src/scan.js`](src/scan.js) so findings show how the secret got there and which project it came from.

Add a fake session for the agent in `test/fixtures.js` that mirrors the real file layout, with real secrets replaced by runtime-built fakes. Describe the real format in your PR, but **don't attach real session files**.

## Pull requests

- Keep each PR focused on one change.
- Run `npm test` before pushing. CI runs the suite on Linux, macOS and Windows with Node 18, 20, 22 and 24.
- Update [`CHANGELOG.md`](CHANGELOG.md) under an `Unreleased` heading.
- Update the README if you change user-facing behavior, options or supported agents.
- Use clear commit messages in the imperative mood: `Add Acme token rule`, `Ignore Supabase anon keys in YAML`.

## Reporting issues

- **False positive or missed secret:** use the [issue template](https://github.com/kazbekaskarov/keyspill/issues/new?template=false-positive.yml) and include the masked line from keyspill's output.
- **New agent:** use the [new agent template](https://github.com/kazbekaskarov/keyspill/issues/new?template=new-agent.yml).
- **Security vulnerability:** report it privately as described in [SECURITY.md](SECURITY.md), not as a public issue.

## Releasing (maintainers)

1. Move `Unreleased` entries in `CHANGELOG.md` under the new version and date.
2. `npm version <patch|minor|major>` (bumps `package.json`, commits and tags).
3. `git push --follow-tags`
4. `npm publish`. `prepublishOnly` runs the tests. With 2FA, approve the staged release on npmjs.com.
5. `gh release create vX.Y.Z --notes-file <section of CHANGELOG>`

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Be kind and assume good intent.
