# Security policy

keyspill reads the most sensitive files on a developer's machine, so its own security matters.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead:
[Report a vulnerability](https://github.com/kazbekaskarov/keyspill/security/advisories/new).

You can expect a first reply within 72 hours. Examples of what counts:

- a full secret (or a recoverable part of one) appearing in terminal, JSON or HTML output
- keyspill making any network request
- keyspill modifying, copying or deleting session files
- `protect --apply` corrupting or losing existing settings

## Never share real secrets

When reporting a false positive or a missed key, send the **masked** line from keyspill's output and describe the format. Never paste a real key into an issue, even an expired one.

## Supported versions

Only the latest published version on npm receives fixes.
