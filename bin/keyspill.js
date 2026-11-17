#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { scan, summarize } from '../src/scan.js';
import { printReport, toJson, c, fmtBytes } from '../src/report.js';
import { renderHtml } from '../src/html.js';
import { protect } from '../src/protect.js';

const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const HELP = `
  ${c.bold('keyspill')} — find the secrets your AI coding agents have already seen

  ${c.bold('Usage')}
    npx keyspill                 scan local agent history, print a report
    npx keyspill --card          also write an HTML report with a share card and open it
    npx keyspill protect         show rules that stop agents reading .env/keys
    npx keyspill protect --apply write those rules (backs up your settings first)

  ${c.bold('Options')}
    --json           machine-readable output (masked values only)
    --html <file>    write the HTML report to <file> (default ./keyspill-report.html)
    --path <dir>     also scan this file or folder (repeatable)
    --all            list every finding, not just the top ones
    --no-open        don't open the HTML report automatically
    --no-color       plain output
    -v, --version    print version

  Scans: Claude Code, Codex, Cursor, Gemini CLI, opencode, Copilot CLI, Cline / Roo / Kilo.
  Runs 100% locally. Never uploads, never stores or prints a full secret.
  Exit code: 1 if a critical or high secret is found (handy in scripts), 0 otherwise.
`;

function parseArgs(argv) {
  const a = { paths: [], cmd: 'scan' };
  const value = (i, flag) => {
    const v = argv[i + 1];
    if (!v || v.startsWith('-')) { console.error(`Option ${flag} needs a value.\n${HELP}`); process.exit(2); }
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === 'protect') a.cmd = 'protect';
    else if (k === '--apply') a.apply = true;
    else if (k === '--json') a.json = true;
    else if (k === '--card') a.html = a.html || 'keyspill-report.html';
    else if (k === '--html') a.html = argv[i + 1] && !argv[i + 1].startsWith('-') ? argv[++i] : 'keyspill-report.html';
    else if (k === '--path') a.paths.push(path.resolve(value(i++, k)));
    else if (k === '--home') a.home = path.resolve(value(i++, k)); // for testing
    else if (k === '--all') a.all = true;
    else if (k === '--no-open') a.noOpen = true;
    else if (k === '--no-color') { /* read in report.js */ }
    else if (k === '-h' || k === '--help') a.help = true;
    else if (k === '-v' || k === '--version') a.version = true;
    else { console.error(`Unknown option: ${k}\n${HELP}`); process.exit(2); }
  }
  return a;
}

function openFile(file) {
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', file] : [file];
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).on('error', () => {}).unref(); } catch { /* headless */ }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) return console.log(HELP);
  if (args.version) return console.log(VERSION);
  if (args.cmd === 'protect') process.exit(protect({ apply: args.apply, home: args.home }));

  const live = process.stderr.isTTY && !args.json;
  const result = await scan({
    home: args.home || os.homedir(),
    extraPaths: args.paths,
    onProgress: live ? ({ files, totalFiles, bytes }) => {
      process.stderr.write(`\r  ${c.gray(`scanning ${files}/${totalFiles} files · ${fmtBytes(bytes)}`)}   `);
    } : undefined,
  });
  if (live) process.stderr.write('\r\x1b[K');

  if (args.json) console.log(toJson(result));
  else printReport(result, { all: args.all });

  if (args.html) {
    const out = path.resolve(args.html);
    fs.writeFileSync(out, renderHtml(result));
    if (!args.json) console.log(`  ${c.bold('Report:')} ${out}\n`);
    if (!args.noOpen) openFile(out);
  }

  const s = summarize(result.findings);
  process.exitCode = s.critical + s.high > 0 ? 1 : 0;
}

main().catch((e) => { console.error(c.red('keyspill failed: ') + (e?.stack || e)); process.exit(2); });
