import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan, summarize } from '../src/scan.js';
import { decodeClaudeDir } from '../src/sources.js';
import { makeHome, SECRETS } from './fixtures.js';

const BIN = fileURLToPath(new URL('../bin/keyspill.js', import.meta.url));
const home = makeHome();
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(XDG_|CLAUDE_CONFIG_DIR|CODEX_HOME|APPDATA)/.test(k)));
const result = await scan({ home, env: {} });
const by = (rule) => result.findings.filter((f) => f.rule === rule);

test('finds secrets across Claude Code, Codex, Copilot CLI and Cursor', () => {
  assert.deepEqual(Object.keys(result.stats.byTool).sort(), ['Claude Code', 'Codex', 'Copilot CLI', 'Cursor']);
  assert.equal(by('stripe-live').length, 1);
  assert.equal(by('openai-key').length, 1);
  assert.equal(by('github-token').length, 1);
  assert.equal(by('telegram-bot').length, 1, 'non-JSON lines are scanned raw');
  assert.equal(by('anthropic-key').length, 2, 'including a key that straddles the 1 MiB chunk boundary');
});

test('Stripe key read via tool is counted per occurrence with origin and project', () => {
  const f = by('stripe-live')[0];
  assert.equal(f.severity, 'critical');
  assert.equal(f.count, 1, 'tool_result + toolUseResult copy on one line count once');
  assert.equal(f.origins.tool, 1);
  assert.deepEqual(f.projects, ['/Users/kaz/work/shop']);
  assert.equal(new Date(f.lastSeen).toISOString().slice(0, 10), '2026-11-02');
});

test('pasted key is attributed to the user; Codex project comes from session_meta', () => {
  assert.equal(by('openai-key')[0].origins.user, 1);
  assert.deepEqual(by('github-token')[0].projects, ['/Users/kaz/oss/nanotab']);
});

test('remote DB password is critical, local default creds are ignored', () => {
  const db = by('db-url').find((f) => f.tools.includes('Claude Code'));
  assert.equal(db.severity, 'critical');
  assert.ok(!db.display.includes(SECRETS.dbPass));
});

test('DB URLs: one finding per credentials, doc placeholders ignored, password not double-counted', () => {
  const db = by('db-url');
  assert.equal(db.length, 2, 'Claude Code postgres + Copilot mongo; USER:PASSWORD@HOST, @cluster and Cyrillic examples dropped');
  const mongo = db.find((f) => f.display.startsWith('mongodb'));
  assert.equal(mongo.count, 2, 'same user:pass@host with different /db?options tails is one finding');
  assert.deepEqual(by('env-secret').filter((f) => f.varName === 'MONGODB_PASSWORD'), [], 'already covered by the URL finding');
});

test('Copilot CLI: origin and project come from its event format', () => {
  const mongo = by('db-url').find((f) => f.display.startsWith('mongodb'));
  assert.deepEqual(mongo.tools, ['Copilot CLI']);
  assert.equal(mongo.origins.user, 1);
  assert.equal(mongo.origins.tool, 1);
  assert.deepEqual(mongo.projects, ['/Users/kaz/hexweave']);
});

test('Supabase: service_role is critical, anon key is ignored', () => {
  const j = result.findings.filter((f) => f.rule === 'jwt');
  assert.deepEqual(j.map((f) => f.label).sort(), ['Supabase service_role key', 'Unexpired JWT'], 'expired JWT and anon key ignored');
  assert.equal(j.find((f) => f.label.startsWith('Supabase')).severity, 'critical');
});

test('generic env secret found; placeholders, process.env and config numbers are not', () => {
  const g = by('env-secret');
  assert.deepEqual(g.map((f) => f.varName).sort(), ['API_TOKEN', 'JWT_SECRET'], 'code-like assignments are not secrets; YAML value is');
  assert.equal(by('aws-access-key').length, 0, 'AWS documentation example key is ignored');
});

test('summary counts add up', () => {
  const s = summarize(result.findings);
  assert.equal(s.total, s.critical + s.high + s.medium);
  assert.equal(s.critical, 4); // stripe, postgres, mongo, service_role
});

test('no full secret ever appears in terminal, JSON or HTML output', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'keyspill-out-'));
  const html = path.join(out, 'r.html');
  const term = spawnSync(process.execPath, [BIN, '--home', home, '--all', '--html', html, '--no-open', '--no-color'], { encoding: 'utf8', env: cleanEnv });
  const json = spawnSync(process.execPath, [BIN, '--home', home, '--json'], { encoding: 'utf8', env: cleanEnv });
  assert.equal(term.status, 1, 'exit 1 when critical/high found');
  const all = term.stdout + term.stderr + json.stdout + fs.readFileSync(html, 'utf8');
  for (const [name, secret] of Object.entries(SECRETS)) {
    if (['awsDocExample', 'anonKey', 'oldJwt'].includes(name)) continue;
    // not even a 10-char run of the secret body may leak
    const body = secret.replace(/^(sk_live_|sk-proj-|sk-ant-api03-|ghp_)/, '');
    for (let i = 0; i + 10 <= body.length; i += 5) {
      assert.ok(!all.includes(body.slice(i, i + 10)), `${name} leaked into output`);
    }
  }
  assert.match(term.stdout, /secrets seen by your agents/);
  assert.equal(JSON.parse(json.stdout).summary.total, result.findings.length);
});

test('clean home: friendly message, exit 0', () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'keyspill-empty-'));
  const r = spawnSync(process.execPath, [BIN, '--home', empty, '--no-color'], { encoding: 'utf8', env: cleanEnv });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /No agent session history found/);
});

test('Claude Code project dirs decode on macOS/Linux and Windows', () => {
  assert.equal(decodeClaudeDir('-Users-kaz-work-shop'), '/Users/kaz/work/shop');
  assert.equal(decodeClaudeDir('C--Users-kaz-work'), 'C:\\Users\\kaz\\work');
  assert.equal(decodeClaudeDir(''), '');
});

test('options that need a value fail loudly instead of guessing', () => {
  for (const flag of ['--path', '--home']) {
    const r = spawnSync(process.execPath, [BIN, flag, '--no-color'], { encoding: 'utf8', env: cleanEnv });
    assert.equal(r.status, 2, `${flag} without a value`);
    assert.match(r.stderr, new RegExp(`${flag} needs a value`));
  }
});

test('--version prints package version', () => {
  const r = spawnSync(process.execPath, [BIN, '--version'], { encoding: 'utf8', env: cleanEnv });
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(r.stdout.trim(), pkg.version);
});

test('protect --apply merges deny rules and backs up settings', () => {
  const h = fs.mkdtempSync(path.join(os.tmpdir(), 'keyspill-prot-'));
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), 'keyspill-proj-'));
  fs.mkdirSync(path.join(h, '.claude'));
  fs.writeFileSync(path.join(h, '.claude', 'settings.json'), JSON.stringify({ model: 'opus', permissions: { deny: ['Bash(rm -rf:*)'] } }));
  const r = spawnSync(process.execPath, [BIN, 'protect', '--apply', '--home', h, '--no-color'], { encoding: 'utf8', cwd: proj, env: cleanEnv });
  assert.equal(r.status, 0, r.stderr);
  const s = JSON.parse(fs.readFileSync(path.join(h, '.claude', 'settings.json'), 'utf8'));
  assert.equal(s.model, 'opus');
  assert.ok(s.permissions.deny.includes('Bash(rm -rf:*)'));
  assert.ok(s.permissions.deny.includes('Read(./.env)'));
  assert.ok(fs.readdirSync(path.join(h, '.claude')).some((f) => f.includes('keyspill-backup')));
  assert.match(fs.readFileSync(path.join(proj, '.cursorignore'), 'utf8'), /\.env/);
  // idempotent
  const again = spawnSync(process.execPath, [BIN, 'protect', '--home', h, '--no-color'], { encoding: 'utf8', cwd: proj, env: cleanEnv });
  assert.match(again.stdout, /already protected/);
});
