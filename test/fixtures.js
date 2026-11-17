// Builds a fake home directory full of fake agent sessions.
// Secrets are assembled at runtime from pieces so that no token-shaped literal
// lives in this repo (keeps GitHub push protection and other scanners quiet).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const rnd = (n, alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789') => {
  let s = '';
  let x = 1234567 + n * 7919;
  for (let i = 0; i < n; i++) { x = (x * 48271) % 2147483647; s += alphabet[x % alphabet.length]; }
  return s;
};
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload) => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.${rnd(43)}`;

export const SECRETS = {
  stripeLive: 'sk' + '_live_' + rnd(32),
  dbPass: 'Qz' + rnd(14),
  mongoPass: 'Mg7' + rnd(15),
  openai: 'sk-' + 'proj-' + rnd(48),
  github: 'gh' + 'p_' + rnd(36),
  anthropic: 'sk-' + 'ant-api03-' + rnd(90),
  anthropicBoundary: 'sk-' + 'ant-api03-' + rnd(91),
  telegram: '7' + '123456789'.slice(0, 8) + ':' + 'AA' + rnd(33),
  serviceRole: jwt({ iss: 'supabase', role: 'service_role', ref: 'abc' }),
  anonKey: jwt({ iss: 'supabase', role: 'anon', ref: 'abc' }),
  jwtSecret: 's3cr3t-' + rnd(12),
  liveJwt: jwt({ sub: 'u_42', exp: Math.floor(Date.now() / 1000) + 3600 }),
  oldJwt: jwt({ sub: 'u_42', exp: 1500000000 }),
  yamlToken: 'Zx81kLmQpR47vTnW' + rnd(6),
  awsDocExample: 'AKIA' + 'IOSFODNN7' + 'EXAMPLE',
};

export function makeHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keyspill-home-'));
  const S = SECRETS;

  // Claude Code: agent reads .env via a tool call; user pastes an OpenAI key; a doc example key; anon key.
  const ccDir = path.join(home, '.claude', 'projects', '-Users-kaz-work-shop');
  fs.mkdirSync(ccDir, { recursive: true });
  const envFile = [
    `STRIPE_SECRET_KEY=${S.stripeLive}`,
    `DATABASE_URL=postgres://app:${S.dbPass}@db.prod.acme-internal.net:5432/shop`,
    `LOCAL_DB=postgres://postgres:postgres@localhost:5432/dev`,
    `JWT_SECRET=${S.jwtSecret}`,
    `PASSWORD_MIN_LENGTH=8`,
    `SUPABASE_ANON_KEY=${S.anonKey}`,
    `SUPABASE_SERVICE_ROLE_KEY=${S.serviceRole}`,
  ].join('\n');
  const cc = [
    { type: 'user', cwd: '/Users/kaz/work/shop', timestamp: '2026-11-02T10:00:00Z', message: { role: 'user', content: `here is my key ${S.openai} why does it 401` } },
    { type: 'assistant', cwd: '/Users/kaz/work/shop', timestamp: '2026-11-02T10:00:05Z', message: { role: 'assistant', content: [{ type: 'tool_use', name: 'Read', input: { file_path: '.env' } }] } },
    { type: 'user', cwd: '/Users/kaz/work/shop', timestamp: '2026-11-02T10:00:06Z', message: { role: 'user', content: [{ type: 'tool_result', content: envFile }] }, toolUseResult: { file: { content: envFile } } },
    { type: 'user', cwd: '/Users/kaz/work/shop', timestamp: '2026-11-02T10:00:07Z', message: { role: 'user', content: [{ type: 'tool_result', content: [
      'ERRORTOKEN = token.ERRORTOKEN', 'ACCESS_TOKEN_KEY = "access_key:84"', 'HEADER_TOKEN_RE = re.compile(r"^x")',
      'WHITESPACE_TOKENS = (_WHITESPACE_TOKENS = {})', 'CHALLENGE_PASSWORD = ObjectIdentifier("1.2.840")',
      `services:\n  api:\n    environment:\n      API_TOKEN: ${S.yamlToken}`,
      `Authorization: Bearer ${S.liveJwt}`, `old: ${S.oldJwt}`,
    ].join('\n') }] } },
    { type: 'assistant', cwd: '/Users/kaz/work/shop', timestamp: '2026-11-02T10:00:09Z', message: { role: 'assistant', content: `AWS docs use ${S.awsDocExample} as an example. Use const API_KEY = process.env.API_KEY instead.` } },
  ];
  fs.writeFileSync(path.join(ccDir, 's1.jsonl'), cc.map((l) => JSON.stringify(l)).join('\n') + '\nnot json but has ' + S.telegram + '\n');

  // Codex: GitHub token in a function_call_output.
  const cxDir = path.join(home, '.codex', 'sessions', '2026', '11', '05');
  fs.mkdirSync(cxDir, { recursive: true });
  const cx = [
    { timestamp: '2026-11-05T08:00:00Z', type: 'session_meta', payload: { cwd: '/Users/kaz/oss/nanotab' } },
    { timestamp: '2026-11-05T08:01:00Z', type: 'response_item', payload: { type: 'function_call_output', output: `$ cat ~/.npmrc\n//registry.npmjs.org/:_authToken=x\nGITHUB_TOKEN=${S.github}` } },
  ];
  fs.writeFileSync(path.join(cxDir, 'rollout-2026-11-05.jsonl'), cx.map((l) => JSON.stringify(l)).join('\n') + '\n');

  // Copilot CLI: events.jsonl. The agent reads a .env (same DB as Claude Code, with a different /db?options
  // tail and a separate MONGODB_PASSWORD line), the user pastes a Mongo URL; docs placeholders appear too.
  const coDir = path.join(home, '.copilot', 'session-state', 'f00d');
  fs.mkdirSync(coDir, { recursive: true });
  const mongo = `mongodb+srv://kaz_db:${S.mongoPass}@hexweave.ab12cd.mongodb.net`;
  const co = [
    { type: 'session.start', timestamp: '2026-08-30T09:00:00Z', data: { context: { cwd: '/Users/kaz/hexweave' } } },
    { type: 'user.message', timestamp: '2026-08-30T09:01:00Z', data: { content: `connect fails: ${mongo}/app?retryWrites=true` } },
    { type: 'tool.execution_complete', timestamp: '2026-08-30T09:02:00Z', data: { result: { content: `MONGODB_URI=${mongo}/?appName=hex\nMONGODB_PASSWORD=${S.mongoPass}` } } },
    { type: 'assistant.message', timestamp: '2026-08-30T09:03:00Z', data: { content: [
      'Format: mongodb+srv://USER:PASSWORD@HOST/db', 'or mongodb+srv://user:pa55w0rdX@cluster/db',
      'по-русски: mongodb+srv://ПОЛЬЗОВАТЕЛЬ:ПаРоЛь123@ХОСТ.mongodb.net',
    ].join('\n') } },
  ];
  fs.writeFileSync(path.join(coDir, 'events.jsonl'), co.map((l) => JSON.stringify(l)).join('\n') + '\n');

  // Cursor: binary sqlite-ish blob, >1 MiB, with one key straddling the 1 MiB chunk boundary.
  // Same layout sources.js expects for this platform (tests pass env: {}, so no APPDATA / XDG overrides).
  const cuUser = process.platform === 'darwin' ? path.join(home, 'Library', 'Application Support', 'Cursor', 'User')
    : process.platform === 'win32' ? path.join(home, 'AppData', 'Roaming', 'Cursor', 'User')
      : path.join(home, '.config', 'Cursor', 'User');
  const cuDir = path.join(cuUser, 'globalStorage');
  fs.mkdirSync(cuDir, { recursive: true });
  const filler = Buffer.alloc(1 << 20, 0x00);
  const before = Buffer.from(`{"text":"key is ${S.anthropic} ok"}`);
  const straddle = Buffer.from(`"${S.anthropicBoundary}"`);
  const cut = 1 << 20;
  const blob = Buffer.concat([before, filler]).subarray(0, cut - 30);
  fs.writeFileSync(path.join(cuDir, 'state.vscdb'), Buffer.concat([blob, straddle, Buffer.alloc(5000, 0x01)]));

  return home;
}
