import fs from 'node:fs';
import readline from 'node:readline';
import crypto from 'node:crypto';
import path from 'node:path';
import { RULES, displayFor, looksPlaceholder } from './rules.js';
import { getSources, walk } from './sources.js';

const SEV_RANK = { critical: 3, high: 2, medium: 1 };
const JSON_WHOLE_LIMIT = 64 * 1024 * 1024;
const CHUNK_OVERLAP = 4096;

export async function scan({ home, env = process.env, extraPaths = [], onProgress = () => {} } = {}) {
  const started = Date.now();
  const sources = getSources(home, env);
  if (extraPaths.length) {
    sources.push({
      id: 'custom', name: 'Custom path', roots: extraPaths,
      match: (f) => /\.(jsonl?|vscdb|db|md|txt|log)$/.test(f),
    });
  }

  const findings = new Map();
  const stats = { files: 0, bytes: 0, byTool: {}, durationMs: 0 };

  // Discover first so progress can show totals.
  const jobs = [];
  for (const src of sources) {
    for (const root of src.roots) {
      for (const f of walk(root, src.match)) jobs.push({ src, root, ...f });
    }
  }
  const totalBytes = jobs.reduce((a, j) => a + j.size, 0);

  for (const job of jobs) {
    const { src, file } = job;
    stats.byTool[src.name] = (stats.byTool[src.name] || 0) + 1;
    const base = {
      tool: src.name, file, mtime: job.mtime,
      project: src.projectFromPath ? src.projectFromPath(file, job.root) : '',
    };
    try {
      if (src.binary || /\.(vscdb|db)$/.test(file)) await scanRaw(file, base, findings);
      else if (file.endsWith('.jsonl')) await scanJsonl(file, base, findings);
      else if (file.endsWith('.json') && job.size < JSON_WHOLE_LIMIT) scanJsonFile(file, base, findings);
      else await scanRaw(file, base, findings);
    } catch {
      // unreadable file (locked DB, permissions): skip silently, it is reported in stats as scanned=false
      continue;
    }
    stats.files++;
    stats.bytes += job.size;
    onProgress({ files: stats.files, totalFiles: jobs.length, bytes: stats.bytes, totalBytes });
  }

  // Drop generic env hits whose value was also caught by a specific rule.
  const specificHashes = new Set([...findings.values()].filter((f) => !f.generic).flatMap((f) => [f.hash, f.secretHash]));
  for (const [k, f] of findings) if (f.generic && specificHashes.has(f.hash)) findings.delete(k);

  stats.durationMs = Date.now() - started;
  const list = [...findings.values()]
    .map(finalize)
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.lastSeen - a.lastSeen);
  return { findings: list, stats };
}

function finalize({ _seen, secretHash, ...f }) {
  return {
    ...f,
    tools: [...f.tools],
    projects: [...f.projects].filter(Boolean),
    files: [...f.files],
  };
}

// ---------- file readers ----------

async function scanJsonl(file, base, findings) {
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  const state = { project: base.project, ts: null };
  let n = 0;
  for await (const line of rl) {
    n++;
    if (line.length < 8) continue;
    state.lineKey = n;
    let obj;
    try { obj = JSON.parse(line); } catch { scanString(line, ctx(base, state, 'unknown'), findings); continue; }
    if (obj && typeof obj === 'object') {
      const cwd = obj.cwd || obj.payload?.cwd || obj.data?.context?.cwd || obj.data?.input?.cwd || obj.data?.workingDirectory;
      if (typeof cwd === 'string') state.project = cwd;
      const ts = obj.timestamp || obj.payload?.timestamp || obj.ts;
      if (ts) state.ts = toMs(ts);
    }
    walkJson(obj, 'unknown', (s, origin) => scanString(s, ctx(base, state, origin), findings));
  }
}

function scanJsonFile(file, base, findings) {
  const text = fs.readFileSync(file, 'utf8');
  let obj;
  try { obj = JSON.parse(text); } catch { scanString(text, ctx(base, {}, 'unknown'), findings); return; }
  const state = { project: base.project || findCwd(obj), ts: null };
  walkJson(obj, 'unknown', (s, origin) => scanString(s, ctx(base, state, origin), findings));
}

async function scanRaw(file, base, findings) {
  const stream = fs.createReadStream(file, { highWaterMark: 1 << 20 });
  let tail = '';
  for await (const buf of stream) {
    const text = tail + buf.toString('latin1');
    scanString(text, { ...ctx(base, {}, 'unknown'), minEnd: tail.length }, findings);
    tail = text.slice(-CHUNK_OVERLAP);
  }
}

function ctx(base, state, origin) {
  return { ...base, project: state.project || base.project, ts: state.ts || base.mtime, origin, lineKey: state.lineKey };
}

function toMs(ts) {
  if (typeof ts === 'number') return ts < 1e12 ? ts * 1000 : ts;
  const t = Date.parse(ts);
  return Number.isNaN(t) ? null : t;
}

function findCwd(obj) {
  let found = '';
  walkJson(obj, 'unknown', () => {}, (node) => {
    if (!found && typeof node.cwd === 'string') found = node.cwd;
  });
  return found;
}

// Walk every string in a JSON value, tracking where it came from:
//   tool      = output of a tool call (the agent read a file / ran a command)
//   user      = something you typed or pasted
//   assistant = something the agent wrote (e.g. a command it ran)
// Event `type` values that mark tool output, per agent (Claude Code, Codex, opencode, Copilot CLI).
const TOOL_TYPES = new Set(['tool_result', 'function_call_output', 'tool', 'tool-result', 'local_shell_call_output', 'tool.execution_complete']);
// Event `type` values that mark who spoke when there is no `role` field.
const USER_TYPES = new Map([
  ['user', 'user'], ['user.message', 'user'],
  ['assistant', 'assistant'], ['assistant.message', 'assistant'], ['model.message', 'assistant'], ['model.response', 'assistant'],
]);

function walkJson(root, origin, onString, onObject) {
  const stack = [[root, origin]];
  while (stack.length) {
    const [node, o] = stack.pop();
    if (typeof node === 'string') { if (node.length >= 8) onString(node, o); continue; }
    if (!node || typeof node !== 'object') continue;
    if (Array.isArray(node)) { for (const v of node) stack.push([v, o]); continue; }
    onObject?.(node);
    let here = o;
    const t = node.type;
    if (TOOL_TYPES.has(t) || node.role === 'tool') here = 'tool';
    else if (o !== 'tool') {
      const role = node.role || USER_TYPES.get(t) || null;
      if (role === 'user') here = 'user';
      else if (role === 'assistant' || role === 'model') here = 'assistant';
    }
    for (const [k, v] of Object.entries(node)) {
      const childOrigin = k === 'toolUseResult' || k === 'functionResponse' ? 'tool' : here;
      stack.push([v, childOrigin]);
    }
  }
}

// ---------- the matcher ----------

export function scanString(text, c, findings) {
  const spans = [];
  for (const rule of RULES) {
    if (rule.generic && !/[=:]/.test(text)) continue;
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text))) {
      const value = m[rule.group || 1];
      const start = m.index + m[0].indexOf(value);
      const end = start + value.length;
      if (c.minEnd && end <= c.minEnd) continue; // already counted in the previous chunk
      if (rule.generic && spans.some(([s, e]) => start < e && end > s)) continue;
      if (rule.id !== 'db-url' && looksPlaceholder(value)) continue;
      let verdict = true;
      if (rule.check) verdict = rule.check(value, m);
      if (!verdict) continue;
      spans.push([start, end]);
      record(rule, value, verdict === true ? {} : verdict, m, c, findings);
    }
  }
}

function record(rule, value, override, m, c, findings) {
  const sha = (s) => crypto.createHash('sha256').update(s).digest('hex').slice(0, 12);
  const hash = sha(rule.canonical ? rule.canonical(value) : value);
  const key = rule.id + ':' + hash;
  let f = findings.get(key);
  if (!f) {
    f = {
      id: key, rule: rule.id, hash,
      secretHash: rule.secretPart ? sha(rule.secretPart(value)) : hash,
      label: override.label || rule.label,
      severity: override.severity || rule.severity,
      generic: !!rule.generic,
      varName: rule.nameGroup ? m[rule.nameGroup] : undefined,
      display: displayFor(rule, value),
      rotate: override.rotate || rule.rotate,
      count: 0, tools: new Set(), projects: new Set(), files: new Set(),
      origins: { tool: 0, user: 0, assistant: 0, unknown: 0 },
      firstSeen: Infinity, lastSeen: 0,
    };
    findings.set(key, f);
  }
  // One JSONL line is one event; agents often store the same tool output twice in it.
  if (c.lineKey !== undefined && f._seen === c.file + '#' + c.lineKey) return;
  if (c.lineKey !== undefined) f._seen = c.file + '#' + c.lineKey;
  f.count++;
  f.tools.add(c.tool);
  if (c.project) f.projects.add(c.project);
  f.files.add(c.file);
  f.origins[c.origin] = (f.origins[c.origin] || 0) + 1;
  const ts = c.ts || c.mtime;
  if (ts < f.firstSeen) f.firstSeen = ts;
  if (ts > f.lastSeen) f.lastSeen = ts;
}

export function summarize(findings) {
  const s = { total: findings.length, critical: 0, high: 0, medium: 0, byTool: {}, byOrigin: { tool: 0, user: 0, assistant: 0 } };
  for (const f of findings) {
    s[f.severity]++;
    for (const t of f.tools) s.byTool[t] = (s.byTool[t] || 0) + 1;
    const top = Object.entries(f.origins).filter(([k]) => k !== 'unknown').sort((a, b) => b[1] - a[1])[0];
    if (top && top[1] > 0) s.byOrigin[top[0]]++;
  }
  return s;
}

export const _internal = { walkJson, path };
