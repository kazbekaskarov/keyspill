import os from 'node:os';
import { summarize } from './scan.js';

const useColor = () => process.stdout.isTTY && !process.env.NO_COLOR && !process.argv.includes('--no-color');
const wrap = (code) => (s) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : String(s));
export const c = {
  bold: wrap('1'), dim: wrap('2'), red: wrap('31'), green: wrap('32'), yellow: wrap('33'),
  magenta: wrap('35'), cyan: wrap('36'), gray: wrap('90'), bgRed: wrap('41;97;1'),
};

const SEV = {
  critical: { dot: c.red('●'), name: (s) => c.red(c.bold(s)) },
  high: { dot: c.yellow('●'), name: (s) => c.yellow(c.bold(s)) },
  medium: { dot: c.gray('●'), name: (s) => c.gray(c.bold(s)) },
};

export function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
}

export function fmtDate(ms) {
  if (!ms || !Number.isFinite(ms)) return '—';
  return new Date(ms).toISOString().slice(0, 10);
}

export function shortPath(p) {
  const h = os.homedir();
  if (!p) return p;
  // Windows paths are case-insensitive and agents log the drive letter either way (c:\ vs C:\).
  const starts = process.platform === 'win32' ? p.toLowerCase().startsWith(h.toLowerCase()) : p.startsWith(h);
  return starts ? '~' + p.slice(h.length) : p;
}

function originText(o) {
  const parts = [];
  if (o.tool) parts.push(`agent read it ${o.tool}×`);
  if (o.user) parts.push(`you pasted it ${o.user}×`);
  if (o.assistant) parts.push(`agent wrote it ${o.assistant}×`);
  return parts.join(' · ');
}

export function printReport({ findings, stats }, { all = false } = {}) {
  const s = summarize(findings);
  const tools = Object.keys(stats.byTool);
  const out = [];
  out.push('');
  out.push(`  ${c.bold('keyspill')} ${c.gray('· what your AI agents have already seen')}`);
  out.push(c.gray(`  Scanned ${stats.files.toLocaleString()} session files (${fmtBytes(stats.bytes)}) from ${tools.length ? tools.join(', ') : 'no agents'} in ${(stats.durationMs / 1000).toFixed(1)}s · 100% local, nothing uploaded`));
  out.push('');

  if (!tools.length) {
    out.push(`  ${c.yellow('No agent session history found.')} Looked for Claude Code, Codex, Cursor, Gemini CLI, opencode, Copilot CLI, Cline/Roo.`);
    out.push(c.gray('  Use --path <dir> to scan somewhere else.'));
    out.push('');
    console.log(out.join('\n'));
    return;
  }

  if (!s.total) {
    out.push(`  ${c.green('✔ No secrets found.')} Your agents have clean hands. For now.`);
    out.push(c.gray('  Keep it that way: npx keyspill protect'));
    out.push('');
    console.log(out.join('\n'));
    return;
  }

  const head = ` ${s.total} secret${s.total === 1 ? '' : 's'} seen by your agents `;
  out.push(`  ${c.bgRed(head)}  ${c.red(s.critical + ' critical')} · ${c.yellow(s.high + ' high')} · ${c.gray(s.medium + ' medium')}`);
  out.push('');

  for (const sev of ['critical', 'high', 'medium']) {
    const group = findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    out.push(`  ${SEV[sev].name(sev.toUpperCase())}`);
    const limit = all ? group.length : sev === 'medium' ? 5 : 15;
    for (const f of group.slice(0, limit)) {
      const label = f.varName ? `${f.label} (${f.varName})` : f.label;
      out.push(`  ${SEV[sev].dot} ${c.bold(label.padEnd(30))} ${c.cyan(f.display)}`);
      const where = [
        `${f.count}×`,
        f.tools.join(', '),
        f.projects.length ? shortPath(f.projects[0]) + (f.projects.length > 1 ? ` +${f.projects.length - 1}` : '') : null,
        'last ' + fmtDate(f.lastSeen),
      ].filter(Boolean).join(' · ');
      out.push(c.gray(`      ${where}`));
      const o = originText(f.origins);
      if (o) out.push(c.gray(`      ${o}`));
      if (f.rotate && sev !== 'medium') out.push(`      ${c.magenta('→ rotate:')} ${c.gray(f.rotate)}`);
    }
    if (group.length > limit) out.push(c.gray(`      … and ${group.length - limit} more (use --all)`));
    out.push('');
  }

  out.push(c.bold('  What now'));
  out.push(`  1. Rotate every ${c.red('critical')} and ${c.yellow('high')} key above. Once it was in a session, it was sent to a model provider.`);
  out.push(`  2. Stop agents reading .env files:  ${c.cyan('npx keyspill protect')}`);
  out.push(`  3. Share your score (no secrets in it):  ${c.cyan('npx keyspill --card')}`);
  out.push('');
  console.log(out.join('\n'));
}

export function toJson({ findings, stats }) {
  return JSON.stringify({
    version: 1,
    summary: summarize(findings),
    stats,
    findings: findings.map((f) => ({
      rule: f.rule, label: f.label, severity: f.severity, masked: f.display, fingerprint: f.hash,
      variable: f.varName, count: f.count, tools: f.tools, projects: f.projects, files: f.files,
      origins: f.origins, firstSeen: fmtDate(f.firstSeen), lastSeen: fmtDate(f.lastSeen), rotate: f.rotate,
    })),
  }, null, 2);
}
