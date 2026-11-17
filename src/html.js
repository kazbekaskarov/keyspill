// Self-contained HTML report. No external requests (no fonts, no CDN, no analytics):
// a security report must not phone home. Secrets only ever appear masked.
import { summarize } from './scan.js';
import { fmtDate, fmtBytes, shortPath } from './report.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

const COLORS = { paper: '#E4E7EB', ink: '#121417', tag: '#FFCF33', red: '#C8102E', amber: '#B86E00', slate: '#6B7280' };

function cardSvg(s, findings, stats) {
  const top = findings.filter((f) => f.severity !== 'medium').slice(0, 4);
  const tools = Object.keys(stats.byTool).join(' + ') || 'my agents';
  const rows = top.map((f, i) => {
    const y = 352 + i * 50;
    const w = 150 + ((f.hash.charCodeAt(0) * 7 + i * 31) % 160);
    const col = f.severity === 'critical' ? COLORS.red : COLORS.amber;
    return `<rect x="96" y="${y - 22}" width="10" height="30" fill="${col}"/>
      <text x="124" y="${y}" font-size="26" font-weight="600" fill="${COLORS.ink}">${esc(f.label)}</text>
      <rect x="${560}" y="${y - 22}" width="${w}" height="30" fill="${COLORS.ink}"/>`;
  }).join('');
  const big = s.total;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630" font-family="Helvetica Neue, Arial, sans-serif" role="img" aria-label="${big} secrets seen by my AI agents">
  <rect width="1200" height="630" fill="${COLORS.paper}"/>
  <g transform="rotate(-2 600 315)">
    <rect x="60" y="52" width="1080" height="530" rx="18" fill="${COLORS.tag}"/>
    <circle cx="1080" cy="112" r="22" fill="${COLORS.paper}"/>
    <circle cx="1080" cy="112" r="22" fill="none" stroke="${COLORS.ink}" stroke-width="3"/>
    <text x="96" y="122" font-size="28" font-weight="700" fill="${COLORS.ink}" letter-spacing="1">EVIDENCE</text>
    <text x="96" y="152" font-size="22" fill="${COLORS.ink}" opacity=".7">${esc(tools)} · ${fmtDate(Date.now())}</text>
    <text x="90" y="300" font-size="168" font-weight="800" fill="${COLORS.ink}" letter-spacing="-6">${big}</text>
    <text x="${120 + String(big).length * 92}" y="232" font-size="40" font-weight="700" fill="${COLORS.ink}">secret${big === 1 ? '' : 's'} my AI</text>
    <text x="${120 + String(big).length * 92}" y="282" font-size="40" font-weight="700" fill="${COLORS.ink}">agents have already seen</text>
    ${rows}
    <text x="96" y="572" font-size="24" fill="${COLORS.ink}"><tspan font-weight="700" fill="${COLORS.red}">${s.critical} critical</tspan> · ${s.high} high · ${s.medium} medium</text>
    <text x="1104" y="572" font-size="24" font-weight="700" text-anchor="end" fill="${COLORS.ink}">npx keyspill</text>
  </g>
</svg>`;
}

export function renderHtml({ findings, stats }) {
  const s = summarize(findings);
  const svg = cardSvg(s, findings, stats);
  const rows = findings.map((f) => `
    <li class="row sev-${f.severity}">
      <span class="sev">${f.severity}</span>
      <div class="what">
        <strong>${esc(f.label)}${f.varName ? ` <em>${esc(f.varName)}</em>` : ''}</strong>
        <code>${esc(f.display)}</code>
      </div>
      <div class="where">
        <span>${f.count}× in ${esc(f.tools.join(', '))}</span>
        ${f.projects.length ? `<span>${esc(shortPath(f.projects[0]))}${f.projects.length > 1 ? ` and ${f.projects.length - 1} more` : ''}</span>` : ''}
        <span>Last seen ${fmtDate(f.lastSeen)}</span>
        ${originLine(f.origins)}
      </div>
      ${f.rotate ? `<a class="rotate" href="${esc(f.rotate)}" target="_blank" rel="noreferrer">Rotate key</a>` : '<span></span>'}
    </li>`).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>keyspill report: ${s.total} secrets</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%23121417'/%3E%3Cg transform='translate(32 32) scale(.74) translate(-32 -32.75)'%3E%3Cpath d='M32 4C32 4 11 28 11 40.5a21 21 0 0 0 42 0C53 28 32 4 32 4Z' fill='%23FFCF33'/%3E%3Ccircle cx='32' cy='37' r='5.5' fill='%23121417'/%3E%3Cpath d='M29 40h6l2.5 11h-11Z' fill='%23121417'/%3E%3C/g%3E%3C/svg%3E">
<style>
:root{--paper:${COLORS.paper};--ink:${COLORS.ink};--tag:${COLORS.tag};--red:${COLORS.red};--amber:${COLORS.amber};--slate:${COLORS.slate}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 "Helvetica Neue",Arial,system-ui,sans-serif}
main{max-width:1040px;margin:0 auto;padding:48px 24px 96px}
h1{font-size:clamp(32px,5vw,52px);line-height:1.05;letter-spacing:-.02em;margin:0 0 8px;font-weight:800;max-width:18ch}
.lede{color:var(--slate);margin:0 0 32px;max-width:62ch}
.card{background:#fff;border:2px solid var(--ink);padding:12px;margin:0 0 12px}
.card svg{display:block;width:100%;height:auto}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 56px;align-items:center}
button,.rotate{font:inherit;font-weight:700;border:2px solid var(--ink);background:var(--tag);color:var(--ink);padding:10px 16px;cursor:pointer;text-decoration:none}
button:focus-visible,.rotate:focus-visible{outline:3px solid var(--red);outline-offset:2px}
.actions small{color:var(--slate)}
h2{font-size:24px;margin:0 0 4px}
.sub{color:var(--slate);margin:0 0 20px}
ol{list-style:none;margin:0;padding:0;border-top:2px solid var(--ink)}
.row{display:grid;grid-template-columns:96px minmax(0,1.2fr) minmax(0,1.4fr) auto;gap:16px;align-items:start;padding:16px 0;border-bottom:1px solid #c5cad1}
.sev{font-weight:700;padding-left:10px;border-left:6px solid var(--slate)}
.sev-critical .sev{border-color:var(--red);color:var(--red)}
.sev-high .sev{border-color:var(--amber);color:var(--amber)}
.what strong{display:block}.what em{font-style:normal;color:var(--slate);font-weight:400}
code{font:14px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--ink);color:var(--paper);padding:2px 6px;display:inline-block;margin-top:4px;word-break:break-all}
.where{color:var(--slate);font-size:14px;display:flex;flex-direction:column}
.rotate{background:#fff;font-size:14px;padding:6px 12px}
.fix{margin-top:56px;border:2px solid var(--ink);background:#fff;padding:24px}
.fix pre{background:var(--ink);color:var(--paper);padding:12px 16px;overflow:auto}
footer{margin-top:40px;color:var(--slate);font-size:14px}
@media (max-width:720px){.row{grid-template-columns:1fr}.rotate{justify-self:start}}
</style></head>
<body><main>
<h1>Your AI agents have seen ${s.total} secret${s.total === 1 ? '' : 's'}.</h1>
<p class="lede">Found in ${stats.files.toLocaleString()} local session files (${fmtBytes(stats.bytes)}) from ${esc(Object.keys(stats.byTool).join(', ') || 'no agents')}. Everything in a session was sent to a model provider, so treat these keys as exposed. This report never left your machine, and every value below is masked.</p>

<div class="card" id="card">${svg}</div>
<div class="actions">
  <button type="button" id="dl">Download share card</button>
  <small>The card has counts and key types only, never values.</small>
</div>

<h2>Evidence</h2>
<p class="sub">${s.critical} critical, ${s.high} high, ${s.medium} medium. Rotate critical and high first.</p>
<ol>${rows || '<li class="row"><span></span><div>Nothing found. Your agents have clean hands.</div></li>'}</ol>

<section class="fix">
  <h2>Stop it happening again</h2>
  <p>Block agents from reading env files and keys. This adds deny rules to Claude Code and a <code>.cursorignore</code> to the current project:</p>
  <pre>npx keyspill protect --apply</pre>
</section>
<footer>Generated by keyspill on ${new Date().toISOString().slice(0, 16).replace('T', ' ')}. Open source, 100% local.</footer>
</main>
<script>
document.getElementById('dl').addEventListener('click', function () {
  var svg = document.querySelector('#card svg');
  var data = new XMLSerializer().serializeToString(svg);
  var img = new Image();
  img.onload = function () {
    var cv = document.createElement('canvas'); cv.width = 2400; cv.height = 1260;
    var g = cv.getContext('2d'); g.drawImage(img, 0, 0, 2400, 1260);
    var a = document.createElement('a'); a.download = 'keyspill-card.png'; a.href = cv.toDataURL('image/png'); a.click();
  };
  img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(data);
});
</script>
</body></html>`;
}

function originLine(o) {
  const parts = [];
  if (o.tool) parts.push(`agent read it ${o.tool}×`);
  if (o.user) parts.push(`you pasted it ${o.user}×`);
  if (o.assistant) parts.push(`agent wrote it ${o.assistant}×`);
  return parts.length ? `<span>${parts.join(', ')}</span>` : '';
}
