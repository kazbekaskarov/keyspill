// Where AI coding agents keep their local session history.
// Every path here is read-only for keyspill: we never modify, upload or copy these files.
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

export function getSources(home = os.homedir(), env = process.env) {
  const plat = process.platform;
  const appData = env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const xdgData = env.XDG_DATA_HOME || path.join(home, '.local', 'share');
  const xdgConfig = env.XDG_CONFIG_HOME || path.join(home, '.config');

  // VS Code–family editors (for Cline / Roo Code / Kilo Code task history, and Cursor's own DBs)
  const editorUserDir = (name) =>
    plat === 'darwin' ? path.join(home, 'Library', 'Application Support', name, 'User')
      : plat === 'win32' ? path.join(appData, name, 'User')
        : path.join(xdgConfig, name, 'User');

  const extensionTasks = [];
  for (const editor of ['Code', 'Code - Insiders', 'Cursor', 'Windsurf', 'VSCodium']) {
    for (const ext of ['saoudrizwan.claude-dev', 'rooveterinaryinc.roo-cline', 'kilocode.kilo-code']) {
      extensionTasks.push(path.join(editorUserDir(editor), 'globalStorage', ext));
    }
  }

  return [
    {
      id: 'claude-code', name: 'Claude Code',
      roots: [path.join(env.CLAUDE_CONFIG_DIR || path.join(home, '.claude'), 'projects')],
      match: (f) => f.endsWith('.jsonl'),
      projectFromPath: (f, root) => decodeClaudeDir(path.relative(root, f).split(path.sep)[0]),
    },
    {
      id: 'codex', name: 'Codex',
      roots: [path.join(env.CODEX_HOME || path.join(home, '.codex'), 'sessions'), path.join(env.CODEX_HOME || path.join(home, '.codex'), 'history.jsonl')],
      match: (f) => f.endsWith('.jsonl'),
    },
    {
      id: 'gemini', name: 'Gemini CLI',
      roots: [path.join(home, '.gemini', 'tmp')],
      match: (f) => f.endsWith('.json') || f.endsWith('.jsonl'),
    },
    {
      id: 'opencode', name: 'opencode',
      roots: [path.join(xdgData, 'opencode', 'storage'), path.join(xdgData, 'opencode', 'project')],
      match: (f) => f.endsWith('.json'),
    },
    {
      id: 'cursor', name: 'Cursor',
      roots: [
        path.join(editorUserDir('Cursor'), 'globalStorage', 'state.vscdb'),
        path.join(editorUserDir('Cursor'), 'workspaceStorage'),
        path.join(home, '.cursor', 'chats'),
      ],
      match: (f) => /\.(vscdb|db)$/.test(f),
      binary: true,
    },
    {
      id: 'copilot-cli', name: 'Copilot CLI',
      roots: [path.join(home, '.copilot', 'session-state'), path.join(home, '.copilot', 'history-session-state')],
      match: (f) => f.endsWith('.jsonl') || f.endsWith('.json'),
    },
    {
      id: 'cline', name: 'Cline / Roo / Kilo',
      roots: extensionTasks.map((p) => path.join(p, 'tasks')),
      match: (f) => /(api_conversation_history|ui_messages)\.json$/.test(f),
    },
  ];
}

// ~/.claude/projects/-Users-kaz-work-shop  ->  /Users/kaz/work/shop  (lossy: dashes in names are ambiguous)
// On Windows: C:\Users\kaz\work  ->  C--Users-kaz-work  ->  C:\Users\kaz\work
export function decodeClaudeDir(name) {
  if (!name) return '';
  const win = name.match(/^([A-Za-z])--(.*)$/);
  if (win) return `${win[1]}:\\${win[2].replace(/-/g, '\\')}`;
  if (!name.startsWith('-')) return name;
  return name.replace(/-/g, '/');
}

const SKIP_DIRS = new Set(['node_modules', '.git', 'Cache', 'CachedData', 'GPUCache', 'logs']);

export function* walk(root, match, maxDepth = 8) {
  let st;
  try { st = fs.statSync(root); } catch { return; }
  if (st.isFile()) { if (match(root)) yield { file: root, size: st.size, mtime: st.mtimeMs }; return; }
  const stack = [[root, 0]];
  while (stack.length) {
    const [dir, depth] = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth && !SKIP_DIRS.has(e.name)) stack.push([p, depth + 1]);
      } else if (e.isFile() && match(p)) {
        try { const s = fs.statSync(p); yield { file: p, size: s.size, mtime: s.mtimeMs }; } catch { /* vanished */ }
      }
    }
  }
}
