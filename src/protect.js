import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { c } from './report.js';

export const CLAUDE_DENY = [
  'Read(./.env)', 'Read(./.env.*)', 'Read(./**/.env)', 'Read(./**/.env.*)',
  'Read(./**/*.pem)', 'Read(./**/*.key)', 'Read(./**/secrets/**)',
  'Read(~/.aws/**)', 'Read(~/.ssh/**)', 'Read(~/.config/gcloud/**)',
];

export const CURSOR_IGNORE = ['.env', '.env.*', '*.pem', '*.key', 'secrets/'];

export function protect({ apply = false, home = os.homedir(), env = process.env, cwd = process.cwd() } = {}) {
  const settingsPath = path.join(env.CLAUDE_CONFIG_DIR || path.join(home, '.claude'), 'settings.json');
  const ignorePath = path.join(cwd, '.cursorignore');

  let settings = {};
  let settingsExists = false;
  try { settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8')); settingsExists = true; } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(c.red(`  Could not parse ${settingsPath}: ${e.message}. Not touching it.`));
      return 1;
    }
  }
  const deny = settings.permissions?.deny || [];
  const addDeny = CLAUDE_DENY.filter((r) => !deny.includes(r));

  let ignore = '';
  try { ignore = fs.readFileSync(ignorePath, 'utf8'); } catch { /* none yet */ }
  const ignoreLines = new Set(ignore.split(/\r?\n/).map((l) => l.trim()));
  const addIgnore = CURSOR_IGNORE.filter((l) => !ignoreLines.has(l));

  console.log('');
  console.log(`  ${c.bold('keyspill protect')} ${c.gray('· keep secrets out of future sessions')}`);
  console.log('');
  console.log(`  ${c.bold('Claude Code')} ${c.gray(settingsPath)}`);
  console.log(addDeny.length ? addDeny.map((r) => `    ${c.green('+')} permissions.deny ${r}`).join('\n') : c.gray('    already protected'));
  console.log(`  ${c.bold('Cursor')} ${c.gray(ignorePath)}`);
  console.log(addIgnore.length ? addIgnore.map((r) => `    ${c.green('+')} ${r}`).join('\n') : c.gray('    already protected'));
  console.log('');

  if (!apply) {
    console.log(`  Nothing changed yet. Run ${c.cyan('npx keyspill protect --apply')} to write these.`);
    console.log(c.gray('  Note: deny rules cover file reads, not shell commands like `cat .env`. Keep reviewing Bash prompts.'));
    console.log('');
    return 0;
  }

  if (addDeny.length) {
    if (settingsExists) fs.copyFileSync(settingsPath, settingsPath + `.keyspill-backup-${Date.now()}`);
    settings.permissions = settings.permissions || {};
    settings.permissions.deny = [...deny, ...addDeny];
    fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
  }
  if (addIgnore.length) {
    const sep = ignore && !ignore.endsWith('\n') ? '\n' : '';
    fs.writeFileSync(ignorePath, ignore + sep + '# added by keyspill\n' + addIgnore.join('\n') + '\n');
  }
  console.log(`  ${c.green('✔ Done.')} ${settingsExists && addDeny.length ? c.gray('A backup of your old settings.json sits next to it.') : ''}`);
  console.log(c.gray('  Deny rules cover file reads, not shell commands like `cat .env`. Keep reviewing Bash prompts.'));
  console.log('');
  return 0;
}
