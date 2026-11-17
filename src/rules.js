// Detection rules. Each rule: id, label, severity, regex (with one capture group = the secret),
// optional `prefix` (non-secret part safe to show), optional `rotate` URL, optional `check(value, match)`.
// Keep rules high-signal: a false positive in a security tool costs more trust than a miss.

const B = String.raw;

export const RULES = [
  // ---------- critical ----------
  {
    id: 'aws-access-key', label: 'AWS access key ID', severity: 'critical', prefix: 'AKIA',
    re: /\b(AKIA[A-Z0-9]{16})\b/g, rotate: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  },
  {
    id: 'aws-secret-key', label: 'AWS secret access key', severity: 'critical',
    re: /aws_?secret_?access_?key["'\s]*[:=]\s*["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    rotate: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  },
  {
    id: 'private-key', label: 'Private key (PEM)', severity: 'critical',
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:\s|\\[nr])*([A-Za-z0-9+/=]{40})/g,
    display: () => '-----BEGIN … PRIVATE KEY-----',
  },
  {
    id: 'stripe-live', label: 'Stripe live secret key', severity: 'critical',
    re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g, prefixFrom: /^(?:sk|rk)_live_/,
    rotate: 'https://dashboard.stripe.com/apikeys',
  },
  {
    id: 'db-url', label: 'Database URL with password', severity: 'critical',
    re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql):\/\/[^\s:@/"'`\\]+:[^\s:@/"'`\\]{3,}@[^\s"'`\\]+)/g,
    check: checkDbUrl,
    display: displayDbUrl,
    // The same credentials show up with different /db?options tails: one finding per user:pass@host.
    canonical: (v) => { const m = parseDbUrl(v); return m ? `${m.scheme}://${m.user}:${m.pass}@${m.host.toLowerCase()}` : v; },
    // The password alone, so a MONGODB_PASSWORD=... line with the same value is not reported twice.
    secretPart: (v) => parseDbUrl(v)?.pass ?? v,
  },

  // ---------- high ----------
  { id: 'aws-temp-key', label: 'AWS temporary key ID', severity: 'high', prefix: 'ASIA', re: /\b(ASIA[A-Z0-9]{16})\b/g },
  {
    id: 'github-token', label: 'GitHub token', severity: 'high',
    re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g,
    prefixFrom: /^(?:gh[pousr]_|github_pat_)/, rotate: 'https://github.com/settings/tokens',
  },
  { id: 'gitlab-token', label: 'GitLab token', severity: 'high', re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g, prefix: 'glpat-', rotate: 'https://gitlab.com/-/user_settings/personal_access_tokens' },
  {
    id: 'openai-key', label: 'OpenAI API key', severity: 'high',
    re: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b/g,
    prefixFrom: /^sk-(?:proj-|svcacct-|admin-)?/, rotate: 'https://platform.openai.com/api-keys',
  },
  { id: 'anthropic-key', label: 'Anthropic API key', severity: 'high', re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})/g, prefixFrom: /^sk-ant-(?:api|admin)\d{2}-/, rotate: 'https://console.anthropic.com/settings/keys' },
  { id: 'google-api-key', label: 'Google API key', severity: 'high', re: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g, prefix: 'AIza', rotate: 'https://console.cloud.google.com/apis/credentials' },
  { id: 'slack-token', label: 'Slack token', severity: 'high', re: /\b(xox[abposr]-[A-Za-z0-9-]{10,})\b/g, prefixFrom: /^xox[abposr]-/, rotate: 'https://api.slack.com/apps' },
  { id: 'slack-webhook', label: 'Slack webhook URL', severity: 'high', re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/g, prefix: 'https://hooks.slack.com/services/', rotate: 'https://api.slack.com/apps' },
  { id: 'telegram-bot', label: 'Telegram bot token', severity: 'high', re: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])/g, rotate: 'https://t.me/BotFather' },
  { id: 'discord-bot', label: 'Discord bot token', severity: 'high', re: /\b([MN][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38})\b/g, rotate: 'https://discord.com/developers/applications' },
  { id: 'sendgrid', label: 'SendGrid API key', severity: 'high', re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/g, prefix: 'SG.', rotate: 'https://app.sendgrid.com/settings/api_keys' },
  { id: 'twilio', label: 'Twilio API key', severity: 'high', re: /\b(SK[0-9a-f]{32})\b/g, prefix: 'SK', rotate: 'https://console.twilio.com/' },
  { id: 'npm-token', label: 'npm token', severity: 'high', re: /\b(npm_[A-Za-z0-9]{36})\b/g, prefix: 'npm_', rotate: 'https://www.npmjs.com/settings/~/tokens' },
  { id: 'pypi-token', label: 'PyPI token', severity: 'high', re: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})/g, prefix: 'pypi-', rotate: 'https://pypi.org/manage/account/token/' },
  { id: 'huggingface', label: 'Hugging Face token', severity: 'high', re: /\b(hf_[A-Za-z0-9]{34,})\b/g, prefix: 'hf_', rotate: 'https://huggingface.co/settings/tokens' },
  { id: 'shopify', label: 'Shopify token', severity: 'high', re: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g, prefixFrom: /^shp(?:at|ca|pa|ss)_/ },
  { id: 'digitalocean', label: 'DigitalOcean token', severity: 'high', re: /\b(do[por]_v1_[a-f0-9]{64})\b/g, prefixFrom: /^do[por]_v1_/, rotate: 'https://cloud.digitalocean.com/account/api/tokens' },
  { id: 'stripe-webhook', label: 'Stripe webhook secret', severity: 'high', re: /\b(whsec_[A-Za-z0-9]{32,})\b/g, prefix: 'whsec_', rotate: 'https://dashboard.stripe.com/webhooks' },
  { id: 'groq', label: 'Groq API key', severity: 'high', re: /\b(gsk_[A-Za-z0-9]{50,})\b/g, prefix: 'gsk_', rotate: 'https://console.groq.com/keys' },
  { id: 'replicate', label: 'Replicate token', severity: 'high', re: /\b(r8_[A-Za-z0-9]{37})\b/g, prefix: 'r8_', rotate: 'https://replicate.com/account/api-tokens' },
  { id: 'supabase-pat', label: 'Supabase access token', severity: 'high', re: /\b(sbp_[a-f0-9]{40})\b/g, prefix: 'sbp_', rotate: 'https://supabase.com/dashboard/account/tokens' },
  { id: 'mailgun', label: 'Mailgun API key', severity: 'high', re: /\b(key-[a-f0-9]{32})\b/g, prefix: 'key-' },

  // ---------- JWT (special-cased: Supabase service_role is critical, anon keys are public) ----------
  {
    id: 'jwt', label: 'JWT', severity: 'medium',
    re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,})\b/g,
    check: checkJwt,
  },

  // ---------- medium ----------
  { id: 'stripe-test', label: 'Stripe test key', severity: 'medium', re: /\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b/g, prefixFrom: /^(?:sk|rk)_test_/ },
  {
    id: 'env-secret', label: 'Secret in env/config', severity: 'medium', generic: true,
    re: new RegExp(B`(?<![A-Za-z0-9_])([A-Z][A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|AUTH_?KEY)[A-Z0-9_]*)["']?([ \t]*[=:][ \t]*)(["']?)([^\s"'\x60\\,;)]{8,})`, 'g'),
    group: 4, nameGroup: 1, check: checkGeneric,
  },
];

const PLACEHOLDER = /(example|sample|dummy|placeholder|your[_-]|changeme|change_me|xxxx|\*\*\*|redacted|<|>|\$\{|\{\{|%s|replace|insert|todo|fake|lorem|\.\.\.|•)/i;

export function looksPlaceholder(v) {
  if (PLACEHOLDER.test(v)) return true;
  if (/^(.)\1+$/.test(v)) return true; // aaaaaaa
  if (/^(?:0123456789|1234567890|abcdef)/i.test(v)) return true;
  return false;
}

export function entropy(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  let e = 0;
  for (const k in f) { const p = f[k] / s.length; e -= p * Math.log2(p); }
  return e;
}

function checkGeneric(value, m) {
  const name = m[1];
  if (/PUBLIC|PUBLISHABLE|_URL$|_PATH$|_FILE$|_NAME$|_ID$|_LENGTH$|_TTL$|_EXPIRES?|_TYPE$|_HEADER$|_FIELD$|_MAX|_MIN|COUNT|SIZE|PORT$|^NEXT_PUBLIC|^VITE_|^REACT_APP_/.test(name)) return false;
  if (looksPlaceholder(value)) return false;
  if (/[(){}[\]]/.test(value)) return false; // code expression
  if (/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value)) return false; // dotted identifier: token.ERRORTOKEN
  if (/key|token|secret|pass|auth/i.test(value)) return false; // a label, not a secret
  const spaced = /\s/.test(m[2]);
  const quoted = !!m[3];
  // `NAME = expr` without quotes is code. Allow it only for strongly random values (YAML / compose files).
  if (spaced && !quoted && !(value.length >= 16 && entropy(value) >= 3.5 && /\d/.test(value) && /[A-Za-z]/.test(value))) return false;
  if (/^(?:process\.|os\.|import\.|env\.|getenv|true|false|null|undefined|none|required|optional|string|number)/i.test(value)) return false;
  if (/^[a-z]+(?:[A-Z][a-z]+)+$/.test(value)) return false; // camelCase identifier
  if (/^[a-z_]+$/.test(value) || /^[A-Z_]+$/.test(value)) return false; // plain word / CONSTANT
  if (/^\d+$/.test(value)) return false;
  if (/^(?:https?:)?\/\//.test(value) || value.includes('/')) return false;
  if (entropy(value) < 3.0) return false;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
  return classes >= 2;
}

const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|db|postgres|mysql|mongo|mongodb|redis|rabbitmq|database)(:\d+)?$/i;
const DEFAULT_PASSWORDS = /^(password|pass|postgres|root|admin|secret|mysql|guest|test|example|changeme|redis|mongo|user|dev|local)$/i;

const PLACEHOLDER_WORDS = /^(user|username|usr|login|host|hostname|server|cluster|db|dbname|database|name|pass|password|pwd|passwd|secret|db_?user|db_?password|db_?pass|my_?user|my_?password)$/i;

function parseDbUrl(value) {
  const m = value.match(/^([^:]+):\/\/([^:]+):([^@]+)@([^/?#]+)/);
  return m ? { scheme: m[1], user: m[2], pass: m[3], host: m[4] } : null;
}

function checkDbUrl(value) {
  const m = parseDbUrl(value);
  if (!m) return false;
  const { user, pass, host } = m;
  const hostname = host.replace(/:\d+$/, '');
  if (looksPlaceholder(pass) || looksPlaceholder(host) || looksPlaceholder(user)) return false;
  if (/^\$|^%|^\{/.test(pass)) return false;
  // Docs and READMEs: mongodb+srv://USER:PASSWORD@HOST, or the same in another language.
  if (PLACEHOLDER_WORDS.test(pass) || PLACEHOLDER_WORDS.test(hostname) || PLACEHOLDER_WORDS.test(user)) return false;
  if (/[^\x00-\x7F]/.test(user + host)) return false; // real hostnames are ASCII (punycode)
  if (LOCAL_HOSTS.test(host) && DEFAULT_PASSWORDS.test(pass)) return false;
  if (LOCAL_HOSTS.test(host)) return { severity: 'medium', label: 'Local database password' };
  if (!hostname.includes('.') && !/^\d/.test(hostname)) return false; // single-word host that isn't local: a placeholder
  return true;
}

function displayDbUrl(value) {
  const m = parseDbUrl(value);
  if (!m) return maskTail(value);
  return `${m.scheme}://${m.user}:${'•'.repeat(6)}${m.pass.length >= 16 ? m.pass.slice(-2) : ''}@${m.host}`;
}

function checkJwt(value) {
  try {
    const payload = JSON.parse(Buffer.from(value.split('.')[1], 'base64url').toString('utf8'));
    if (payload.role === 'anon') return false; // Supabase anon key: public by design
    if (payload.role === 'service_role') return { severity: 'critical', label: 'Supabase service_role key', rotate: 'https://supabase.com/dashboard/project/_/settings/api' };
    // Only report tokens that are still usable. Expired or never-expiring sample tokens are noise.
    if (typeof payload.exp === 'number' && payload.exp * 1000 > Date.now()) return { label: 'Unexpired JWT' };
    return false;
  } catch {
    return false;
  }
}

export function maskTail(v, prefix = '') {
  const rest = v.slice(prefix.length);
  const tail = rest.length >= 20 ? 4 : rest.length >= 12 ? 2 : 0;
  return prefix + '•'.repeat(8) + (tail ? rest.slice(-tail) : '');
}

export function displayFor(rule, value) {
  if (rule.display) return rule.display(value);
  let prefix = rule.prefix && value.startsWith(rule.prefix) ? rule.prefix : '';
  if (rule.prefixFrom) prefix = (value.match(rule.prefixFrom) || [''])[0];
  return maskTail(value, prefix);
}
