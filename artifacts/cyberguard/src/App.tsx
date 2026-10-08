import { useMemo, useState, type FormEvent } from 'react';
import {
  ArrowRight,
  Check,
  CheckCircle2,
  CircleAlert,
  Eye,
  EyeOff,
  Fingerprint,
  Globe2,
  Info,
  LockKeyhole,
  RotateCcw,
  Shield,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
} from 'lucide-react';

type RiskResult = {
  level: 'Low' | 'Moderate' | 'Elevated';
  className: 'low' | 'medium' | 'high';
  signals: string[];
};

const CHECKLIST = [
  { id: 'unique', title: 'Use a different password for every account', detail: 'A password manager can remember them for you.' },
  { id: 'mfa', title: 'Turn on two-step verification', detail: 'Start with your email and financial accounts.' },
  { id: 'recovery', title: 'Review account recovery options', detail: 'Make sure your phone number and backup email are current.' },
  { id: 'updates', title: 'Keep your devices up to date', detail: 'Enable automatic updates where you can.' },
  { id: 'lock', title: 'Set a screen lock on your devices', detail: 'Use a strong passcode, PIN, or biometric unlock.' },
  { id: 'backup', title: 'Back up important files', detail: 'Keep a copy somewhere separate from your device.' },
  { id: 'sessions', title: 'Review signed-in devices', detail: 'Sign out of devices you no longer recognize or use.' },
  { id: 'alerts', title: 'Enable sign-in alerts', detail: 'Let your accounts tell you when a new login happens.' },
];

function inspectLink(rawInput: string): RiskResult {
  const raw = rawInput.trim();
  const signals: string[] = [];
  let points = 0;
  let parsed: URL | null = null;
  try {
    parsed = new URL(/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(raw) ? raw : `https://${raw}`);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      signals.push('This is not a standard web link (HTTP or HTTPS).');
      points += 2;
    }
  } catch {
    return {
      level: 'Elevated',
      className: 'high',
      signals: ['The text does not look like a complete web address. Check for missing characters or extra spaces.'],
    };
  }

  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol === 'http:') {
    signals.push('The address uses HTTP, so the connection is not encrypted in transit.');
    points += 1;
  }
  if (parsed.username || parsed.password || raw.includes('@')) {
    signals.push('An @ symbol or embedded sign-in details can disguise which site the address opens.');
    points += 2;
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')) {
    signals.push('The destination is written as a numeric network address rather than a familiar domain name.');
    points += 2;
  }
  if (host.startsWith('xn--') || host.split('.').some((part) => part.startsWith('xn--'))) {
    signals.push('The domain contains an internationalized (punycode) label that can be hard to distinguish by eye.');
    points += 2;
  }
  const labels = host.split('.').filter(Boolean);
  if (labels.length >= 5) {
    signals.push(`The address has ${labels.length} domain sections, which can make the actual site name harder to spot.`);
    points += 1;
  }
  if (/(login|verify|secure|account|update|password|billing|wallet|gift|prize|urgent)/i.test(`${host}${parsed.pathname}`)) {
    signals.push('The address includes account, payment, or urgency-related words. These words alone do not establish intent.');
    points += 1;
  }
  if (/(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|shorturl\.at)$/i.test(host)) {
    signals.push('This appears to use a link-shortening domain, which hides the final destination.');
    points += 1;
  }
  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    signals.push(`The address uses a non-standard port (${parsed.port}).`);
    points += 1;
  }
  if (raw.length > 180) {
    signals.push('This is an unusually long address; long paths and parameters can make details harder to review.');
    points += 1;
  }
  if (signals.length === 0) {
    signals.push('No common string-level warning patterns were noticed in this address.');
    signals.push('A familiar-looking address can still be unsafe; check the sender and domain carefully.');
  }
  if (points >= 4) return { level: 'Elevated', className: 'high', signals };
  if (points >= 2) return { level: 'Moderate', className: 'medium', signals };
  return { level: 'Low', className: 'low', signals };
}

function evaluatePassword(value: string) {
  if (!value) return null;
  const checks = [
    { label: '12 or more characters', met: value.length >= 12 },
    { label: 'Upper and lowercase letters', met: /[a-z]/.test(value) && /[A-Z]/.test(value) },
    { label: 'At least one number', met: /\d/.test(value) },
    { label: 'At least one symbol', met: /[^A-Za-z0-9]/.test(value) },
    { label: 'Avoids common patterns', met: !/(1234|abcd|qwerty|password|letmein|.)\1{3,}/i.test(value) && !/password|qwerty|letmein|1234/i.test(value) },
  ];
  const metCount = checks.filter((item) => item.met).length;
  const longEnough = value.length >= 14;
  const label = metCount <= 2 ? 'Needs work' : metCount === 3 ? 'Getting there' : metCount === 4 && !longEnough ? 'Good start' : 'Strong pattern';
  const percent = Math.min(100, Math.round((metCount / checks.length) * 100));
  return { checks, label, percent };
}

function loadChecklist(): string[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem('cyberguard-checklist-v1') || '[]');
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string' && CHECKLIST.some((entry) => entry.id === item)) : [];
  } catch {
    return [];
  }
}

function App() {
  const [linkInput, setLinkInput] = useState('');
  const [linkResult, setLinkResult] = useState<RiskResult | null>(null);
  const [linkError, setLinkError] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [completed, setCompleted] = useState<string[]>(loadChecklist);
  const passwordResult = useMemo(() => evaluatePassword(password), [password]);
  const progress = Math.round((completed.length / CHECKLIST.length) * 100);

  function runLinkCheck(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!linkInput.trim()) {
      setLinkError('Paste or type an address to review.');
      setLinkResult(null);
      return;
    }
    setLinkError('');
    setLinkResult(inspectLink(linkInput));
  }

  function toggleChecklist(id: string) {
    setCompleted((current) => {
      const next = current.includes(id) ? current.filter((item) => item !== id) : [...current, id];
      try {
        localStorage.setItem('cyberguard-checklist-v1', JSON.stringify(next));
      } catch {
        // Checklist still works for this visit when browser storage is unavailable.
      }
      return next;
    });
  }

  function clearPassword() {
    setPassword('');
    setShowPassword(false);
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="CyberGuard home" data-testid="link-home">
          <span className="brand-mark"><Shield size={18} strokeWidth={2.2} /></span>
          CyberGuard
        </a>
        <div className="top-meta" data-testid="status-local-tools">
          <span className="online-dot" aria-hidden="true" />
          Private by design
        </div>
      </header>

      <main className="main-wrap">
        <section className="intro-row" aria-labelledby="page-title">
          <div>
            <div className="eyebrow">A little more sure of yourself online</div>
            <h1 className="page-title" id="page-title">Pause. Check. Carry on.</h1>
            <p className="intro-copy">Small, practical checks for the moments that matter. Review a link, get a feel for a password pattern, and make account safety a habit.</p>
          </div>
          <div className="privacy-chip" data-testid="text-privacy-promise"><Fingerprint size={16} /> Your checks stay on this device</div>
        </section>

        <div className="tool-grid">
          <section className="panel panel-link" aria-labelledby="link-heading">
            <div className="panel-head">
              <div>
                <div className="panel-kicker"><span className="panel-icon"><Globe2 size={17} /></span> Link check</div>
                <h2 className="panel-title" id="link-heading">Take a closer look</h2>
                <p className="panel-desc">A quick review of clues in the address itself. No destination is opened.</p>
              </div>
            </div>
            <form onSubmit={runLinkCheck} noValidate>
              <label className="field-label" htmlFor="link-input">Website address</label>
              <div className="input-wrap">
                <Globe2 size={16} aria-hidden="true" color="#83908a" />
                <input id="link-input" className="text-input" type="text" inputMode="url" autoComplete="url" placeholder="example.com/something" value={linkInput} onChange={(event) => { setLinkInput(event.target.value); setLinkError(''); }} aria-describedby={linkError ? 'link-error' : 'link-input-note'} data-testid="input-link" />
              </div>
              {linkError ? <p className="microcopy" id="link-error" role="alert" style={{ color: '#a25241', marginTop: 7 }}>{linkError}</p> : <p className="microcopy" id="link-input-note" style={{ marginTop: 7 }}>You can paste the full address, including https://</p>}
              <div className="link-form-actions">
                <span className="microcopy">Local text analysis only</span>
                <button className="primary-button" type="submit" data-testid="button-check-link">Review link <ArrowRight size={15} /></button>
              </div>
            </form>
            {linkResult && (
              <div className={`result-box ${linkResult.className}`} role="status" aria-live="polite" data-testid="status-link-result">
                <div className="result-top">
                  <div className={`risk-label ${linkResult.className}`}>
                    {linkResult.className === 'high' ? <TriangleAlert size={16} /> : linkResult.className === 'medium' ? <CircleAlert size={16} /> : <CheckCircle2 size={16} />}
                    {linkResult.level} signals
                  </div>
                  <span className="result-caption">Not a safety verdict</span>
                </div>
                <ul className="signal-list">
                  {linkResult.signals.map((signal, index) => <li key={`${signal}-${index}`} data-testid={`text-link-signal-${index}`}><Check size={14} />{signal}</li>)}
                </ul>
              </div>
            )}
          </section>

          <section className="panel panel-password" aria-labelledby="password-heading">
            <div className="panel-head">
              <div>
                <div className="panel-kicker"><span className="panel-icon"><LockKeyhole size={17} /></span> Password practice</div>
                <h2 className="panel-title" id="password-heading">Build a better passphrase</h2>
                <p className="panel-desc">See a few useful strength signals, privately and right here.</p>
              </div>
            </div>
            <label className="field-label" htmlFor="password-input">Try a password</label>
            <div className="input-wrap">
              <LockKeyhole size={16} aria-hidden="true" color="#83908a" />
              <input id="password-input" className="text-input" type={showPassword ? 'text' : 'password'} autoComplete="new-password" placeholder="Type something to assess" value={password} onChange={(event) => setPassword(event.target.value)} aria-describedby="password-note" data-testid="input-password" />
              <button type="button" className="icon-button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? 'Hide password' : 'Reveal password'} aria-pressed={showPassword} data-testid="button-toggle-password">
                {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
              <button type="button" className="icon-button" onClick={clearPassword} aria-label="Clear password" data-testid="button-clear-password"><RotateCcw size={16} /></button>
            </div>
            <p className="microcopy" id="password-note" style={{ marginTop: 8 }}>Never saved or sent. Avoid entering a password you already use.</p>
            {passwordResult ? (
              <div className="result-box" role="status" aria-live="polite" data-testid="status-password-result">
                <div className="result-top">
                  <div className="risk-label"><Sparkles size={15} />{passwordResult.label}</div>
                  <span className="result-caption" data-testid="text-password-progress">{passwordResult.percent}% signals</span>
                </div>
                <div style={{ height: 4, background: '#e2e8df', borderRadius: 6, marginTop: 12, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${passwordResult.percent}%`, background: '#5b9276', borderRadius: 6, transition: 'width .2s ease' }} />
                </div>
                <ul className="signal-list">
                  {passwordResult.checks.map((check, index) => <li key={check.label} data-testid={`text-password-signal-${index}`}><Check size={14} color={check.met ? '#648d75' : '#b8beb6'} />{check.label}{check.met ? ' — yes' : ' — try adding this'}</li>)}
                </ul>
              </div>
            ) : (
              <div className="privacy-footer" style={{ marginTop: 18 }} data-testid="text-password-empty"><Info size={15} /><span>Feedback appears as you type. This is a basic strength guide, <strong>not a breach check</strong>.</span></div>
            )}
          </section>

          <section className="panel panel-checklist" aria-labelledby="checklist-heading">
            <div className="panel-head">
              <div>
                <div className="panel-kicker"><span className="panel-icon"><ShieldCheck size={17} /></span> Steady habits</div>
                <h2 className="panel-title" id="checklist-heading">Your account-safety checklist</h2>
                <p className="panel-desc">A few useful basics, at your pace. Your progress is saved only in this browser.</p>
              </div>
              <div className="checklist-summary">
                <div className="progress-ring" style={{ ['--progress' as string]: `${progress}%` }} role="img" aria-label={`${progress}% complete`} data-testid="progress-checklist"><span>{progress}%</span></div>
                <span className="microcopy" data-testid="text-checklist-count">{completed.length} of {CHECKLIST.length}<br />complete</span>
              </div>
            </div>
            <div className="checklist-layout">
              <div className="check-list">
                {CHECKLIST.map((item) => {
                  const isDone = completed.includes(item.id);
                  return (
                    <label className={`check-item ${isDone ? 'done' : ''}`} key={item.id} htmlFor={`check-${item.id}`} data-testid={`item-checklist-${item.id}`}>
                      <input className="check-box" type="checkbox" id={`check-${item.id}`} checked={isDone} onChange={() => toggleChecklist(item.id)} data-testid={`input-checklist-${item.id}`} />
                      <span><span className="check-title">{item.title}</span><span className="check-detail">{item.detail}</span></span>
                    </label>
                  );
                })}
              </div>
              <aside className="check-aside">
                <div className="aside-label">A useful place to start</div>
                <h3 className="aside-title">Secure your email first.</h3>
                <p className="aside-copy">Your email can reset many other accounts. Use a unique password and turn on two-step verification there before moving on.</p>
                <div className="aside-rule" />
                <p className="aside-copy">No need to do everything today. Each checked item is one less thing to wonder about.</p>
              </aside>
            </div>
          </section>
        </div>

        <div className="privacy-footer" data-testid="text-privacy-details">
          <Fingerprint size={16} />
          <span><strong>Private by design.</strong> Link checks inspect only the text you enter and never visit or resolve a site. Password feedback runs in your browser and is cleared when you reset it. Checklist progress stays in this browser’s local storage. CyberGuard does not send your inputs anywhere.</span>
        </div>
        <footer className="footer-line">
          <span>CYBERGUARD · EVERYDAY SECURITY, WITHOUT THE DRAMA</span>
          <span>Useful signals. Your judgment.</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
