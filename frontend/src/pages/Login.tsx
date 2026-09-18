import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, API_URL } from '../api';

interface PublicBranding {
  platform_name: string;
  tagline: string;
  logo_url: string | null;
  primary_color: string;
  accent_color: string;
  support_email: string | null;
  docs_url: string | null;
  password_min_length: number;
  password_require_uppercase: boolean;
  password_require_number: boolean;
  password_require_special: boolean;
  sso_enabled: boolean;
  sso_provider_name: string;
}

/* ─── Feature cards data ─────────────────────────────────────────────────── */
const FEATURES = [
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-5 h-5">
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
      </svg>
    ),
    title: 'Zero-Trust Query Gateway',
    desc: 'Every query is intercepted, validated, and rewritten before reaching your databases.',
    color: '#38BDF8',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-5 h-5">
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88"/>
      </svg>
    ),
    title: 'Dynamic Column Masking',
    desc: 'PII auto-detected and masked by role — admin sees raw, analyst sees redacted.',
    color: '#818CF8',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-5 h-5">
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/>
      </svg>
    ),
    title: 'AES Tokenization Vault',
    desc: 'Sensitive values replaced with reversible tokens. Only admins can detokenize.',
    color: '#A855F7',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-5 h-5">
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5M9 11.25v1.5M12 9v3.75m3-6.75v6.75"/>
      </svg>
    ),
    title: 'Universal Data Catalog',
    desc: '26+ connectors — scan, classify, and govern every database in one platform.',
    color: '#34D399',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-5 h-5">
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z"/>
      </svg>
    ),
    title: 'Immutable Audit Trail',
    desc: 'Every access, rewrite, and policy change logged — exportable for compliance.',
    color: '#FB923C',
  },
  {
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-5 h-5">
        <path strokeLinecap="round" strokeLinejoin="round"
          d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"/>
      </svg>
    ),
    title: 'AI Risk Scoring',
    desc: 'Queries scored in real-time — CRITICAL risk gates require admin approval.',
    color: '#F472B6',
  },
];

const SLOGANS = [
  'See Everything. Govern Everything.',
  'Intelligence at the Edge of Your Data.',
  'Trust Through Transparency.',
];

/* ─── Decorative animated blobs ─────────────────────────────────────────── */
const BlobBg = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none">
    {/* Top-left blob */}
    <div style={{
      position: 'absolute', top: '-15%', left: '-10%',
      width: 480, height: 480, borderRadius: '50%',
      background: 'radial-gradient(circle, rgba(56,189,248,0.12) 0%, transparent 70%)',
      animation: 'pulse 6s ease-in-out infinite',
    }}/>
    {/* Center blob */}
    <div style={{
      position: 'absolute', top: '30%', left: '20%',
      width: 600, height: 600, borderRadius: '50%',
      background: 'radial-gradient(circle, rgba(129,140,248,0.08) 0%, transparent 70%)',
      animation: 'pulse 8s ease-in-out infinite 2s',
    }}/>
    {/* Bottom-right blob */}
    <div style={{
      position: 'absolute', bottom: '-20%', right: '-5%',
      width: 500, height: 500, borderRadius: '50%',
      background: 'radial-gradient(circle, rgba(168,85,247,0.1) 0%, transparent 70%)',
      animation: 'pulse 7s ease-in-out infinite 1s',
    }}/>
    {/* Grid lines */}
    <svg width="100%" height="100%" style={{ opacity: 0.03 }}>
      <defs>
        <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
          <path d="M 40 0 L 0 0 0 40" fill="none" stroke="white" strokeWidth="0.5"/>
        </pattern>
      </defs>
      <rect width="100%" height="100%" fill="url(#grid)"/>
    </svg>
  </div>
);

/* ─── Component ──────────────────────────────────────────────────────────── */
export function Login() {
  const [email, setEmail]             = useState('');
  const [password, setPassword]       = useState('');
  const [error, setError]             = useState('');
  const [loading, setLoading]         = useState(false);
  const [sloganIdx]                   = useState(() => Math.floor(Math.random() * SLOGANS.length));
  const [branding, setBranding]       = useState<PublicBranding | null>(null);
  const navigate = useNavigate();

  // Fetch public branding/config on mount (unauthenticated endpoint)
  useEffect(() => {
    api.get('/settings/public?tenant_id=1')
      .then(r => setBranding(r.data as PublicBranding))
      .catch(() => { /* silently use defaults */ });
  }, []);

  const platformName = branding?.platform_name ?? 'MetaSight';
  const tagline      = branding?.tagline      ?? 'Database Governance Platform';

  // ── First-run setup ────────────────────────────────────────────────────
  // MetaSight has no public self-registration — users are provisioned by an
  // admin (POST /users, admin-only) after the very first tenant+admin exists.
  // That first account normally comes from a curl against POST /auth/setup
  // (see README/DEPLOYMENT.md); this screen wraps the same call so a fresh,
  // unconfigured install has something to click instead of a terminal.
  // /auth/setup-status is public/unauthenticated and only ever returns a
  // boolean — it self-disables (mirroring POST /auth/setup) the moment any
  // user exists, so this whole screen only ever appears once, on the very
  // first visit to a fresh database.
  const [needsSetup, setNeedsSetup]   = useState<boolean | null>(null); // null = still checking
  const [setupSecret, setSetupSecret] = useState('');
  const [confirmPw, setConfirmPw]     = useState('');
  const [setupError, setSetupError]   = useState('');
  const [setupLoading, setSetupLoading] = useState(false);

  useEffect(() => {
    api.get('/auth/setup-status')
      .then(r => setNeedsSetup(!!r.data?.needs_setup))
      .catch(() => setNeedsSetup(false)); // fail closed to the ordinary login form
  }, []);

  const handleSetupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSetupError('');
    if (password !== confirmPw) {
      setSetupError('Passwords do not match.');
      return;
    }
    setSetupLoading(true);
    try {
      await api.post(
        '/auth/setup',
        { admin_email: email, admin_password: password },
        { headers: { 'X-Setup-Secret': setupSecret } },
      );
      // Bootstrap created the account — log straight in rather than making
      // someone re-type the password they just chose.
      const formData = new URLSearchParams();
      formData.append('username', email);
      formData.append('password', password);
      const res = await api.post('/auth/login', formData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      localStorage.setItem('token', res.data.access_token);
      navigate('/');
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      setSetupError(
        Array.isArray(detail) ? (detail[0]?.msg || 'Setup failed.') : (detail || 'Setup failed.')
      );
    } finally {
      setSetupLoading(false);
    }
  };

  // ── MFA (TOTP) second step ─────────────────────────────────────────────
  // /auth/login returns { mfa_required: true, mfa_token } instead of a real
  // access_token when the account has MFA enabled — this screen collects
  // the 6-digit code and exchanges both for a real token via /auth/mfa/challenge.
  const [mfaToken, setMfaToken]   = useState<string | null>(null);
  const [mfaCode, setMfaCode]     = useState('');
  const [mfaError, setMfaError]   = useState('');
  const [mfaLoading, setMfaLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const formData = new URLSearchParams();
      formData.append('username', email);
      formData.append('password', password);
      const res = await api.post('/auth/login', formData, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      if (res.data.mfa_required) {
        setMfaToken(res.data.mfa_token);
        return;
      }
      localStorage.setItem('token', res.data.access_token);
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMfaError('');
    setMfaLoading(true);
    try {
      const res = await api.post('/auth/mfa/challenge', { mfa_token: mfaToken, code: mfaCode });
      localStorage.setItem('token', res.data.access_token);
      navigate('/');
    } catch (err: any) {
      setMfaError(err.response?.data?.detail || 'Invalid code. Please try again.');
    } finally {
      setMfaLoading(false);
    }
  };

  return (
    <>
      {/* ── Global keyframes injected once ────────────────────────── */}
      <style>{`
        @keyframes pulse {
          0%, 100% { transform: scale(1);   opacity: 1; }
          50%       { transform: scale(1.1); opacity: 0.7; }
        }
        @keyframes fadeSlideUp {
          from { opacity: 0; transform: translateY(16px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes shimmer {
          0%   { background-position: -200% center; }
          100% { background-position:  200% center; }
        }
        .feature-card:hover { transform: translateY(-2px); box-shadow: 0 8px 32px rgba(0,0,0,0.35); }
        .feature-card { transition: transform 0.2s ease, box-shadow 0.2s ease; }
      `}</style>

      <div className="min-h-screen flex" style={{ background: '#070D1A' }}>

        {/* ════════════════════════════════════════════════════════════
            LEFT PANEL — Brand / Marketing
        ════════════════════════════════════════════════════════════ */}
        <div
          className="hidden lg:flex flex-col justify-between w-[55%] relative px-14 py-12"
          style={{ background: 'linear-gradient(135deg, #0B1120 0%, #0D1428 60%, #100B24 100%)' }}
        >
          <BlobBg />

          {/* Top — Logo + wordmark */}
          <div style={{ animation: 'fadeSlideUp 0.6s ease forwards', position: 'relative', zIndex: 1 }}>
            <div className="flex items-center gap-4 mb-10">
              <img src="/metasight-logo.svg" alt="MetaSight" className="w-16 h-auto"/>
              <div>
                <div
                  className="text-2xl font-extrabold tracking-tight"
                  style={{
                    background: 'linear-gradient(90deg,#38BDF8,#818CF8,#A855F7)',
                    WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
                  }}
                >{platformName}</div>
                <div className="text-[9px] font-semibold tracking-[0.2em] text-slate-500 uppercase">
                  {tagline}
                </div>
              </div>
            </div>

            {/* Hero slogan */}
            <h1 className="text-4xl xl:text-5xl font-black leading-tight text-white mb-3">
              {SLOGANS[sloganIdx].split('.').map((part, i) => (
                part.trim() ? (
                  <span key={i}>
                    {i === 0 ? (
                      <span style={{
                        background: 'linear-gradient(90deg,#38BDF8 0%,#818CF8 60%,#A855F7 100%)',
                        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
                        backgroundSize: '200% auto', animation: 'shimmer 4s linear infinite',
                      }}>
                        {part.trim()}
                      </span>
                    ) : (
                      <span className="text-white"> {part.trim()}</span>
                    )}
                    {i < SLOGANS[sloganIdx].split('.').length - 2 ? '.' : ''}
                  </span>
                ) : null
              ))}
            </h1>
            <p className="text-slate-400 text-base mb-10 max-w-md leading-relaxed">
              The enterprise-grade gateway that secures every query, masks every secret,
              and creates a complete audit trail across all your data sources.
            </p>

            {/* Stats strip */}
            <div className="flex gap-8 mb-12">
              {[
                { val: '26+', label: 'Connectors' },
                { val: '100%', label: 'Query Coverage' },
                { val: 'AES-256', label: 'Encryption' },
                { val: 'Real-time', label: 'Risk Scoring' },
              ].map(s => (
                <div key={s.label}>
                  <div
                    className="text-2xl font-black"
                    style={{
                      background: 'linear-gradient(90deg,#38BDF8,#818CF8)',
                      WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
                    }}
                  >{s.val}</div>
                  <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">{s.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Middle — Feature grid */}
          <div
            className="grid grid-cols-2 gap-3 relative"
            style={{ zIndex: 1, animation: 'fadeSlideUp 0.7s ease 0.15s both' }}
          >
            {FEATURES.map((f) => (
              <div
                key={f.title}
                className="feature-card rounded-xl p-4 flex gap-3"
                style={{
                  background: 'rgba(255,255,255,0.03)',
                  border: `1px solid ${f.color}22`,
                  boxShadow: `0 2px 12px rgba(0,0,0,0.2), inset 0 1px 0 ${f.color}10`,
                }}
              >
                {/* Icon circle */}
                <div
                  className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center"
                  style={{ background: `${f.color}18`, color: f.color }}
                >
                  {f.icon}
                </div>
                <div>
                  <div className="text-xs font-bold text-white mb-0.5">{f.title}</div>
                  <div className="text-[10px] text-slate-500 leading-relaxed">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Bottom — Compliance badges */}
          <div className="flex items-center gap-4 mt-8 relative" style={{ zIndex: 1 }}>
            {['SOC 2 Ready', 'GDPR Compliant', 'HIPAA Aware', 'ISO 27001'].map(badge => (
              <div
                key={badge}
                className="px-3 py-1 rounded-full text-[9px] font-bold uppercase tracking-widest"
                style={{
                  background: 'rgba(129,140,248,0.08)',
                  border: '1px solid rgba(129,140,248,0.2)',
                  color: '#818CF8',
                }}
              >{badge}</div>
            ))}
          </div>
        </div>

        {/* ════════════════════════════════════════════════════════════
            RIGHT PANEL — Login form
        ════════════════════════════════════════════════════════════ */}
        <div
          className="flex-1 flex flex-col justify-center items-center px-6 py-12 relative"
          style={{ background: '#070D1A' }}
        >
          {/* Subtle right-panel glow */}
          <div style={{
            position: 'absolute', top: '50%', left: '50%',
            transform: 'translate(-50%,-50%)',
            width: 400, height: 400, borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(129,140,248,0.05) 0%, transparent 70%)',
            pointerEvents: 'none',
          }}/>

          <div
            className="w-full max-w-sm"
            style={{ animation: 'fadeSlideUp 0.5s ease forwards', position: 'relative', zIndex: 1 }}
          >
            {/* Mobile-only logo */}
            <div className="flex flex-col items-center mb-8 lg:hidden">
              <img src="/metasight-logo.svg" alt="MetaSight" className="w-20 h-auto mb-3"/>
              <div
                className="text-2xl font-extrabold"
                style={{
                  background: 'linear-gradient(90deg,#38BDF8,#818CF8,#A855F7)',
                  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
                }}
              >{platformName}</div>
              <p className="text-[9px] text-slate-500 uppercase tracking-widest mt-0.5">{tagline}</p>
            </div>

            {/* Form heading */}
            <div className="mb-8">
              {mfaToken ? (
                <>
                  <h2 className="text-2xl font-bold text-white mb-1">Two-factor authentication</h2>
                  <p className="text-sm text-slate-500">Enter the 6-digit code from your authenticator app</p>
                </>
              ) : needsSetup ? (
                <>
                  <h2 className="text-2xl font-bold text-white mb-1">Create your first admin</h2>
                  <p className="text-sm text-slate-500">
                    No account exists yet — set up {platformName} to get started.
                  </p>
                </>
              ) : (
                <>
                  <h2 className="text-2xl font-bold text-white mb-1">Welcome back</h2>
                  <p className="text-sm text-slate-500">Sign in to your {platformName} workspace</p>
                </>
              )}
            </div>

            {/* Card */}
            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(129,140,248,0.15)',
                boxShadow: '0 30px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.03)',
                backdropFilter: 'blur(20px)',
              }}
            >
              {/* Top gradient stripe */}
              <div className="h-[2px]" style={{ background: 'linear-gradient(90deg,#38BDF8,#818CF8,#A855F7)' }}/>

              {mfaToken ? (
                <form className="px-8 py-8 space-y-5" onSubmit={handleMfaSubmit}>
                  {mfaError && (
                    <div
                      className="px-4 py-3 rounded-lg text-sm text-red-300 flex items-start gap-2"
                      style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}
                    >
                      <svg className="w-4 h-4 flex-shrink-0 mt-0.5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd"/>
                      </svg>
                      {mfaError}
                    </div>
                  )}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest mb-2">
                      Authentication code
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      required
                      autoFocus
                      maxLength={6}
                      value={mfaCode}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                      placeholder="000000"
                      className="w-full px-4 py-2.5 rounded-lg text-center text-lg tracking-[0.5em] text-white placeholder-slate-600 outline-none transition-all duration-200"
                      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={mfaLoading || mfaCode.length !== 6}
                    className="w-full py-3 px-4 rounded-lg text-sm font-bold text-white transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{
                      background: 'linear-gradient(135deg, #38BDF8 0%, #818CF8 50%, #A855F7 100%)',
                      boxShadow: mfaLoading ? 'none' : '0 4px 24px rgba(129,140,248,0.4), 0 1px 0 rgba(255,255,255,0.1) inset',
                    }}
                  >
                    {mfaLoading ? 'Verifying…' : 'Verify'}
                  </button>
                  <button
                    type="button"
                    onClick={() => { setMfaToken(null); setMfaCode(''); setMfaError(''); }}
                    className="w-full text-center text-xs text-slate-500 hover:text-slate-300"
                  >
                    Back to sign in
                  </button>
                </form>
              ) : needsSetup === null ? (
                /* Still checking /auth/setup-status — avoid flashing one form then the other */
                <div className="px-8 py-8 flex items-center justify-center gap-2 text-sm text-slate-500">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                  </svg>
                  Checking…
                </div>
              ) : needsSetup ? (
                <form className="px-8 py-8 space-y-5" onSubmit={handleSetupSubmit}>
                  {setupError && (
                    <div
                      className="px-4 py-3 rounded-lg text-sm text-red-300 flex items-start gap-2"
                      style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}
                    >
                      <svg className="w-4 h-4 flex-shrink-0 mt-0.5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd"/>
                      </svg>
                      {setupError}
                    </div>
                  )}

                  {/* Admin email */}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest mb-2">
                      Admin email
                    </label>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)}
                      placeholder="you@company.com"
                      className="w-full px-4 py-2.5 rounded-lg text-sm text-white placeholder-slate-600 outline-none transition-all duration-200"
                      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                    />
                  </div>

                  {/* Admin password */}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest mb-2">
                      Admin password
                    </label>
                    <input
                      type="password"
                      required
                      value={password}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full px-4 py-2.5 rounded-lg text-sm text-white placeholder-slate-600 outline-none transition-all duration-200"
                      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                    />
                    {branding && (
                      <p className="text-[10px] text-slate-600 mt-1.5">
                        At least {branding.password_min_length} characters
                        {branding.password_require_uppercase ? ', one uppercase letter' : ''}
                        {branding.password_require_number ? ', one number' : ''}
                        {branding.password_require_special ? ', one special character' : ''}.
                      </p>
                    )}
                  </div>

                  {/* Confirm password */}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest mb-2">
                      Confirm password
                    </label>
                    <input
                      type="password"
                      required
                      value={confirmPw}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setConfirmPw(e.target.value)}
                      placeholder="••••••••"
                      className="w-full px-4 py-2.5 rounded-lg text-sm text-white placeholder-slate-600 outline-none transition-all duration-200"
                      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                    />
                  </div>

                  {/* Setup secret */}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest mb-2">
                      Setup secret
                    </label>
                    <input
                      type="password"
                      required
                      value={setupSecret}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSetupSecret(e.target.value)}
                      placeholder="From SETUP_SECRET in your .env"
                      className="w-full px-4 py-2.5 rounded-lg text-sm text-white placeholder-slate-600 outline-none transition-all duration-200"
                      style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                    />
                    <p className="text-[10px] text-slate-600 mt-1.5">
                      Proves you have server access — whoever deployed this instance set this in
                      the environment, it's not a password you choose here.
                    </p>
                  </div>

                  {/* Submit */}
                  <button
                    type="submit"
                    disabled={setupLoading}
                    className="w-full py-3 px-4 rounded-lg text-sm font-bold text-white transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{
                      background: 'linear-gradient(135deg, #38BDF8 0%, #818CF8 50%, #A855F7 100%)',
                      boxShadow: setupLoading ? 'none' : '0 4px 24px rgba(129,140,248,0.4), 0 1px 0 rgba(255,255,255,0.1) inset',
                    }}
                  >
                    {setupLoading ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                        </svg>
                        Setting up…
                      </span>
                    ) : (
                      <span className="flex items-center justify-center gap-2">
                        Create admin & sign in
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/>
                        </svg>
                      </span>
                    )}
                  </button>
                </form>
              ) : (
                <form className="px-8 py-8 space-y-5" onSubmit={handleSubmit}>
                  {error && (
                    <div
                      className="px-4 py-3 rounded-lg text-sm text-red-300 flex items-start gap-2"
                      style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)' }}
                    >
                      <svg className="w-4 h-4 flex-shrink-0 mt-0.5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd"/>
                      </svg>
                      {error}
                    </div>
                  )}

                  {/* Email */}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest mb-2">
                      Email address
                    </label>
                    <div className="relative">
                      <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"/>
                        </svg>
                      </div>
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)}
                        placeholder="you@company.com"
                        className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm text-white placeholder-slate-600 outline-none transition-all duration-200"
                        style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                        onFocus={(e: React.FocusEvent<HTMLInputElement>) => {
                          e.target.style.borderColor = '#818CF8';
                          e.target.style.boxShadow = '0 0 0 3px rgba(129,140,248,0.12)';
                        }}
                        onBlur={(e: React.FocusEvent<HTMLInputElement>) => {
                          e.target.style.borderColor = 'rgba(129,140,248,0.2)';
                          e.target.style.boxShadow = 'none';
                        }}
                      />
                    </div>
                  </div>

                  {/* Password */}
                  <div>
                    <label className="block text-[11px] font-semibold text-slate-400 uppercase tracking-widest mb-2">
                      Password
                    </label>
                    <div className="relative">
                      <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/>
                        </svg>
                      </div>
                      <input
                        type="password"
                        required
                        value={password}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
                        placeholder="••••••••"
                        className="w-full pl-10 pr-4 py-2.5 rounded-lg text-sm text-white placeholder-slate-600 outline-none transition-all duration-200"
                        style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                        onFocus={(e: React.FocusEvent<HTMLInputElement>) => {
                          e.target.style.borderColor = '#818CF8';
                          e.target.style.boxShadow = '0 0 0 3px rgba(129,140,248,0.12)';
                        }}
                        onBlur={(e: React.FocusEvent<HTMLInputElement>) => {
                          e.target.style.borderColor = 'rgba(129,140,248,0.2)';
                          e.target.style.boxShadow = 'none';
                        }}
                      />
                    </div>
                  </div>

                  {/* Submit */}
                  <button
                    type="submit"
                    disabled={loading}
                    className="w-full py-3 px-4 rounded-lg text-sm font-bold text-white transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{
                      background: 'linear-gradient(135deg, #38BDF8 0%, #818CF8 50%, #A855F7 100%)',
                      boxShadow: loading ? 'none' : '0 4px 24px rgba(129,140,248,0.4), 0 1px 0 rgba(255,255,255,0.1) inset',
                    }}
                    onMouseEnter={(e: React.MouseEvent<HTMLButtonElement>) => { if (!loading) e.currentTarget.style.transform = 'translateY(-1px)'; }}
                    onMouseLeave={(e: React.MouseEvent<HTMLButtonElement>) => { e.currentTarget.style.transform = 'translateY(0)'; }}
                  >
                    {loading ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                        </svg>
                        Authenticating…
                      </span>
                    ) : (
                      <span className="flex items-center justify-center gap-2">
                        Sign in to {platformName}
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/>
                        </svg>
                      </span>
                    )}
                  </button>

                  {branding?.sso_enabled && (
                    <>
                      <div className="flex items-center gap-3 text-[10px] text-slate-600 uppercase tracking-widest">
                        <div className="flex-1 h-px bg-slate-800" />
                        or
                        <div className="flex-1 h-px bg-slate-800" />
                      </div>
                      <a
                        href={`${API_URL}/auth/sso/login`}
                        className="w-full py-3 px-4 rounded-lg text-sm font-semibold text-slate-200 flex items-center justify-center gap-2 transition-all duration-200"
                        style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(129,140,248,0.2)' }}
                      >
                        Continue with {branding.sso_provider_name}
                      </a>
                    </>
                  )}
                </form>
              )}
            </div>

            {/* Trust indicators */}
            <div className="flex items-center justify-center gap-5 mt-6">
              {[
                { icon: '🔒', text: 'End-to-end encrypted' },
                { icon: '🛡️', text: 'SOC 2 Ready' },
                { icon: '✓', text: 'Audit logged' },
              ].map(t => (
                <div key={t.text} className="flex items-center gap-1.5 text-[10px] text-slate-600 font-medium">
                  <span>{t.icon}</span>
                  <span>{t.text}</span>
                </div>
              ))}
            </div>

            <p className="text-center text-[10px] text-slate-700 mt-6">
              &copy; {new Date().getFullYear()} {platformName} · {tagline} · All rights reserved
            </p>
          </div>
        </div>

      </div>
    </>
  );
}
