import { useState } from 'react';
import { ShieldCheck, ShieldOff, KeyRound, AlertTriangle, Check } from 'lucide-react';
import { api, getTokenPayload } from '../api';

interface EnrollResponse {
  secret: string;
  provisioning_uri: string;
  qr_code_png_base64: string;
}

export function MyAccount() {
  const payload = getTokenPayload();
  const email = payload?.sub ?? '';

  // MFA status isn't in the JWT (it can change mid-session without a new
  // login), so this page tracks it locally rather than trusting the token —
  // it starts "unknown" and the enroll/disable flows themselves are the
  // source of truth for what state we're in.
  const [enrolling, setEnrolling] = useState(false);
  const [enrollData, setEnrollData] = useState<EnrollResponse | null>(null);
  const [confirmCode, setConfirmCode] = useState('');
  const [confirmError, setConfirmError] = useState('');
  const [confirmLoading, setConfirmLoading] = useState(false);
  const [enabled, setEnabled] = useState<boolean | null>(null);

  const [disabling, setDisabling] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableError, setDisableError] = useState('');
  const [disableLoading, setDisableLoading] = useState(false);

  const startEnroll = async () => {
    setEnrolling(true);
    setConfirmError('');
    try {
      const { data } = await api.post<EnrollResponse>('/auth/mfa/enroll');
      setEnrollData(data);
    } catch (e: any) {
      setConfirmError(e.response?.data?.detail || 'Failed to start MFA enrollment');
      setEnrolling(false);
    }
  };

  const confirmEnroll = async () => {
    setConfirmLoading(true);
    setConfirmError('');
    try {
      await api.post('/auth/mfa/enroll/confirm', { code: confirmCode });
      setEnabled(true);
      setEnrolling(false);
      setEnrollData(null);
      setConfirmCode('');
    } catch (e: any) {
      setConfirmError(e.response?.data?.detail || 'Invalid code');
    } finally {
      setConfirmLoading(false);
    }
  };

  const disable = async () => {
    setDisableLoading(true);
    setDisableError('');
    try {
      await api.post('/auth/mfa/disable', { password: disablePassword });
      setEnabled(false);
      setDisabling(false);
      setDisablePassword('');
    } catch (e: any) {
      setDisableError(e.response?.data?.detail || 'Incorrect password');
    } finally {
      setDisableLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in text-slate-800 dark:text-slate-100 max-w-2xl">
      <div className="pb-2 border-b border-slate-150 dark:border-slate-850">
        <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-3">
          <KeyRound className="w-8 h-8 text-brand-indigo" />
          <span>My Account</span>
        </h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{email}</p>
      </div>

      <div className="premium-card p-6 space-y-4">
        <h2 className="text-lg font-bold text-slate-900 dark:text-white">Two-Factor Authentication</h2>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Require a 6-digit code from an authenticator app (Google Authenticator, Authy, 1Password, ...)
          in addition to your password when signing in.
        </p>

        {!enrolling && enabled !== false && (
          <div className="flex items-center gap-2">
            <button onClick={startEnroll} className="premium-btn-primary gap-2 text-xs px-3.5 py-2">
              <ShieldCheck size={14} /> {enabled ? 'Re-enroll MFA' : 'Enable MFA'}
            </button>
            {enabled && !disabling && (
              <button onClick={() => setDisabling(true)} className="premium-btn-secondary gap-2 text-xs px-3.5 py-2">
                <ShieldOff size={14} /> Disable MFA
              </button>
            )}
          </div>
        )}

        {enrollData && (
          <div className="space-y-4 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Scan this QR code with your authenticator app, or enter the secret manually.
            </p>
            <img
              src={`data:image/png;base64,${enrollData.qr_code_png_base64}`}
              alt="MFA QR code"
              className="w-40 h-40 bg-white p-2 rounded-lg"
            />
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Secret</label>
              <code className="block text-xs font-mono text-slate-700 dark:text-slate-300 break-all p-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                {enrollData.secret}
              </code>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Enter code to confirm</label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={confirmCode}
                onChange={e => setConfirmCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className="premium-input font-mono text-center tracking-[0.5em]"
              />
            </div>
            {confirmError && (
              <p className="text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1.5 font-semibold">
                <AlertTriangle size={12} /> {confirmError}
              </p>
            )}
            <div className="flex justify-end gap-3">
              <button onClick={() => { setEnrolling(false); setEnrollData(null); setConfirmCode(''); }} className="premium-btn-secondary">
                Cancel
              </button>
              <button onClick={confirmEnroll} disabled={confirmLoading || confirmCode.length !== 6} className="premium-btn-primary disabled:opacity-50">
                {confirmLoading ? 'Verifying…' : 'Confirm & Enable'}
              </button>
            </div>
          </div>
        )}

        {enabled && (
          <div className="flex items-center gap-1.5 text-xs text-emerald-600 dark:text-emerald-400 font-semibold">
            <Check size={13} /> MFA is enabled on this account.
          </div>
        )}

        {disabling && (
          <div className="space-y-3 p-4 rounded-xl border border-rose-200 dark:border-rose-900/30 bg-rose-50/30 dark:bg-rose-950/10">
            <p className="text-xs text-slate-600 dark:text-slate-400">Enter your password to disable MFA.</p>
            <input
              type="password"
              value={disablePassword}
              onChange={e => setDisablePassword(e.target.value)}
              placeholder="Password"
              className="premium-input"
            />
            {disableError && (
              <p className="text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1.5 font-semibold">
                <AlertTriangle size={12} /> {disableError}
              </p>
            )}
            <div className="flex justify-end gap-3">
              <button onClick={() => { setDisabling(false); setDisablePassword(''); }} className="premium-btn-secondary">Cancel</button>
              <button onClick={disable} disabled={disableLoading || !disablePassword} className="premium-btn-primary disabled:opacity-50">
                {disableLoading ? 'Disabling…' : 'Disable MFA'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
