import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

// Reached after the backend's GET /auth/sso/callback finishes the OIDC
// exchange and redirects here with the real access token in the URL
// fragment (never a query string, so it never lands in server access logs).
export function SSOCallback() {
  const navigate = useNavigate();
  const [error, setError] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const token = params.get('token');
    if (!token) {
      setError('No token received from SSO login.');
      return;
    }
    localStorage.setItem('token', token);
    // Strip the token out of the URL before navigating so it never sits in
    // browser history.
    window.history.replaceState(null, '', '/sso/callback');
    navigate('/', { replace: true });
  }, [navigate]);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-300">
        <div className="text-center space-y-3">
          <p className="text-sm text-rose-400">{error}</p>
          <a href="/login" className="text-xs text-slate-500 hover:text-slate-300 underline">Back to sign in</a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-400 text-sm">
      Signing you in…
    </div>
  );
}
