import React, { useState } from 'react';
import {
  Mail,
  Lock,
  Eye,
  EyeOff,
  ArrowLeft,
  Shield,
  AlertCircle,
  Loader2,
  Sparkles,
  Terminal
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getApiBaseUrl } from '../services/api';

interface LoginPageProps {
  onNavigate: (route: string) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onNavigate }) => {
  const { login } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [touchedEmail, setTouchedEmail] = useState(false);
  const [touchedPassword, setTouchedPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [showForgotPasswordModal, setShowForgotPasswordModal] = useState(false);

  // Form Validation Logic
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isEmailValid = email.trim().length > 0 && emailRegex.test(email.trim());
  const isPasswordValid = password.length >= 8;

  const emailError = touchedEmail && !isEmailValid
    ? email.trim().length === 0
      ? 'Email address is required'
      : 'Please enter a valid email address (e.g., admin@soc.gov.in)'
    : null;

  const passwordError = touchedPassword && !isPasswordValid
    ? password.length === 0
      ? 'Password is required'
      : 'Password must be at least 8 characters long'
    : null;

  const isFormValid = isEmailValid && isPasswordValid;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouchedEmail(true);
    setTouchedPassword(true);

    if (!isFormValid || isLoading) return;

    setIsLoading(true);
    setLoginError(null);

    try {
      await login({ email: email.trim(), password });

      // Determine destination after login
      let targetRoute = '/dashboard';
      if (typeof window !== 'undefined') {
        const params = new URLSearchParams(window.location.search);
        const redirectParam = params.get('redirect');
        if (redirectParam && redirectParam.startsWith('/dashboard')) {
          targetRoute = redirectParam;
        }
      }

      onNavigate(targetRoute);
    } catch (err: any) {
      if (err.status === 401) {
        setLoginError('Invalid work email or password. Please verify your credentials.');
      } else if (err.status === 429) {
        setLoginError(err.message || 'Account temporarily locked due to repeated failed login attempts.');
      } else if (err.status === 0) {
        setLoginError(`Backend unavailable. Could not connect to API server at ${getApiBaseUrl()}.`);
      } else {
        setLoginError(err.message || 'Authentication failed. Please verify credentials or contact SOC administrator.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#07072B] text-[#F5F5F7] flex flex-col justify-between font-sans selection:bg-[#A8F500]/30 selection:text-[#F5F5F7] relative overflow-hidden">
      {/* Background Ambience & Grid */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute inset-0 dot-matrix opacity-40 [mask-image:radial-gradient(ellipse_at_center,transparent_20%,black_80%)]" />
        <div className="perspective-grid-container opacity-60">
          <div className="perspective-grid" />
        </div>
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-[#4C8DFF]/10 rounded-full blur-[140px]" />
        <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 w-[500px] h-[250px] bg-[#A8F500]/5 rounded-full blur-[130px]" />
      </div>

      {/* Top Header Bar */}
      <header className="relative z-20 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5 flex items-center justify-between">
        <button
          onClick={() => onNavigate('/')}
          className="inline-flex items-center gap-2 text-xs sm:text-sm font-medium text-[#A5A5BE] hover:text-[#F5F5F7] px-3.5 py-2 rounded-xl bg-[#10103D]/60 hover:bg-[#15154A] border border-[#242452] hover:border-[#39D7FF]/40 transition-all cursor-pointer backdrop-blur-sm group"
        >
          <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-0.5 text-[#39D7FF]" />
          <span>Return to Landing Page</span>
        </button>

        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-[#A5A5BE] bg-[#10103D]/60 border border-[#242452] px-3 py-1.5 rounded-full backdrop-blur-sm">
          <span className="w-2 h-2 rounded-full bg-[#A8F500] animate-pulse" />
          <span>SIH PS 26145</span>
          <span className="text-[#242452]">|</span>
          <span className="text-[#39D7FF]">SECURE AUTH CONSOLE</span>
        </div>
      </header>

      {/* Main Content / Card Container */}
      <main className="relative z-10 flex-1 flex items-center justify-center px-4 sm:px-6 py-8">
        <div className="w-full max-w-md mx-auto">
          {/* Main Login Card */}
          <div className="relative rounded-2xl bg-[#10103D]/90 border border-[#242452] shadow-2xl p-6 sm:p-8 backdrop-blur-xl glow-panel">
            {/* Card Header & Brand */}
            <div className="text-center mb-6 sm:mb-8">
              <button
                onClick={() => onNavigate('/')}
                className="inline-flex items-center gap-2.5 mb-4 group cursor-pointer focus:outline-none"
                aria-label="NETRA Home"
              >
                <div className="relative w-10 h-10 rounded-xl bg-[#07072B] border border-[#242452] flex items-center justify-center group-hover:border-[#A8F500]/60 transition-colors">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#A8F500] animate-ping-dot absolute" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#A8F500]" />
                  <div className="absolute inset-0 border border-[#A8F500]/20 rounded-xl scale-90 group-hover:scale-100 transition-transform" />
                </div>
                <span className="font-heading font-extrabold text-2xl tracking-tight text-[#F5F5F7] flex items-center">
                  NETRA
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#A8F500] ml-1" />
                </span>
              </button>

              <h1 className="font-heading font-extrabold text-xl sm:text-2xl text-[#F5F5F7] tracking-tight mb-2">
                Security Console Access
              </h1>
              <p className="text-xs sm:text-sm text-[#A5A5BE] font-sans">
                Sign in with authorized SOC operator credentials to access real-time flow telemetry and model detection alerts.
              </p>
            </div>

            {/* Error Message Alert */}
            {loginError && (
              <div className="mb-6 p-4 rounded-xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/40 text-[#F5F5F7] text-xs font-sans animate-fadeIn">
                <div className="flex items-start gap-2.5">
                  <AlertCircle className="w-4 h-4 text-[#FF4D5A] shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <p className="font-semibold text-[#FF4D5A] text-[13px]">
                      Authentication Failed
                    </p>
                    <p className="text-[#A5A5BE] leading-relaxed">
                      {loginError}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Login Form */}
            <form onSubmit={handleSubmit} noValidate className="space-y-4 sm:space-y-5">
              {/* Email Field */}
              <div>
                <label
                  htmlFor="email"
                  className="block text-xs font-semibold uppercase tracking-wider text-[#A5A5BE] mb-1.5"
                >
                  Work Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#A5A5BE]">
                    <Mail className="w-4 h-4" />
                  </div>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      if (loginError) setLoginError(null);
                    }}
                    onBlur={() => setTouchedEmail(true)}
                    placeholder="admin@soc.gov.in"
                    autoComplete="email"
                    className={`w-full bg-[#07072B] border rounded-xl pl-10 pr-4 py-2.5 text-sm font-mono text-[#F5F5F7] placeholder-[#A5A5BE]/40 focus:outline-none transition-colors ${
                      emailError
                        ? 'border-[#FF4D5A] focus:border-[#FF4D5A]'
                        : 'border-[#242452] focus:border-[#39D7FF]'
                    }`}
                  />
                </div>
                {emailError && (
                  <div className="flex items-center gap-1.5 mt-1.5 text-xs text-[#FF4D5A]">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{emailError}</span>
                  </div>
                )}
              </div>

              {/* Password Field */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label
                    htmlFor="password"
                    className="block text-xs font-semibold uppercase tracking-wider text-[#A5A5BE]"
                  >
                    Password
                  </label>
                  <button
                    type="button"
                    onClick={() => setShowForgotPasswordModal(true)}
                    className="text-xs text-[#39D7FF] hover:text-[#7ADFFF] transition-colors cursor-pointer"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#A5A5BE]">
                    <Lock className="w-4 h-4" />
                  </div>
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      if (loginError) setLoginError(null);
                    }}
                    onBlur={() => setTouchedPassword(true)}
                    placeholder="••••••••••••"
                    autoComplete="current-password"
                    className={`w-full bg-[#07072B] border rounded-xl pl-10 pr-11 py-2.5 text-sm font-mono text-[#F5F5F7] placeholder-[#A5A5BE]/40 focus:outline-none transition-colors ${
                      passwordError
                        ? 'border-[#FF4D5A] focus:border-[#FF4D5A]'
                        : 'border-[#242452] focus:border-[#39D7FF]'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-[#A5A5BE] hover:text-[#F5F5F7] transition-colors cursor-pointer focus:outline-none"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4" />
                    ) : (
                      <Eye className="w-4 h-4" />
                    )}
                  </button>
                </div>
                {passwordError && (
                  <div className="flex items-center gap-1.5 mt-1.5 text-xs text-[#FF4D5A]">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{passwordError}</span>
                  </div>
                )}
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                id="login-submit-btn"
                disabled={!isFormValid || isLoading}
                className={`w-full py-3 px-4 rounded-xl font-semibold text-sm transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer ${
                  isFormValid && !isLoading
                    ? 'bg-[#A8F500] hover:bg-[#B7FF19] text-[#07072B] shadow-md hover:shadow-[#A8F500]/25'
                    : 'bg-[#15154A] text-[#A5A5BE]/50 border border-[#242452] cursor-not-allowed'
                }`}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-[#07072B]" />
                    <span>Verifying Credentials...</span>
                  </>
                ) : (
                  <span>Sign In</span>
                )}
              </button>
            </form>

            {/* Divider */}
            <div className="relative my-6 sm:my-7">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-[#242452]" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-[#10103D] px-3 font-mono text-[#A5A5BE]/80 text-[11px] tracking-wider">
                  SOC Account Provisioning
                </span>
              </div>
            </div>

            {/* Administrator Bootstrap Information Card */}
            <div className="space-y-3">
              <div className="p-3.5 rounded-xl bg-[#0B0B35] border border-[#242452] flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-[#F5F5F7]">
                    <Terminal className="w-3.5 h-3.5 text-[#39D7FF]" />
                    <span>Administrator Provisioning</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#39D7FF]/10 text-[#39D7FF] border border-[#39D7FF]/30">
                    HOST CLI
                  </span>
                </div>
                <p className="text-[11px] text-[#A5A5BE] leading-relaxed">
                  Public registration is disabled. Administrator accounts are provisioned via the secure host CLI:
                </p>
                <div className="p-2 rounded bg-[#07072B] border border-[#242452] font-mono text-[11px] text-[#A8F500] overflow-x-auto">
                  python scripts/create_admin.py
                </div>
                <button
                  type="button"
                  id="prefill-admin-btn"
                  onClick={() => {
                    setEmail('admin@soc.gov.in');
                    setPassword('CyberDefense2026!');
                    setTouchedEmail(true);
                    setTouchedPassword(true);
                    if (loginError) setLoginError(null);
                  }}
                  className="w-full mt-1 inline-flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg text-xs font-mono text-[#39D7FF] bg-[#10103D] hover:bg-[#15154A] border border-[#39D7FF]/30 hover:border-[#39D7FF] transition-all cursor-pointer"
                >
                  <Sparkles className="w-3 h-3" />
                  <span>Pre-fill Default Admin Credentials</span>
                </button>
                <div className="text-[10px] text-[#A5A5BE] font-mono text-center pt-1">
                  Default: <span className="text-[#F5F5F7]">admin@soc.gov.in</span> • <span className="text-[#39D7FF]">CyberDefense2026!</span>
                </div>
              </div>
            </div>

            {/* Security Notice Footer */}
            <div className="mt-6 pt-5 border-t border-[#242452] flex items-center justify-center gap-2 text-[11px] font-mono text-[#A5A5BE]/70 text-center">
              <Shield className="w-3.5 h-3.5 text-[#A8F500]/70 shrink-0" />
              <span>Strict Argon2id Authentication • Session-Protected Console</span>
            </div>
          </div>
        </div>
      </main>

      {/* Page Bottom Metadata */}
      <footer className="relative z-20 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5 text-center">
        <div className="text-[11px] font-mono text-[#A5A5BE]/50">
          Smart India Hackathon • PS 26145 • Unidirectional Threat Monitoring System
        </div>
      </footer>

      {/* Forgot Password Modal */}
      {showForgotPasswordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
          <div className="max-w-sm w-full bg-[#10103D] border border-[#242452] rounded-2xl p-6 shadow-2xl relative">
            <div className="flex items-center gap-2 text-[#39D7FF] mb-3">
              <Shield className="w-5 h-5" />
              <h3 className="font-heading font-bold text-base text-[#F5F5F7]">
                SOC Credential Recovery
              </h3>
            </div>
            <p className="text-xs text-[#A5A5BE] leading-relaxed mb-4 font-sans">
              For security compliance under unidirectional traffic monitoring protocols, self-service password resets are disabled.
            </p>
            <div className="p-3 rounded-lg bg-[#07072B] border border-[#242452] text-[11px] font-mono text-[#A5A5BE] space-y-1 mb-5">
              <div>Command: <span className="text-[#39D7FF]">python scripts/create_admin.py --force</span></div>
              <div>Hotline: <span className="text-[#A8F500]">EXT-26145 (SOC Desk)</span></div>
            </div>
            <button
              onClick={() => setShowForgotPasswordModal(false)}
              className="w-full py-2.5 px-4 rounded-xl font-medium text-xs text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-colors cursor-pointer"
            >
              Close Notice
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default LoginPage;
