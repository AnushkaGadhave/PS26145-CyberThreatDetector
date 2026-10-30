import React, { useState } from 'react';
import {
  Mail,
  Lock,
  Eye,
  EyeOff,
  ArrowLeft,
  Shield,
  AlertCircle,
  CheckCircle2,
  Loader2,
  User,
  KeyRound
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getApiBaseUrl } from '../services/api';

interface LoginPageProps {
  onNavigate: (route: string) => void;
  initialMode?: 'login' | 'signup';
}

export const LoginPage: React.FC<LoginPageProps> = ({ onNavigate, initialMode = 'login' }) => {
  const { login, register } = useAuth();

  const [mode, setMode] = useState<'login' | 'signup'>(initialMode);

  // Common Fields
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Sign Up Specific Fields
  const [fullName, setFullName] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // Validation & Touched States
  const [touchedEmail, setTouchedEmail] = useState(false);
  const [touchedPassword, setTouchedPassword] = useState(false);
  const [touchedFullName, setTouchedFullName] = useState(false);
  const [touchedConfirmPassword, setTouchedConfirmPassword] = useState(false);

  // Status & UI States
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [showForgotPasswordModal, setShowForgotPasswordModal] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotSubmitted, setForgotSubmitted] = useState(false);
  const [forgotLoading, setForgotLoading] = useState(false);

  // Validation Rules
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const isEmailValid = email.trim().length > 0 && emailRegex.test(email.trim());
  const isPasswordLengthValid = password.length >= 8;
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const isPasswordStrong = isPasswordLengthValid && hasLetter && hasDigit;
  const isFullNameValid = fullName.trim().length >= 2;
  const doPasswordsMatch = password.length > 0 && password === confirmPassword;

  // Field Errors
  const emailError = touchedEmail && !isEmailValid
    ? email.trim().length === 0
      ? 'Email address is required'
      : 'Please enter a valid email address'
    : null;

  const passwordError = touchedPassword && !isPasswordLengthValid
    ? password.length === 0
      ? 'Password is required'
      : 'Password must be at least 8 characters long'
    : touchedPassword && mode === 'signup' && !isPasswordStrong
    ? 'Password must include at least one letter and one number'
    : null;

  const fullNameError = touchedFullName && mode === 'signup' && !isFullNameValid
    ? fullName.trim().length === 0
      ? 'Full name is required'
      : 'Full name must be at least 2 characters'
    : null;

  const confirmPasswordError = touchedConfirmPassword && mode === 'signup' && !doPasswordsMatch
    ? confirmPassword.length === 0
      ? 'Please confirm your password'
      : 'Passwords do not match'
    : null;

  const isLoginFormValid = isEmailValid && isPasswordLengthValid;
  const isSignUpFormValid = isFullNameValid && isEmailValid && isPasswordStrong && doPasswordsMatch;

  const isFormValid = mode === 'login' ? isLoginFormValid : isSignUpFormValid;

  const switchMode = (newMode: 'login' | 'signup') => {
    setMode(newMode);
    setErrorMessage(null);
    setSuccessMessage(null);
    setTouchedEmail(false);
    setTouchedPassword(false);
    setTouchedFullName(false);
    setTouchedConfirmPassword(false);
  };

  const getTargetRoute = (): string => {
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const redirectParam = params.get('redirect');
      if (redirectParam && redirectParam.startsWith('/dashboard')) {
        return redirectParam;
      }
    }
    return '/dashboard';
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouchedEmail(true);
    setTouchedPassword(true);
    if (mode === 'signup') {
      setTouchedFullName(true);
      setTouchedConfirmPassword(true);
    }

    if (!isFormValid || isLoading) return;

    setIsLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      if (mode === 'login') {
        await login({ email: email.trim(), password });
        onNavigate(getTargetRoute());
      } else {
        await register({
          full_name: fullName.trim(),
          email: email.trim().toLowerCase(),
          password
        });
        setSuccessMessage('Account created successfully! Initializing your workspace...');
        setTimeout(() => {
          onNavigate(getTargetRoute());
        }, 1200);
      }
    } catch (err: any) {
      if (err.status === 401) {
        setErrorMessage('Invalid email or password. Please verify your credentials and try again.');
      } else if (err.status === 409) {
        setErrorMessage('An account with this email address already exists. Please log in instead.');
      } else if (err.status === 429) {
        setErrorMessage(err.message || 'Too many attempts. Please wait a few minutes before trying again.');
      } else if (err.status === 0) {
        setErrorMessage(`Backend service unavailable. Could not connect to API server at ${getApiBaseUrl()}.`);
      } else {
        setErrorMessage(err.message || (mode === 'login' ? 'Authentication failed. Please try again.' : 'Registration failed. Please try again.'));
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#07072B] text-[#F5F5F7] flex flex-col justify-between font-sans selection:bg-[#A8F500]/30 selection:text-[#F5F5F7] relative overflow-hidden">
      {/* Background Ambience & Perspective Grid */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute inset-0 dot-matrix opacity-40 [mask-image:radial-gradient(ellipse_at_center,transparent_20%,black_80%)]" />
        <div className="perspective-grid-container opacity-60">
          <div className="perspective-grid" />
        </div>
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-[#4C8DFF]/10 rounded-full blur-[140px]" />
        <div className="absolute bottom-1/4 left-1/2 -translate-x-1/2 w-[500px] h-[250px] bg-[#A8F500]/5 rounded-full blur-[130px]" />
      </div>

      {/* Top Navigation Bar */}
      <header className="relative z-20 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5 flex items-center justify-between">
        <button
          onClick={() => onNavigate('/')}
          className="inline-flex items-center gap-2 text-xs sm:text-sm font-medium text-[#A5A5BE] hover:text-[#F5F5F7] px-3.5 py-2 rounded-xl bg-[#10103D]/60 hover:bg-[#15154A] border border-[#242452] hover:border-[#39D7FF]/40 transition-all cursor-pointer backdrop-blur-sm group"
        >
          <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-0.5 text-[#39D7FF]" />
          <span>Return to Home</span>
        </button>

        <div className="flex items-center gap-2 text-xs font-mono text-[#A5A5BE] bg-[#10103D]/60 border border-[#242452] px-3.5 py-1.5 rounded-full backdrop-blur-sm">
          <span className="w-2 h-2 rounded-full bg-[#A8F500] animate-pulse" />
          <span className="text-[#39D7FF] font-semibold">THREATTRACK CLOUD AUTH</span>
        </div>
      </header>

      {/* Main Authentication Card */}
      <main className="relative z-10 flex-1 flex items-center justify-center px-4 sm:px-6 py-6 sm:py-10">
        <div className="w-full max-w-md mx-auto">
          <div className="relative rounded-2xl bg-[#10103D]/95 border border-[#242452] shadow-2xl p-6 sm:p-8 backdrop-blur-xl glow-panel">
            {/* Brand Header */}
            <div className="text-center mb-6">
              <button
                onClick={() => onNavigate('/')}
                className="inline-flex items-center gap-2.5 mb-3 group cursor-pointer focus:outline-none"
                aria-label="ThreatTrack Home"
              >
                <div className="relative w-10 h-10 rounded-xl bg-[#07072B] border border-[#242452] flex items-center justify-center group-hover:border-[#A8F500]/60 transition-colors">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#A8F500] animate-ping-dot absolute" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#A8F500]" />
                  <div className="absolute inset-0 border border-[#A8F500]/20 rounded-xl scale-90 group-hover:scale-100 transition-transform" />
                </div>
                <span className="font-heading font-extrabold text-2xl tracking-tight text-[#F5F5F7] flex items-center">
                  ThreatTrack
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#A8F500] ml-1" />
                </span>
              </button>

              <h1 className="font-heading font-extrabold text-xl sm:text-2xl text-[#F5F5F7] tracking-tight mb-1.5">
                {mode === 'login' ? 'Sign In to ThreatTrack' : 'Create an Account'}
              </h1>
              <p className="text-xs sm:text-sm text-[#A5A5BE] font-sans">
                {mode === 'login'
                  ? 'Access your telemetry dashboard and monitor network threats.'
                  : 'Start monitoring network flows and detecting threats from your machine.'}
              </p>
            </div>

            {/* Segmented Mode Switcher */}
            <div className="grid grid-cols-2 p-1 mb-6 rounded-xl bg-[#07072B] border border-[#242452]">
              <button
                type="button"
                onClick={() => switchMode('login')}
                className={`py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  mode === 'login'
                    ? 'bg-[#15154A] text-[#F5F5F7] shadow-sm border border-[#39D7FF]/30'
                    : 'text-[#A5A5BE] hover:text-[#F5F5F7]'
                }`}
              >
                Log In
              </button>
              <button
                type="button"
                onClick={() => switchMode('signup')}
                className={`py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                  mode === 'signup'
                    ? 'bg-[#15154A] text-[#F5F5F7] shadow-sm border border-[#A8F500]/30'
                    : 'text-[#A5A5BE] hover:text-[#F5F5F7]'
                }`}
              >
                Sign Up
              </button>
            </div>

            {/* Error Notification */}
            {errorMessage && (
              <div className="mb-5 p-3.5 rounded-xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/40 text-[#F5F5F7] text-xs font-sans animate-fadeIn">
                <div className="flex items-start gap-2.5">
                  <AlertCircle className="w-4 h-4 text-[#FF4D5A] shrink-0 mt-0.5" />
                  <div className="space-y-0.5">
                    <p className="font-semibold text-[#FF4D5A]">
                      {mode === 'login' ? 'Sign In Error' : 'Registration Error'}
                    </p>
                    <p className="text-[#A5A5BE] leading-relaxed">{errorMessage}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Success Notification */}
            {successMessage && (
              <div className="mb-5 p-3.5 rounded-xl bg-[#A8F500]/10 border border-[#A8F500]/40 text-[#F5F5F7] text-xs font-sans animate-fadeIn">
                <div className="flex items-start gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-[#A8F500] shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold text-[#A8F500]">Success</p>
                    <p className="text-[#A5A5BE] leading-relaxed">{successMessage}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} noValidate className="space-y-4">
              {/* Full Name Field (Sign Up Only) */}
              {mode === 'signup' && (
                <div>
                  <label
                    htmlFor="fullName"
                    className="block text-xs font-semibold uppercase tracking-wider text-[#A5A5BE] mb-1.5"
                  >
                    Full Name
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#A5A5BE]">
                      <User className="w-4 h-4" />
                    </div>
                    <input
                      id="fullName"
                      type="text"
                      value={fullName}
                      onChange={(e) => {
                        setFullName(e.target.value);
                        if (errorMessage) setErrorMessage(null);
                      }}
                      onBlur={() => setTouchedFullName(true)}
                      placeholder="Jane Doe"
                      autoComplete="name"
                      className={`w-full bg-[#07072B] border rounded-xl pl-10 pr-4 py-2.5 text-sm text-[#F5F5F7] placeholder-[#A5A5BE]/40 focus:outline-none transition-colors ${
                        fullNameError
                          ? 'border-[#FF4D5A] focus:border-[#FF4D5A]'
                          : 'border-[#242452] focus:border-[#39D7FF]'
                      }`}
                    />
                  </div>
                  {fullNameError && (
                    <div className="flex items-center gap-1.5 mt-1.5 text-xs text-[#FF4D5A]">
                      <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>{fullNameError}</span>
                    </div>
                  )}
                </div>
              )}

              {/* Email Field */}
              <div>
                <label
                  htmlFor="email"
                  className="block text-xs font-semibold uppercase tracking-wider text-[#A5A5BE] mb-1.5"
                >
                  Email Address
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
                      if (errorMessage) setErrorMessage(null);
                    }}
                    onBlur={() => setTouchedEmail(true)}
                    placeholder="name@example.com"
                    autoComplete="email"
                    className={`w-full bg-[#07072B] border rounded-xl pl-10 pr-4 py-2.5 text-sm text-[#F5F5F7] placeholder-[#A5A5BE]/40 focus:outline-none transition-colors ${
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
                  {mode === 'login' && (
                    <button
                      type="button"
                      onClick={() => {
                        setForgotEmail(email);
                        setForgotSubmitted(false);
                        setShowForgotPasswordModal(true);
                      }}
                      className="text-xs text-[#39D7FF] hover:text-[#7ADFFF] transition-colors cursor-pointer"
                    >
                      Forgot password?
                    </button>
                  )}
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
                      if (errorMessage) setErrorMessage(null);
                    }}
                    onBlur={() => setTouchedPassword(true)}
                    placeholder={mode === 'signup' ? 'At least 8 characters (letter + number)' : '••••••••••••'}
                    autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                    className={`w-full bg-[#07072B] border rounded-xl pl-10 pr-11 py-2.5 text-sm text-[#F5F5F7] placeholder-[#A5A5BE]/40 focus:outline-none transition-colors ${
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
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {passwordError && (
                  <div className="flex items-center gap-1.5 mt-1.5 text-xs text-[#FF4D5A]">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{passwordError}</span>
                  </div>
                )}
              </div>

              {/* Confirm Password Field (Sign Up Only) */}
              {mode === 'signup' && (
                <div>
                  <label
                    htmlFor="confirmPassword"
                    className="block text-xs font-semibold uppercase tracking-wider text-[#A5A5BE] mb-1.5"
                  >
                    Confirm Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#A5A5BE]">
                      <KeyRound className="w-4 h-4" />
                    </div>
                    <input
                      id="confirmPassword"
                      type={showConfirmPassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => {
                        setConfirmPassword(e.target.value);
                        if (errorMessage) setErrorMessage(null);
                      }}
                      onBlur={() => setTouchedConfirmPassword(true)}
                      placeholder="Repeat your password"
                      autoComplete="new-password"
                      className={`w-full bg-[#07072B] border rounded-xl pl-10 pr-11 py-2.5 text-sm text-[#F5F5F7] placeholder-[#A5A5BE]/40 focus:outline-none transition-colors ${
                        confirmPasswordError
                          ? 'border-[#FF4D5A] focus:border-[#FF4D5A]'
                          : 'border-[#242452] focus:border-[#39D7FF]'
                      }`}
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-[#A5A5BE] hover:text-[#F5F5F7] transition-colors cursor-pointer focus:outline-none"
                      aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                    >
                      {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {confirmPasswordError && (
                    <div className="flex items-center gap-1.5 mt-1.5 text-xs text-[#FF4D5A]">
                      <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                      <span>{confirmPasswordError}</span>
                    </div>
                  )}
                </div>
              )}

              {/* Submit Action Button */}
              <button
                type="submit"
                id="auth-submit-btn"
                disabled={!isFormValid || isLoading}
                className={`w-full py-3 px-4 rounded-xl font-semibold text-sm transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer mt-2 ${
                  isFormValid && !isLoading
                    ? 'bg-[#A8F500] hover:bg-[#B7FF19] text-[#07072B] shadow-md hover:shadow-[#A8F500]/25'
                    : 'bg-[#15154A] text-[#A5A5BE]/50 border border-[#242452] cursor-not-allowed'
                }`}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-[#07072B]" />
                    <span>{mode === 'login' ? 'Signing In...' : 'Creating Account...'}</span>
                  </>
                ) : (
                  <span>{mode === 'login' ? 'Sign In' : 'Create Account'}</span>
                )}
              </button>
            </form>

            {/* Bottom Toggle Link */}
            <div className="mt-6 pt-5 border-t border-[#242452] text-center">
              {mode === 'login' ? (
                <p className="text-xs text-[#A5A5BE]">
                  Don't have an account?{' '}
                  <button
                    type="button"
                    onClick={() => switchMode('signup')}
                    className="font-semibold text-[#A8F500] hover:text-[#B7FF19] transition-colors cursor-pointer underline-offset-2 hover:underline"
                  >
                    Sign up
                  </button>
                </p>
              ) : (
                <p className="text-xs text-[#A5A5BE]">
                  Already have an account?{' '}
                  <button
                    type="button"
                    onClick={() => switchMode('login')}
                    className="font-semibold text-[#39D7FF] hover:text-[#7ADFFF] transition-colors cursor-pointer underline-offset-2 hover:underline"
                  >
                    Log in
                  </button>
                </p>
              )}
            </div>

            {/* Security Notice */}
            <div className="mt-4 flex items-center justify-center gap-2 text-[11px] font-mono text-[#A5A5BE]/60 text-center">
              <Shield className="w-3.5 h-3.5 text-[#A8F500]/70 shrink-0" />
              <span>Strict Argon2id Authentication • Session-Protected Workspace</span>
            </div>
          </div>
        </div>
      </main>

      {/* Page Footer */}
      <footer className="relative z-20 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5 text-center">
        <div className="text-[11px] font-mono text-[#A5A5BE]/50">
          ThreatTrack • AI-Powered Network Threat Monitoring System
        </div>
      </footer>

      {/* Forgot Password Modal */}
      {showForgotPasswordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fadeIn">
          <div className="max-w-md w-full bg-[#10103D] border border-[#242452] rounded-2xl p-6 sm:p-7 shadow-2xl relative glow-panel">
            {!forgotSubmitted ? (
              <>
                <div className="flex items-center gap-2.5 text-[#39D7FF] mb-2">
                  <Shield className="w-5 h-5 text-[#39D7FF]" />
                  <h3 className="font-heading font-bold text-lg text-[#F5F5F7]">
                    Reset Your Password
                  </h3>
                </div>
                <p className="text-xs text-[#A5A5BE] leading-relaxed mb-5 font-sans">
                  Enter the email address associated with your ThreatTrack account. We will dispatch instructions to help you reset your password.
                </p>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (!forgotEmail || !emailRegex.test(forgotEmail.trim())) return;
                    setForgotLoading(true);
                    setTimeout(() => {
                      setForgotLoading(false);
                      setForgotSubmitted(true);
                    }, 700);
                  }}
                  className="space-y-4"
                >
                  <div>
                    <label htmlFor="forgot-email" className="block text-xs font-semibold uppercase tracking-wider text-[#A5A5BE] mb-1.5">
                      Account Email
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#A5A5BE]">
                        <Mail className="w-4 h-4" />
                      </div>
                      <input
                        id="forgot-email"
                        type="email"
                        value={forgotEmail}
                        onChange={(e) => setForgotEmail(e.target.value)}
                        placeholder="name@example.com"
                        required
                        className="w-full bg-[#07072B] border border-[#242452] focus:border-[#39D7FF] rounded-xl pl-10 pr-4 py-2.5 text-sm text-[#F5F5F7] placeholder-[#A5A5BE]/40 focus:outline-none transition-colors"
                      />
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-[#07072B] border border-[#242452] text-[11px] text-[#A5A5BE] space-y-1">
                    <div className="flex items-center justify-between">
                      <span>Deployment Mode:</span>
                      <span className="text-[#39D7FF] font-mono">Self-Hosted PostgreSQL</span>
                    </div>
                    <div>If SMTP email delivery is not configured, contact your system administrator.</div>
                  </div>

                  <div className="flex gap-3 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowForgotPasswordModal(false)}
                      className="flex-1 py-2.5 px-4 rounded-xl font-medium text-xs text-[#A5A5BE] hover:text-[#F5F5F7] bg-[#15154A] hover:bg-[#1a1a5e] border border-[#242452] transition-colors cursor-pointer"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={forgotLoading || !forgotEmail || !emailRegex.test(forgotEmail.trim())}
                      className="flex-1 py-2.5 px-4 rounded-xl font-semibold text-xs text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] disabled:bg-[#15154A] disabled:text-[#A5A5BE]/40 transition-colors cursor-pointer flex items-center justify-center gap-2"
                    >
                      {forgotLoading ? (
                        <>
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-[#07072B]" />
                          <span>Sending...</span>
                        </>
                      ) : (
                        <span>Send Instructions</span>
                      )}
                    </button>
                  </div>
                </form>
              </>
            ) : (
              <div className="text-center py-2">
                <div className="w-12 h-12 rounded-full bg-[#A8F500]/10 border border-[#A8F500]/40 flex items-center justify-center mx-auto mb-3.5">
                  <CheckCircle2 className="w-6 h-6 text-[#A8F500]" />
                </div>
                <h3 className="font-heading font-bold text-lg text-[#F5F5F7] mb-2">
                  Instructions Dispatched
                </h3>
                <p className="text-xs text-[#A5A5BE] leading-relaxed mb-5 font-sans">
                  If an account is associated with <span className="text-[#39D7FF] font-medium">{forgotEmail}</span>, instructions have been dispatched. Please check your inbox and spam folder.
                </p>
                <div className="p-3 rounded-lg bg-[#07072B] border border-[#242452] text-[11px] font-mono text-[#A5A5BE] mb-5 text-left space-y-1">
                  <div>Delivery Status: <span className="text-[#A8F500]">Processed</span></div>
                  <div>Support Desk: <span className="text-[#39D7FF]">Contact your SOC Administrator</span></div>
                </div>
                <button
                  onClick={() => setShowForgotPasswordModal(false)}
                  className="w-full py-2.5 px-4 rounded-xl font-semibold text-xs text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-colors cursor-pointer"
                >
                  Back to Sign In
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default LoginPage;
