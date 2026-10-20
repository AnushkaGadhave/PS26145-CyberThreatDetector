import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Hero } from './components/Hero';
import { Capabilities } from './components/Capabilities';
import { HowItWorks } from './components/HowItWorks';
import { ThreatDetection } from './components/ThreatDetection';
import { ExplainableDetection } from './components/ExplainableDetection';
import { PassiveByDesign } from './components/PassiveByDesign';
import { Architecture } from './components/Architecture';
import { ProductPreview } from './components/ProductPreview';
import { FinalCTA } from './components/FinalCTA';
import { Footer } from './components/Footer';
import { DashboardPage } from './components/DashboardPage';
import { LoginPage } from './components/LoginPage';
import { ErrorBoundary } from './components/dashboard/ErrorBoundary';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AlertTriangle, RefreshCw } from 'lucide-react';

const AppContent: React.FC = () => {
  const { isAuthenticated, isAuthLoading } = useAuth();

  const [currentRoute, setCurrentRoute] = useState<string>(() => {
    if (typeof window !== 'undefined') {
      const path = window.location.pathname;
      if (path === '/login') return '/login';
      if (path.startsWith('/dashboard')) return path;
    }
    return '/';
  });

  useEffect(() => {
    const handlePopState = () => {
      const path = window.location.pathname;
      if (path === '/login') {
        setCurrentRoute('/login');
      } else if (path.startsWith('/dashboard')) {
        setCurrentRoute(path);
      } else {
        setCurrentRoute(path === '' ? '/' : path);
      }
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigateTo = (route: string) => {
    window.history.pushState({}, '', route);
    setCurrentRoute(route);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Route Guard: Protected Dashboard Pages
  if (currentRoute.startsWith('/dashboard')) {
    if (isAuthLoading) {
      return (
        <div className="min-h-screen bg-[#07072B] flex flex-col items-center justify-center font-mono text-[#F5F5F7]">
          <RefreshCw className="w-8 h-8 text-[#39D7FF] animate-spin mb-4" />
          <p className="text-sm font-semibold tracking-wide">
            Verifying Operator Credentials...
          </p>
          <p className="text-xs text-[#A5A5BE] mt-1 font-sans">
            Checking authenticated session with NETRA backend console
          </p>
        </div>
      );
    }

    if (!isAuthenticated) {
      // Redirect to login preserving intended target
      return <LoginPage onNavigate={navigateTo} />;
    }

    return <DashboardPage onNavigate={navigateTo} currentRoute={currentRoute} />;
  }

  // Login Page (redirects to dashboard if already authenticated)
  if (currentRoute === '/login') {
    if (isAuthenticated) {
      return <DashboardPage onNavigate={navigateTo} currentRoute="/dashboard" />;
    }
    return <LoginPage onNavigate={navigateTo} />;
  }

  // Landing Page
  if (currentRoute === '/') {
    return (
      <div className="min-h-screen bg-[#07072B] text-[#F5F5F7] flex flex-col font-sans selection:bg-[#A8F500]/30 selection:text-[#F5F5F7]">
        {/* Sticky Premium Navbar */}
        <Navbar onNavigate={navigateTo} currentRoute={currentRoute} />

        {/* Main Public Landing Content */}
        <main className="flex-grow">
          <Hero onNavigate={navigateTo} />
          <Capabilities />
          <HowItWorks />
          <ThreatDetection />
          <ExplainableDetection />
          <PassiveByDesign />
          <Architecture />
          <ProductPreview onNavigate={navigateTo} />
          <FinalCTA onNavigate={navigateTo} />
        </main>

        {/* Dark Minimal Footer */}
        <Footer onNavigate={navigateTo} />
      </div>
    );
  }

  // 404 Route Not Found
  return (
    <div className="min-h-screen bg-[#07072B] text-[#F5F5F7] flex flex-col font-sans selection:bg-[#A8F500]/30 selection:text-[#F5F5F7]">
      <Navbar onNavigate={navigateTo} currentRoute={currentRoute} />
      <main className="flex-1 flex items-center justify-center p-6 font-mono">
        <div className="max-w-md w-full bg-[#10103D]/90 border border-[#242452] rounded-2xl p-8 text-center shadow-2xl space-y-4">
          <div className="w-16 h-16 rounded-2xl bg-[#FF4D5A]/15 border border-[#FF4D5A]/30 flex items-center justify-center mx-auto text-[#FF4D5A]">
            <AlertTriangle className="w-8 h-8" />
          </div>
          <h1 className="font-heading font-extrabold text-2xl text-[#F5F5F7]">
            404 — Page Not Found
          </h1>
          <p className="text-xs text-[#A5A5BE]">
            The requested URL <code className="text-[#39D7FF]">{currentRoute}</code> does not exist on NETRA Sensor.
          </p>
          <div className="flex items-center justify-center gap-3 pt-3">
            <button
              onClick={() => navigateTo('/')}
              className="px-4 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] text-xs transition-all cursor-pointer"
            >
              Return to Home
            </button>
            <button
              onClick={() => navigateTo('/dashboard')}
              className="px-4 py-2 rounded-xl bg-[#39D7FF]/20 hover:bg-[#39D7FF]/30 border border-[#39D7FF]/40 text-[#F5F5F7] text-xs font-bold transition-all cursor-pointer"
            >
              Open Dashboard
            </button>
          </div>
        </div>
      </main>
      <Footer onNavigate={navigateTo} />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ErrorBoundary
      fallbackTitle="NETRA Platform Exception"
      onReset={() => window.location.href = '/'}
      onNavigateHome={() => window.location.href = '/'}
    >
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ErrorBoundary>
  );
};

export default App;
