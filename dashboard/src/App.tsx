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

export const App: React.FC = () => {
  const [currentRoute, setCurrentRoute] = useState<string>(() => {
    if (typeof window !== 'undefined') {
      const path = window.location.pathname;
      return path.startsWith('/dashboard') ? '/dashboard' : '/';
    }
    return '/';
  });

  useEffect(() => {
    const handlePopState = () => {
      const path = window.location.pathname;
      setCurrentRoute(path.startsWith('/dashboard') ? '/dashboard' : '/');
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigateTo = (route: string) => {
    window.history.pushState({}, '', route);
    setCurrentRoute(route);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (currentRoute === '/dashboard') {
    return <DashboardPage onNavigate={navigateTo} />;
  }

  return (
    <div className="min-h-screen bg-[#07072B] text-[#F5F5F7] flex flex-col font-sans selection:bg-[#A8F500]/30 selection:text-[#F5F5F7]">
      {/* Sticky Premium Navbar */}
      <Navbar onNavigate={navigateTo} currentRoute={currentRoute} />

      {/* Main Public Landing Content */}
      <main className="flex-grow">
        {/* Hero Section */}
        <Hero onNavigate={navigateTo} />

        {/* Section 1 — Core Capabilities */}
        <Capabilities />

        {/* Section 2 — How It Works (Pipeline) */}
        <HowItWorks />

        {/* Section 3 — Threat Detection (6 Threat Signals) */}
        <ThreatDetection />

        {/* Section 4 — Explainable Detection (Realistic Alert Spotlight) */}
        <ExplainableDetection />

        {/* Section 5 — Passive by Design (3 Pillars) */}
        <PassiveByDesign />

        {/* Section 6 — Architecture (Connected Blocks) */}
        <Architecture />

        {/* Section 7 — Product Preview (Wide Dashboard Showcase) */}
        <ProductPreview onNavigate={navigateTo} />

        {/* Section 8 — Final CTA */}
        <FinalCTA onNavigate={navigateTo} />
      </main>

      {/* Dark Minimal Footer */}
      <Footer onNavigate={navigateTo} />
    </div>
  );
};

export default App;
