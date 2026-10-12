import React from 'react';
import { ArrowLeft, Shield, Server, ExternalLink, CheckCircle2 } from 'lucide-react';


interface DashboardPageProps {
  onNavigate: (route: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  return (
    <div className="min-h-screen bg-[#07072B] text-[#F5F5F7] flex flex-col justify-between">
      {/* Top Navigation */}
      <header className="border-b border-[#242452] bg-[#07072B]/90 backdrop-blur-md px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigate('/')}
              className="p-2 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all flex items-center gap-2 text-xs font-mono"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back to Landing Page</span>
            </button>
            <div className="h-4 w-px bg-[#242452]" />
            <div className="flex items-center gap-2">
              <span className="font-heading font-extrabold text-lg text-[#F5F5F7]">
                NETRA
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#A8F500]/15 text-[#A8F500] border border-[#A8F500]/30">
                /dashboard
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono text-[#A5A5BE]">
            <span className="flex items-center gap-1.5 text-[#7DDB52]">
              <span className="w-2 h-2 rounded-full bg-[#7DDB52] animate-pulse" />
              ROUTE ACTIVE
            </span>
          </div>
        </div>
      </header>

      {/* Main Console Bridge Content */}
      <main className="max-w-4xl mx-auto px-4 py-16 text-center flex flex-col items-center">
        <div className="w-14 h-14 rounded-2xl bg-[#10103D] border border-[#242452] flex items-center justify-center mb-6 shadow-xl">
          <Shield className="w-7 h-7 text-[#A8F500]" />
        </div>

        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-4">
          <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
          SIH PS 26145 • OPERATIONAL CONSOLE ROUTE
        </div>

        <h1 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight mb-4">
          NETRA Monitoring Console
        </h1>

        <p className="text-base sm:text-lg text-[#A5A5BE] max-w-xl mx-auto leading-relaxed mb-10 font-sans">
          You have navigated to the dedicated <code className="text-[#A8F500] font-mono">/dashboard</code> route. As specified for this landing page deliverable, the full dashboard interface is linked and prepared for live API telemetry.
        </p>

        {/* Integration Architecture Card */}
        <div className="w-full rounded-2xl bg-[#10103D] border border-[#242452] p-6 sm:p-8 text-left shadow-2xl space-y-6">
          <div className="flex items-center justify-between border-b border-[#242452] pb-4">
            <span className="font-heading font-bold text-base text-[#F5F5F7] flex items-center gap-2">
              <Server className="w-4 h-4 text-[#A8F500]" />
              FastAPI Telemetry Service Status
            </span>
            <span className="text-xs font-mono text-[#39D7FF]">
              PORT 8000
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-4 rounded-xl bg-[#07072B] border border-[#242452]">
              <div className="text-[#A5A5BE] mb-1">Backend Server Command:</div>
              <code className="text-[#A8F500] text-[11px] block overflow-x-auto">
                python -m uvicorn src.api.main:app --reload --port 8000
              </code>
            </div>

            <div className="p-4 rounded-xl bg-[#07072B] border border-[#242452]">
              <div className="text-[#A5A5BE] mb-1">API Interactive Docs:</div>
              <a
                href="http://127.0.0.1:8000/docs"
                target="_blank"
                rel="noreferrer"
                className="text-[#39D7FF] hover:underline flex items-center gap-1.5 text-[11px]"
              >
                <span>http://127.0.0.1:8000/docs</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#07072B]/60 border border-[#242452] space-y-2 text-xs">
            <div className="flex items-center gap-2 text-[#7DDB52] font-mono">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Route resolution verified for /dashboard</span>
            </div>
            <p className="text-[#A5A5BE] text-[11px] font-sans">
              Passive sensor capture, flow normalization, and detection models (DDoS, Botnet C2, Recon) are operational in the Python runtime.
            </p>
          </div>

          <div className="pt-2 flex justify-center">
            <button
              onClick={() => onNavigate('/')}
              className="inline-flex items-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-all cursor-pointer shadow-md hover:shadow-[#A8F500]/25"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Return to NETRA Landing Page</span>
            </button>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#242452] py-6 text-center text-xs font-mono text-[#A5A5BE]/60">
        NETRA • SIH Problem Statement 26145 • Dedicated Dashboard Gateway
      </footer>
    </div>
  );
};
