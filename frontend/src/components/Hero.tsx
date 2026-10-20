import React from 'react';
import { ArrowRight, Activity, AlertTriangle } from 'lucide-react';

interface HeroProps {
  onNavigate: (route: string) => void;
}

export const Hero: React.FC<HeroProps> = ({ onNavigate }) => {


  return (
    <section className="relative min-h-[95vh] pt-32 pb-24 md:pt-40 md:pb-32 flex flex-col items-center justify-center overflow-hidden">
      {/* Background Technical Grid and Matrix (Parlo reference inspired) */}
      <div className="absolute inset-0 pointer-events-none">
        {/* Top & corner faint dot matrix */}
        <div className="absolute inset-0 dot-matrix opacity-40 [mask-image:radial-gradient(ellipse_at_center,transparent_20%,black_75%)]" />

        {/* Subtle radial ambient illumination */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[350px] bg-[#4C8DFF]/8 rounded-full blur-[130px]" />
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[450px] h-[220px] bg-[#A8F500]/5 rounded-full blur-[110px]" />

        {/* 3D Perspective Network Floor Grid (Parlo reference) */}
        <div className="perspective-grid-container">
          <div className="perspective-grid" />
        </div>

        {/* Ambient Network Nodes */}
        <div className="hidden lg:block absolute inset-0">
          <div className="absolute top-[28%] left-[12%] flex items-center gap-2 text-[11px] font-mono text-[#A5A5BE]/40 tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]/60 animate-ping-dot" />
            <span>TAP_INTERFACE::01 (UNIDIRECTIONAL)</span>
          </div>
          <div className="absolute top-[34%] right-[14%] flex items-center gap-2 text-[11px] font-mono text-[#A5A5BE]/40 tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-[#39D7FF]/60" />
            <span>FLOW_BUFFER::AGGREGATING</span>
          </div>
          <div className="absolute bottom-[22%] left-[16%] flex items-center gap-2 text-[11px] font-mono text-[#A5A5BE]/35 tracking-wider">
            <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]/40" />
            <span>READ_ONLY_CAPTURE::ACTIVE</span>
          </div>
        </div>
      </div>

      {/* Hero Content Container */}
      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center flex flex-col items-center">
        {/* Top Eyebrow Badge (Lime accent) */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#10103D]/80 border border-[#242452] hover:border-[#A8F500]/40 transition-colors shadow-sm mb-6 sm:mb-8 backdrop-blur-sm animate-fadeIn">
          <span className="w-2 h-2 rounded-full bg-[#A8F500] animate-pulse" />
          <span className="text-[11px] sm:text-xs font-semibold tracking-wider uppercase text-[#A8F500]">
            PASSIVE NETWORK THREAT MONITORING
          </span>
          <span className="text-[#242452] text-xs">|</span>
          <span className="text-[11px] sm:text-xs font-mono text-[#A5A5BE]">
            SIH PS 26145
          </span>
        </div>

        {/* Main Heading */}
        <h1 className="font-heading font-extrabold text-4xl sm:text-5xl md:text-6xl lg:text-7xl text-[#F5F5F7] tracking-tight leading-[1.08] max-w-4xl mb-6">
          SEE EVERY FLOW.<br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#F5F5F7] via-[#F5F5F7] to-[#A5A5BE]">
            DETECT EVERY THREAT.
          </span>
        </h1>

        {/* Supporting Paragraph (Narrow, clean, readable) */}
        <p className="font-sans text-base sm:text-lg md:text-xl text-[#A5A5BE] max-w-2xl mx-auto leading-relaxed mb-8 sm:mb-10 font-normal">
          Passively capture network traffic, analyze flow behavior, and surface explainable security alerts without inspecting or decrypting application payloads.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3.5 sm:gap-4 w-full sm:w-auto mb-16 sm:mb-20">
          <button
            onClick={() => onNavigate('/dashboard')}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-6 py-3.5 rounded-xl font-semibold text-sm sm:text-base text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-all duration-200 shadow-md hover:shadow-[#A8F500]/25 cursor-pointer group"
          >
            <span>Launch Monitoring</span>
            <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
          </button>

          <a
            href="#how-it-works"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl font-medium text-sm sm:text-base text-[#F5F5F7] bg-[#10103D]/70 hover:bg-[#15154A] border border-[#242452] hover:border-[#39D7FF]/40 transition-all duration-200 backdrop-blur-sm"
          >
            Explore How It Works
          </a>
        </div>

        {/* Hero Product Visual (Floating preview panel inspired by NordLayer & Parlo) */}
        <div className="w-full max-w-4xl mx-auto relative group">
          {/* Subtle outer decorative glow */}
          <div className="absolute -inset-1 rounded-2xl bg-gradient-to-b from-[#242452]/50 via-transparent to-[#A8F500]/10 blur-xl opacity-75 group-hover:opacity-100 transition-opacity" />

          {/* Main Panel Box */}
          <div className="relative rounded-xl sm:rounded-2xl bg-[#10103D] border border-[#242452] shadow-2xl overflow-hidden backdrop-blur-xl text-left">
            {/* Panel Top Titlebar */}
            <div className="px-4 sm:px-6 py-3.5 bg-[#0B0B35]/80 border-b border-[#242452] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#FF4D5A]/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#F7B84B]/80" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#7DDB52]/80" />
                </div>
                <div className="h-4 w-px bg-[#242452]" />
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#A8F500] animate-ping-dot" />
                  <span className="text-xs font-mono font-medium tracking-wider text-[#A8F500] uppercase">
                    LIVE MONITOR PREVIEW
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-3 text-xs font-mono text-[#A5A5BE]">
                <span className="hidden sm:inline-block px-2 py-0.5 rounded bg-[#07072B] border border-[#242452] text-[11px]">
                  INTERFACE: ETH0 (PASSIVE_TAP)
                </span>
                <span className="text-[#7DDB52] flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#7DDB52]" />
                  ONLINE
                </span>
              </div>
            </div>

            {/* Metrics Ribbon */}
            <div className="grid grid-cols-2 sm:grid-cols-4 border-b border-[#242452] bg-[#07072B]/40">
              <div className="p-3.5 sm:p-4 border-r border-b sm:border-b-0 border-[#242452]">
                <div className="text-[11px] font-mono text-[#A5A5BE] uppercase tracking-wider mb-1">
                  Network Activity
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="font-heading font-extrabold text-xl sm:text-2xl text-[#F5F5F7]">
                    18
                  </span>
                  <span className="text-xs font-mono text-[#A8F500]">FLOWS</span>
                </div>
              </div>

              <div className="p-3.5 sm:p-4 border-r border-b sm:border-b-0 border-[#242452]">
                <div className="text-[11px] font-mono text-[#A5A5BE] uppercase tracking-wider mb-1">
                  Total Detections
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="font-heading font-extrabold text-xl sm:text-2xl text-[#39D7FF]">
                    8
                  </span>
                  <span className="text-xs font-mono text-[#A5A5BE]">ALERTS</span>
                </div>
              </div>

              <div className="p-3.5 sm:p-4 border-r border-[#242452]">
                <div className="text-[11px] font-mono text-[#A5A5BE] uppercase tracking-wider mb-1">
                  High Severity
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="font-heading font-extrabold text-xl sm:text-2xl text-[#FF8A3D]">
                    2
                  </span>
                  <span className="text-xs font-mono text-[#FF8A3D]/80">HIGH</span>
                </div>
              </div>

              <div className="p-3.5 sm:p-4">
                <div className="text-[11px] font-mono text-[#A5A5BE] uppercase tracking-wider mb-1">
                  Critical Impact
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="font-heading font-extrabold text-xl sm:text-2xl text-[#F5F5F7]">
                    0
                  </span>
                  <span className="text-xs font-mono text-[#7DDB52]">CRITICAL</span>
                </div>
              </div>
            </div>

            {/* Inner Dashboard View: Animated Chart & Alert Row */}
            <div className="p-4 sm:p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#A8F500]" />
                  <span className="font-heading font-bold text-sm text-[#F5F5F7]">
                    Real-Time Temporal Traffic Rate (Forward/Backward Packets)
                  </span>
                </div>
                <span className="font-mono text-[11px] text-[#A5A5BE]">
                  SAMPLING WINDOW: 60s MICRO-BATCHES
                </span>
              </div>

              {/* Vector SVG Sparkline Graph */}
              <div className="relative h-28 sm:h-36 w-full rounded-lg bg-[#07072B]/60 border border-[#242452] p-3 flex items-end overflow-hidden">
                {/* Horizontal reference grid lines */}
                <div className="absolute inset-0 flex flex-col justify-between p-3 pointer-events-none opacity-20">
                  <div className="border-b border-[#A5A5BE]" />
                  <div className="border-b border-[#A5A5BE]" />
                  <div className="border-b border-[#A5A5BE]" />
                </div>

                {/* Animated SVG Path Area */}
                <svg
                  className="w-full h-full overflow-visible"
                  viewBox="0 0 600 120"
                  preserveAspectRatio="none"
                >
                  <defs>
                    <linearGradient id="limeGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#A8F500" stopOpacity="0.3" />
                      <stop offset="100%" stopColor="#A8F500" stopOpacity="0.0" />
                    </linearGradient>
                  </defs>

                  {/* Area fill */}
                  <path
                    d="M 0 100 Q 60 70, 120 85 T 240 45 T 360 80 T 480 30 T 600 50 L 600 120 L 0 120 Z"
                    fill="url(#limeGrad)"
                  />

                  {/* Wave line */}
                  <path
                    d="M 0 100 Q 60 70, 120 85 T 240 45 T 360 80 T 480 30 T 600 50"
                    fill="none"
                    stroke="#A8F500"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                  />

                  {/* Secondary Cyan Reference Line */}
                  <path
                    d="M 0 90 Q 60 95, 120 60 T 240 70 T 360 50 T 480 65 T 600 75"
                    fill="none"
                    stroke="#39D7FF"
                    strokeWidth="1.5"
                    strokeDasharray="4 4"
                    opacity="0.6"
                  />

                  {/* Current Active Data Point Indicator */}
                  <circle cx="480" cy="30" r="4.5" fill="#A8F500" className="animate-pulse" />
                  <circle cx="480" cy="30" r="8" fill="none" stroke="#A8F500" strokeWidth="1" opacity="0.5" />
                </svg>

                {/* Floating telemetry callout */}
                <div className="absolute top-2 right-4 bg-[#10103D]/90 border border-[#242452] px-2.5 py-1 rounded text-[11px] font-mono text-[#F5F5F7] shadow">
                  <span className="text-[#A8F500] font-bold">1,842 pkts/s</span> peak
                </div>
              </div>

              {/* Recent Alert Preview Bar */}
              <div className="p-3 sm:p-3.5 rounded-lg bg-[#07072B]/80 border border-[#242452] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded-md bg-[#FF8A3D]/15 border border-[#FF8A3D]/40 flex items-center justify-center shrink-0">
                    <AlertTriangle className="w-4 h-4 text-[#FF8A3D]" />
                  </div>
                  <div className="flex flex-col">
                    <div className="flex items-center gap-2">
                      <span className="font-heading font-bold text-xs sm:text-sm text-[#F5F5F7]">
                        BOTNET_C2
                      </span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-semibold bg-[#FF8A3D]/20 text-[#FF8A3D] border border-[#FF8A3D]/30">
                        HIGH
                      </span>
                      <span className="text-[11px] font-mono text-[#A5A5BE] hidden sm:inline">
                        192.168.1.104 → 198.51.100.44:443
                      </span>
                    </div>
                    <span className="text-[11px] text-[#A5A5BE]">
                      Periodic beaconing detected • Confidence 91% • Evidence: IAT Regularity = 0.94
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0">
                  <span className="text-[11px] font-mono text-[#A5A5BE]">
                    JUST NOW
                  </span>
                  <button
                    onClick={() => onNavigate('/dashboard')}
                    className="text-xs font-semibold text-[#A8F500] hover:text-[#B7FF19] flex items-center gap-1 group/btn"
                  >
                    <span>Inspect</span>
                    <ArrowRight className="w-3 h-3 transition-transform group-hover/btn:translate-x-0.5" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
