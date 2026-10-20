import React from 'react';
import { ArrowRight, Shield } from 'lucide-react';


interface FinalCTAProps {
  onNavigate: (route: string) => void;
}

export const FinalCTA: React.FC<FinalCTAProps> = ({ onNavigate }) => {
  return (
    <section className="py-28 md:py-36 relative bg-[#07072B] border-t border-[#242452]/70 overflow-hidden text-center">
      {/* Background Subtle Ambience */}
      <div className="absolute inset-0 dot-matrix opacity-25 pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[350px] bg-[#A8F500]/5 rounded-full blur-[160px] pointer-events-none" />

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10 flex flex-col items-center">
        {/* Eyebrow */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-8">
          <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500] animate-pulse" />
          START CONTINUOUS VISIBILITY
        </div>

        {/* Large Heading */}
        <h2 className="font-heading font-extrabold text-3xl sm:text-5xl md:text-6xl text-[#F5F5F7] tracking-tight leading-[1.12] max-w-4xl mb-6">
          YOUR NETWORK IS ALWAYS MOVING.<br />
          <span className="text-[#A8F500]">YOUR VISIBILITY SHOULD BE TOO.</span>
        </h2>

        {/* Supporting text */}
        <p className="font-sans text-lg sm:text-xl text-[#A5A5BE] max-w-xl mx-auto mb-10 leading-relaxed">
          Observe traffic. Analyze behavior. Investigate suspicious activity.
        </p>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 w-full sm:w-auto">
          <button
            onClick={() => onNavigate('/dashboard')}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-8 py-4 rounded-xl font-semibold text-base text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-all duration-200 shadow-lg hover:shadow-[#A8F500]/25 cursor-pointer group"
          >
            <span>Launch Monitoring</span>
            <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
          </button>

          <a
            href="#architecture"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-8 py-4 rounded-xl font-medium text-base text-[#F5F5F7] bg-[#10103D]/70 hover:bg-[#15154A] border border-[#242452] hover:border-[#39D7FF]/40 transition-all duration-200"
          >
            <span>View Architecture</span>
          </a>
        </div>

        {/* Official SIH Tagline */}
        <div className="mt-14 pt-8 border-t border-[#242452]/60 flex items-center gap-2 text-xs font-mono text-[#A5A5BE]/70">
          <Shield className="w-3.5 h-3.5 text-[#A8F500]" />
          <span>Smart India Hackathon • Problem Statement 26145 • Read-Only Unidirectional Telemetry</span>
        </div>
      </div>
    </section>
  );
};
