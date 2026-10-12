import React from 'react';
import { Eye, Cpu, BrainCircuit, ArrowUpRight } from 'lucide-react';

export const Capabilities: React.FC = () => {
  const capabilities = [
    {
      number: '01',
      title: 'PASSIVE CAPTURE',
      description:
        'Observe authorized network traffic without sending, modifying, blocking, or probing packets.',
      icon: Eye,
      tag: 'Zero Active Injections',
      details: 'Strict read-only network tap preserving line-rate integrity and operational silence.',
    },
    {
      number: '02',
      title: 'FLOW ANALYSIS',
      description:
        'Convert packets into structured bidirectional network flows and behavioral features.',
      icon: Cpu,
      tag: '5-Tuple Temporal Aggregation',
      details: 'Statistical windowing computing packet length entropy, inter-arrival times, and volume ratios.',
    },
    {
      number: '03',
      title: 'EXPLAINABLE DETECTION',
      description:
        'Generate security alerts with confidence, supporting evidence, and model context.',
      icon: BrainCircuit,
      tag: 'Calibrated Inference & Evidence',
      details: 'Provides transparent telemetry justifications instead of opaque black-box alarm scores.',
    },
  ];

  return (
    <section id="product" className="py-24 md:py-32 relative border-t border-[#242452]/70 bg-[#07072B]">
      {/* Subtle background ambient dot pattern */}
      <div className="absolute inset-0 dot-matrix opacity-20 pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
            CORE CAPABILITIES
          </div>
          <h2 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight leading-tight">
            ONE MONITORING LAYER.<br />
            <span className="text-[#A5A5BE]">MULTIPLE THREAT SIGNALS.</span>
          </h2>
          <p className="mt-4 text-base sm:text-lg text-[#A5A5BE] font-sans">
            Engineered from first principles for non-intrusive enterprise visibility across unidirectional taps and encrypted channels.
          </p>
        </div>

        {/* 3 Premium Feature Blocks */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 lg:gap-8">
          {capabilities.map((cap) => {
            const Icon = cap.icon;
            return (
              <div
                key={cap.number}
                className="group relative rounded-2xl bg-[#10103D]/70 hover:bg-[#15154A] border border-[#242452] hover:border-[#A8F500]/50 p-8 sm:p-10 transition-all duration-300 hover:-translate-y-1.5 shadow-lg hover:shadow-2xl hover:shadow-[#A8F500]/5 flex flex-col justify-between"
              >
                {/* Top Number & Icon */}
                <div>
                  <div className="flex items-start justify-between mb-8">
                    <span className="font-heading font-extrabold text-5xl sm:text-6xl text-[#A5A5BE]/30 group-hover:text-[#A8F500] transition-colors duration-300 font-mono tracking-tighter">
                      {cap.number}
                    </span>
                    <div className="w-11 h-11 rounded-xl bg-[#07072B] border border-[#242452] group-hover:border-[#A8F500]/40 flex items-center justify-center transition-colors">
                      <Icon className="w-5 h-5 text-[#A5A5BE] group-hover:text-[#A8F500] transition-colors" />
                    </div>
                  </div>

                  {/* Title & Tag */}
                  <div className="mb-4">
                    <span className="text-[11px] font-mono tracking-wider uppercase text-[#39D7FF] bg-[#39D7FF]/10 px-2.5 py-0.5 rounded-full border border-[#39D7FF]/20 inline-block mb-3">
                      {cap.tag}
                    </span>
                    <h3 className="font-heading font-extrabold text-xl sm:text-2xl text-[#F5F5F7] tracking-tight">
                      {cap.title}
                    </h3>
                  </div>

                  {/* Body description */}
                  <p className="text-sm sm:text-base text-[#A5A5BE] leading-relaxed mb-6 font-sans">
                    {cap.description}
                  </p>
                </div>

                {/* Bottom Technical Insight */}
                <div className="pt-6 border-t border-[#242452]/80 flex items-center justify-between text-xs text-[#A5A5BE]/80">
                  <span className="leading-snug">{cap.details}</span>
                  <ArrowUpRight className="w-4 h-4 text-[#A5A5BE]/40 group-hover:text-[#A8F500] transition-colors shrink-0 ml-2" />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
