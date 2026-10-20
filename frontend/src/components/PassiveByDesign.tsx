import React from 'react';
import { EyeOff, ShieldCheck, Binary, Lock, Check } from 'lucide-react';

export const PassiveByDesign: React.FC = () => {
  const pillars = [
    {
      id: '01',
      title: 'READ-ONLY MONITORING',
      subtitle: 'Traffic is observed without modifying network communication.',
      icon: EyeOff,
      bullet: 'Zero inline latency',
      description:
        'NETRA operates entirely via out-of-band SPAN mirrors or passive optical TAPs. No packet injection, blocking, or probing occurs on the monitored wire.',
    },
    {
      id: '02',
      title: 'METADATA-FIRST ANALYSIS',
      subtitle: 'The system works with flow and protocol metadata.',
      icon: Binary,
      bullet: 'High-entropy telemetry',
      description:
        'Evaluates timing, duration, packet length variance, TCP window parameters, and directionality ratios to capture attacker footprints.',
    },
    {
      id: '03',
      title: 'NO PAYLOAD DECRYPTION',
      subtitle: 'TLS/QUIC payloads are not decrypted or inspected.',
      icon: Lock,
      bullet: 'Privacy & compliance preserved',
      description:
        'Zero man-in-the-middle certificates, zero private key exposure, and zero compliance risks. Privacy-preserving monitoring by architectural design.',
    },
  ];

  return (
    <section className="py-24 md:py-32 relative bg-[#07072B] border-t border-[#242452]/70">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-4">
            <ShieldCheck className="w-3.5 h-3.5 text-[#A8F500]" />
            ARCHITECTURAL INTEGRITY
          </div>
          <h2 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight leading-tight">
            OBSERVE WITHOUT<br />
            <span className="text-[#39D7FF]">INTERFERING.</span>
          </h2>
          <p className="mt-4 text-base sm:text-lg text-[#A5A5BE] font-sans">
            Guaranteed operational silence and zero footprint across critical enterprise network segments.
          </p>
        </div>

        {/* 3 Clean Horizontal Feature Pillars */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 lg:gap-8">
          {pillars.map((pillar) => {
            const Icon = pillar.icon;
            return (
              <div
                key={pillar.id}
                className="group rounded-2xl bg-[#10103D]/60 hover:bg-[#15154A] border border-[#242452] hover:border-[#A8F500]/50 p-8 transition-all duration-300 flex flex-col justify-between shadow-lg hover:-translate-y-1"
              >
                <div>
                  {/* Icon & ID */}
                  <div className="flex items-center justify-between mb-6">
                    <div className="w-12 h-12 rounded-xl bg-[#07072B] border border-[#242452] group-hover:border-[#A8F500]/40 flex items-center justify-center transition-colors">
                      <Icon className="w-5 h-5 text-[#A8F500]" />
                    </div>
                    <span className="text-xs font-mono font-bold text-[#A5A5BE]/50">
                      // {pillar.id}
                    </span>
                  </div>

                  {/* Title & Subtitle */}
                  <h3 className="font-heading font-extrabold text-xl text-[#F5F5F7] tracking-tight mb-2">
                    {pillar.title}
                  </h3>
                  <p className="text-sm font-semibold text-[#A8F500] font-sans mb-4">
                    {pillar.subtitle}
                  </p>

                  {/* Body description */}
                  <p className="text-sm text-[#A5A5BE] leading-relaxed font-sans mb-6">
                    {pillar.description}
                  </p>
                </div>

                {/* Pill highlight */}
                <div className="pt-4 border-t border-[#242452]/80 flex items-center gap-2 text-xs font-mono text-[#39D7FF]">
                  <Check className="w-3.5 h-3.5 text-[#A8F500]" />
                  <span>{pillar.bullet}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
