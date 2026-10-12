import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Binary, 
  Sliders, 
  Fingerprint,
  Info
} from 'lucide-react';


export const ExplainableDetection: React.FC = () => {
  const [selectedMetric, setSelectedMetric] = useState<number | null>(null);

  const evidenceMetrics = [
    {
      key: 'Src_Flows_60s',
      value: '18',
      normalRange: '1 - 4',
      ratio: '90%',
      description: 'Egress flow initiation frequency within rolling 60-second temporal window.',
      status: 'Anomalous Fan-Out',
      limeHighlight: true,
    },
    {
      key: 'RepeatRatio',
      value: '0.82',
      normalRange: '< 0.30',
      ratio: '82%',
      description: 'Ratio of repeated destination endpoint socket attempts indicating persistent target lock.',
      status: 'High Convergence',
      limeHighlight: true,
    },
    {
      key: 'IAT Regularity',
      value: '0.94',
      normalRange: '< 0.45',
      ratio: '94%',
      description: 'Inter-Arrival Time coefficient of variation revealing deterministic beaconing periodicity.',
      status: 'Periodic Heartbeat',
      limeHighlight: true,
    },
  ];

  return (
    <section id="explainable" className="py-24 md:py-32 relative bg-[#0B0B35]/80 border-t border-[#242452]/70 overflow-hidden">
      {/* Background Radial Glow */}
      <div className="absolute top-1/2 right-1/4 -translate-y-1/2 w-[550px] h-[550px] bg-[#A8F500]/5 rounded-full blur-[140px] pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-center">
          
          {/* Left Column: Heading and Technical Context */}
          <div className="lg:col-span-6 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
              EXPLAINABLE AI ENGINE
            </div>

            <h2 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight leading-[1.12]">
              DON'T JUST DETECT A THREAT.<br />
              <span className="text-[#A8F500]">UNDERSTAND WHY.</span>
            </h2>

            <p className="text-base sm:text-lg text-[#A5A5BE] font-sans leading-relaxed">
              Opaque risk scores trigger alert fatigue and wasted incident triage. NETRA inspects mathematical flow telemetry, attaching explicit behavioral features and calibrated confidence bands to every detection.
            </p>

            <div className="space-y-4 pt-2">
              <div className="p-4 rounded-xl bg-[#10103D]/70 border border-[#242452] flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-[#07072B] border border-[#242452] flex items-center justify-center shrink-0 mt-0.5">
                  <Fingerprint className="w-4 h-4 text-[#A8F500]" />
                </div>
                <div>
                  <h4 className="font-heading font-bold text-sm text-[#F5F5F7]">
                    Zero Black-Box Assertions
                  </h4>
                  <p className="text-xs text-[#A5A5BE] mt-1 leading-relaxed">
                    Every flag cites exact statistical evidence: inter-arrival cadence, packet length variance, and direction asymmetry.
                  </p>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#10103D]/70 border border-[#242452] flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-lg bg-[#07072B] border border-[#242452] flex items-center justify-center shrink-0 mt-0.5">
                  <Sliders className="w-4 h-4 text-[#39D7FF]" />
                </div>
                <div>
                  <h4 className="font-heading font-bold text-sm text-[#F5F5F7]">
                    Calibrated Confidence Tiers
                  </h4>
                  <p className="text-xs text-[#A5A5BE] mt-1 leading-relaxed">
                    Empirical validation curves separate genuine anomalous behavior from baseline noisy enterprise traffic.
                  </p>
                </div>
              </div>
            </div>

            {/* Truthful Context Banner */}
            <div className="pt-2 text-[11px] font-mono text-[#A5A5BE]/70 flex items-center gap-2">
              <Info className="w-3.5 h-3.5 text-[#39D7FF] shrink-0" />
              <span>
                Simulated live triage card shown for conceptual demonstration. Detections represent model suspicion.
              </span>
            </div>
          </div>

          {/* Right Column: Realistic Alert Visualization Card */}
          <div className="lg:col-span-6">
            <div className="relative rounded-2xl bg-[#10103D] border border-[#242452] shadow-2xl p-6 sm:p-8 backdrop-blur-xl group hover:border-[#A8F500]/40 transition-all duration-300">
              {/* Card Header */}
              <div className="flex items-center justify-between pb-5 border-b border-[#242452]">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-[#FF8A3D]/15 border border-[#FF8A3D]/40 flex items-center justify-center">
                    <ShieldAlert className="w-5 h-5 text-[#FF8A3D]" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-heading font-extrabold text-xl sm:text-2xl text-[#F5F5F7] tracking-tight">
                        BOTNET_C2
                      </span>
                      <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-[#FF8A3D]/20 text-[#FF8A3D] border border-[#FF8A3D]/40">
                        HIGH
                      </span>
                    </div>
                    <span className="text-xs font-mono text-[#A5A5BE]">
                      ALERT_ID: #ALT-9402 • PROTOCOL: TCP
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <span className="px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold bg-[#07072B] border border-[#242452] text-[#A5A5BE] block mb-1">
                    UNLABELED_LIVE
                  </span>
                  <span className="text-[10px] font-mono text-[#39D7FF]">
                    Model Suspicion
                  </span>
                </div>
              </div>

              {/* Confidence Score Gauge */}
              <div className="py-5 border-b border-[#242452]">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-[#A5A5BE]">
                    Model Confidence
                  </span>
                  <span className="font-heading font-extrabold text-2xl text-[#A8F500] font-mono">
                    91%
                  </span>
                </div>
                {/* Progress bar with lime highlight */}
                <div className="w-full h-2 rounded-full bg-[#07072B] border border-[#242452] overflow-hidden p-0.5">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-[#7DDB52] via-[#A8F500] to-[#B7FF19] shadow-[0_0_12px_rgba(168,245,0,0.6)]"
                    style={{ width: '91%' }}
                  />
                </div>
                <div className="flex justify-between text-[10px] font-mono text-[#A5A5BE]/60 mt-1.5">
                  <span>BASELINE (0%)</span>
                  <span>SUSPICION THRESHOLD (75%)</span>
                  <span className="text-[#A8F500]">ACTIVE (91%)</span>
                </div>
              </div>

              {/* WHY FLAGGED Section */}
              <div className="py-5 border-b border-[#242452]">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Binary className="w-4 h-4 text-[#A8F500]" />
                    <span className="font-heading font-bold text-sm tracking-wider uppercase text-[#F5F5F7]">
                      WHY FLAGGED
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-[#A5A5BE]">
                    EVIDENCE VECTOR (TOP 3)
                  </span>
                </div>

                {/* Evidence Metrics Table */}
                <div className="space-y-3">
                  {evidenceMetrics.map((metric, idx) => (
                    <div
                      key={metric.key}
                      onClick={() => setSelectedMetric(selectedMetric === idx ? null : idx)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer ${
                        selectedMetric === idx
                          ? 'bg-[#15154A] border-[#A8F500]'
                          : 'bg-[#07072B]/80 border-[#242452] hover:border-[#A8F500]/50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="font-mono text-xs font-semibold text-[#F5F5F7]">
                            {metric.key}
                          </span>
                          <span className="text-[10px] font-mono text-[#A5A5BE] ml-2">
                            (Norm: {metric.normalRange})
                          </span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-mono font-extrabold text-sm sm:text-base text-[#A8F500]">
                            {metric.value}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#A8F500]/10 text-[#A8F500] border border-[#A8F500]/30">
                            {metric.status}
                          </span>
                        </div>
                      </div>

                      {/* Mini bar */}
                      <div className="w-full h-1 bg-[#10103D] rounded-full mt-2 overflow-hidden">
                        <div
                          className="h-full bg-[#A8F500] rounded-full"
                          style={{ width: metric.ratio }}
                        />
                      </div>

                      {/* Expanded explanation */}
                      {selectedMetric === idx && (
                        <p className="mt-2 text-[11px] text-[#A5A5BE] leading-relaxed pt-2 border-t border-[#242452]">
                          {metric.description}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Concluding Alert Explanation Summary */}
              <div className="pt-4 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="w-2 h-2 rounded-full bg-[#A8F500] animate-pulse" />
                  <p className="font-sans text-xs sm:text-sm font-medium text-[#F5F5F7]">
                    Repeated source-destination activity observed.
                  </p>
                </div>
                <span className="text-[11px] font-mono text-[#39D7FF]">
                  Window: 60.0s
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
