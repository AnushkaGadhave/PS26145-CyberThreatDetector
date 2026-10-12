import React, { useState, useEffect } from 'react';
import { 
  Network, 
  Radio, 
  Layers, 
  Binary, 
  Cpu, 
  BellRing, 
  LayoutDashboard,
  ChevronRight,
  Info
} from 'lucide-react';

export const HowItWorks: React.FC = () => {
  const [activeStep, setActiveStep] = useState(0);
  const [autoPlay, setAutoPlay] = useState(true);

  const pipelineSteps = [
    {
      id: 1,
      shortName: 'NETWORK TRAFFIC',
      title: 'Network Traffic',
      icon: Network,
      tag: 'Raw Interface',
      desc: 'High-speed line rate IP packets traversing mirrored SPAN ports, optical TAPs, or physical interfaces.',
      spec: '1 Gbps+ line rate, zero packet interception',
    },
    {
      id: 2,
      shortName: 'PASSIVE CAPTURE',
      title: 'Passive Capture',
      icon: Radio,
      tag: 'Npcap / Scapy Sniffer',
      desc: 'Asynchronous kernel-level ring buffer captures packet headers without transmitting a single probe.',
      spec: 'Strict read-only permissions, zero injection',
    },
    {
      id: 3,
      shortName: 'FLOW EXTRACTION',
      title: 'Flow Extraction',
      icon: Layers,
      tag: 'Temporal 5-Tuple',
      desc: 'Correlates source IP/port, destination IP/port, and protocol into bidirectional micro-flows.',
      spec: 'Active timeout: 120s | Idle timeout: 15s',
    },
    {
      id: 4,
      shortName: 'FEATURE ENGINE',
      title: 'Feature Engine',
      icon: Binary,
      tag: 'Behavioral Metrics',
      desc: 'Computes inter-arrival time (IAT), packet size entropy, byte asymmetry, and egress fan-out.',
      spec: '38 statistical features, NumPy vectorized',
    },
    {
      id: 5,
      shortName: 'DETECTION MODELS',
      title: 'Detection Models',
      icon: Cpu,
      tag: 'Calibrated ML',
      desc: 'Evaluates flows against trained behavioral models for DDoS, Botnet C2, and Recon anomalies.',
      spec: 'Calibrated Random Forest & Gradient Boosted',
    },
    {
      id: 6,
      shortName: 'ALERT ENGINE',
      title: 'Alert Engine',
      icon: BellRing,
      tag: 'Explainable Triage',
      desc: 'Synthesizes suspicious signals into contextual alerts with confidence bands and telemetry evidence.',
      spec: 'Confidence tiers: Low / Med / High / Critical',
    },
    {
      id: 7,
      shortName: 'SECURITY DASHBOARD',
      title: 'Security Dashboard',
      icon: LayoutDashboard,
      tag: 'Analyst Interface',
      desc: 'Delivers real-time threat intelligence and flow telemetry via FastAPI and interactive charts.',
      spec: 'Sub-50ms query latency, PostgreSQL backed',
    },
  ];

  // Auto progression for demonstration of live pipeline flow
  useEffect(() => {
    if (!autoPlay) return;
    const interval = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % pipelineSteps.length);
    }, 3200);
    return () => clearInterval(interval);
  }, [autoPlay, pipelineSteps.length]);

  return (
    <section id="how-it-works" className="py-24 md:py-32 relative bg-[#0B0B35]/60 border-t border-[#242452]/70">
      {/* Background illumination */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-[#A8F500]/5 blur-[140px] pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
            PIPELINE ARCHITECTURE
          </div>
          <h2 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight leading-tight">
            FROM TRAFFIC TO<br />
            <span className="text-[#A8F500]">THREAT DETECTION</span>
          </h2>
          <p className="mt-4 text-base sm:text-lg text-[#A5A5BE] font-sans">
            Seven continuous pipeline stages transforming raw wire packets into explainable incident triage.
          </p>
        </div>

        {/* Desktop Pipeline (Horizontal with Progressive Connector) */}
        <div className="hidden lg:block mb-12">
          {/* Connecting Line Track */}
          <div className="relative mb-6">
            <div className="absolute top-1/2 left-6 right-6 -translate-y-1/2 h-0.5 bg-[#242452]" />
            {/* Active Lime Progress Bar */}
            <div
              className="absolute top-1/2 left-6 -translate-y-1/2 h-0.5 bg-[#A8F500] transition-all duration-700 shadow-[0_0_12px_rgba(168,245,0,0.8)]"
              style={{
                width: `${(activeStep / (pipelineSteps.length - 1)) * 92}%`,
              }}
            />

            {/* Step Nodes Row */}
            <div className="relative flex justify-between items-center">
              {pipelineSteps.map((step, index) => {
                const Icon = step.icon;
                const isActive = activeStep === index;
                const isPassed = activeStep >= index;

                return (
                  <button
                    key={step.id}
                    onClick={() => {
                      setAutoPlay(false);
                      setActiveStep(index);
                    }}
                    className="group flex flex-col items-center focus:outline-none cursor-pointer"
                  >
                    <div
                      className={`w-13 h-13 rounded-2xl flex items-center justify-center transition-all duration-300 relative z-10 ${
                        isActive
                          ? 'bg-[#A8F500] text-[#07072B] shadow-lg shadow-[#A8F500]/30 scale-110 border-2 border-[#B7FF19]'
                          : isPassed
                          ? 'bg-[#15154A] text-[#A8F500] border border-[#A8F500]/60'
                          : 'bg-[#10103D] text-[#A5A5BE] border border-[#242452] group-hover:border-[#A5A5BE]/60'
                      }`}
                    >
                      <Icon className="w-5 h-5" />
                      {isActive && (
                        <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-[#07072B] border-2 border-[#A8F500]" />
                      )}
                    </div>

                    <div className="mt-3 text-center">
                      <span
                        className={`text-[11px] font-mono tracking-tight font-semibold block transition-colors ${
                          isActive
                            ? 'text-[#A8F500]'
                            : isPassed
                            ? 'text-[#F5F5F7]'
                            : 'text-[#A5A5BE]'
                        }`}
                      >
                        {step.shortName}
                      </span>
                      <span className="text-[10px] text-[#A5A5BE]/60 font-mono">
                        0{step.id}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Selected Stage Detail Panel */}
        <div className="rounded-2xl bg-[#10103D] border border-[#242452] p-6 sm:p-8 md:p-10 shadow-2xl relative overflow-hidden backdrop-blur-md">
          <div className="absolute top-0 right-0 w-80 h-80 bg-[#A8F500]/5 rounded-full blur-3xl pointer-events-none" />

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            {/* Left Stage Details */}
            <div className="lg:col-span-7">
              <div className="flex items-center gap-3 mb-4">
                <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-[#A8F500]/15 text-[#A8F500] border border-[#A8F500]/30">
                  STAGE 0{pipelineSteps[activeStep].id} OF 07
                </span>
                <span className="text-xs font-mono text-[#39D7FF]">
                  {pipelineSteps[activeStep].tag}
                </span>
              </div>

              <h3 className="font-heading font-extrabold text-2xl sm:text-3xl md:text-4xl text-[#F5F5F7] tracking-tight mb-4">
                {pipelineSteps[activeStep].title}
              </h3>

              <p className="text-base sm:text-lg text-[#A5A5BE] leading-relaxed mb-6 font-sans">
                {pipelineSteps[activeStep].desc}
              </p>

              <div className="p-4 rounded-xl bg-[#07072B]/80 border border-[#242452] flex items-center gap-3 text-xs sm:text-sm font-mono text-[#F5F5F7]">
                <Info className="w-4 h-4 text-[#A8F500] shrink-0" />
                <span>
                  <strong className="text-[#A8F500]">Operational Spec:</strong>{' '}
                  {pipelineSteps[activeStep].spec}
                </span>
              </div>
            </div>

            {/* Right Interactive Telemetry Preview Box */}
            <div className="lg:col-span-5">
              <div className="rounded-xl bg-[#07072B] border border-[#242452] p-5 font-mono text-xs space-y-3 shadow-inner">
                <div className="flex items-center justify-between text-[#A5A5BE] border-b border-[#242452] pb-2">
                  <span className="flex items-center gap-1.5 text-[#A8F500]">
                    <span className="w-2 h-2 rounded-full bg-[#A8F500] animate-pulse" />
                    STAGE_TELEMETRY::INSPECT
                  </span>
                  <span>STATUS: HEALTHY</span>
                </div>

                <div className="space-y-1.5 text-[#F5F5F7]/90 text-[11px] leading-relaxed">
                  <div>
                    <span className="text-[#A5A5BE]">layer_input: </span>
                    <span className="text-[#39D7FF]">
                      {activeStep === 0
                        ? 'IEEE 802.3 Ethernet Frames'
                        : activeStep === 1
                        ? 'Raw PCAP Ringbuffer'
                        : activeStep === 2
                        ? 'IP Flow 5-Tuple Key'
                        : activeStep === 3
                        ? 'Time-Series Float64 Vectors'
                        : activeStep === 4
                        ? 'Calibrated Ensemble Probability'
                        : activeStep === 5
                        ? 'Structured JSON Alert Model'
                        : 'REST API & WebSockets'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#A5A5BE]">execution_mode: </span>
                    <span className="text-[#A8F500]">NON_BLOCKING_ASYNC</span>
                  </div>
                  <div>
                    <span className="text-[#A5A5BE]">packet_mutation: </span>
                    <span className="text-[#7DDB52]">STRICTLY_NONE (0%)</span>
                  </div>
                  <div>
                    <span className="text-[#A5A5BE]">latency_overhead: </span>
                    <span className="text-[#F5F5F7]">
                      {activeStep < 4 ? '< 2.4 ms' : activeStep === 4 ? '16.8 ms' : '< 1.1 ms'}
                    </span>
                  </div>
                </div>

                {/* Scrubber Navigation Buttons */}
                <div className="pt-3 border-t border-[#242452] flex items-center justify-between">
                  <button
                    onClick={() => {
                      setAutoPlay(false);
                      setActiveStep((prev) => (prev > 0 ? prev - 1 : pipelineSteps.length - 1));
                    }}
                    className="text-[11px] text-[#A5A5BE] hover:text-[#F5F5F7] px-2.5 py-1 rounded bg-[#10103D] border border-[#242452]"
                  >
                    ← Previous
                  </button>
                  <button
                    onClick={() => setAutoPlay(!autoPlay)}
                    className="text-[10px] text-[#A8F500] hover:underline"
                  >
                    {autoPlay ? 'Pause Auto-Progression' : 'Resume Auto-Progression'}
                  </button>
                  <button
                    onClick={() => {
                      setAutoPlay(false);
                      setActiveStep((prev) => (prev + 1) % pipelineSteps.length);
                    }}
                    className="text-[11px] text-[#A8F500] hover:text-[#B7FF19] px-2.5 py-1 rounded bg-[#10103D] border border-[#242452]"
                  >
                    Next →
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Mobile Vertical Pipeline */}
        <div className="block lg:hidden mt-8 space-y-3">
          {pipelineSteps.map((step, idx) => {
            const Icon = step.icon;
            const isSelected = activeStep === idx;
            return (
              <button
                key={step.id}
                onClick={() => {
                  setAutoPlay(false);
                  setActiveStep(idx);
                }}
                className={`w-full text-left p-4 rounded-xl border transition-all flex items-center justify-between ${
                  isSelected
                    ? 'bg-[#15154A] border-[#A8F500] text-[#F5F5F7]'
                    : 'bg-[#10103D]/60 border-[#242452] text-[#A5A5BE]'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                      isSelected
                        ? 'bg-[#A8F500] text-[#07072B]'
                        : 'bg-[#07072B] text-[#A5A5BE]'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-mono font-bold">
                      0{step.id} • {step.shortName}
                    </div>
                    <div className="text-[11px] text-[#A5A5BE]">{step.tag}</div>
                  </div>
                </div>
                <ChevronRight
                  className={`w-4 h-4 ${
                    isSelected ? 'text-[#A8F500]' : 'text-[#242452]'
                  }`}
                />
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
};
