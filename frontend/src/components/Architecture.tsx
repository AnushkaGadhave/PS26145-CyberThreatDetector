import React, { useState } from 'react';
import { ArrowRight } from 'lucide-react';


export const Architecture: React.FC = () => {
  const [activeNode, setActiveNode] = useState<number | null>(null);

  const architectureNodes = [
    {
      id: 0,
      title: 'LIVE TRAFFIC',
      role: 'Ingestion Source',
      tech: '802.3 Ethernet / 802.11 Wi-Fi',
      desc: 'High-speed physical frames traversing passive optical TAP or mirrored network switch port.',
      badge: 'Unidirectional / In-Wire',
      layer: 'Layer 1 / 2 Wire',
    },
    {
      id: 1,
      title: 'NPCAP / SENSOR',
      role: 'Passive Kernel Sniffer',
      tech: 'Npcap Driver & Scapy AsyncSniffer',
      desc: 'Captures raw frames from interface buffer in non-promiscuous, strictly read-only mode without dropping packets.',
      badge: '0 Packet Injections',
      layer: 'Kernel Telemetry',
    },
    {
      id: 2,
      title: 'FLOW BUILDER',
      role: 'Temporal Aggregator',
      tech: 'Python 5-Tuple Engine',
      desc: 'Correlates forward and backward packets into bidirectional flow records using active (120s) and idle (15s) expiry.',
      badge: 'TCP / UDP / ICMP Flows',
      layer: 'Flow Assembly',
    },
    {
      id: 3,
      title: 'FEATURE ENGINE',
      role: 'Behavioral Extraction',
      tech: 'NumPy Vectorized Pipeline',
      desc: 'Extracts 38 statistical metrics including Inter-Arrival Time (IAT) variance, packet length entropy, and flow asymmetry.',
      badge: 'Zero Payload Inspection',
      layer: 'Mathematical Profiling',
    },
    {
      id: 4,
      title: 'THREAT DETECTION',
      role: 'Calibrated Inference',
      tech: 'Scikit-Learn ML Classifiers',
      desc: 'Runs calibrated behavioral detectors for DDoS, Botnet C2 beaconing, and PortScan fan-out activity.',
      badge: 'Probabilistic Scoring',
      layer: 'Anomaly Detection',
    },
    {
      id: 5,
      title: 'ALERT ENGINE',
      role: 'Triage & Evidence Synthesis',
      tech: 'Rule & Evidence Pipeline',
      desc: 'Combines multi-threat probabilities into explainable security alerts, attaching telemetry evidence and confidence bands.',
      badge: 'Low / Med / High / Critical',
      layer: 'Security Triage',
    },
    {
      id: 6,
      title: 'POSTGRESQL',
      role: 'Relational Store',
      tech: 'PostgreSQL 16 & SQLAlchemy ORM',
      desc: 'Stores normalized flow records, generated threat alerts, and detector compatibility metrics with optimized btree indexes.',
      badge: 'Zero Payload Stored',
      layer: 'Relational Persistence',
    },
    {
      id: 7,
      title: 'FASTAPI',
      role: 'REST API & Distribution',
      tech: 'FastAPI & Uvicorn ASGI Server',
      desc: 'Exposes paginated query endpoints, CORS handling, Pydantic data schemas, and OpenAPI interactive documentation.',
      badge: 'Port 8000 REST Engine',
      layer: 'Distribution Gateway',
    },
    {
      id: 8,
      title: 'DASHBOARD',
      role: 'Analyst Interface',
      tech: 'React 19, TypeScript, Tailwind CSS',
      desc: 'Real-time security operations console displaying flow metrics, alert queues, evidence drill-downs, and telemetry charts.',
      badge: 'Port 5173 Client App',
      layer: 'Operator Console',
    },
  ];

  return (
    <section id="architecture" className="py-24 md:py-32 relative bg-[#0B0B35]/70 border-t border-[#242452]/70">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
            SYSTEM SPECIFICATION
          </div>
          <h2 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight leading-tight">
            BUILT FOR PASSIVE<br />
            <span className="text-[#A8F500]">NETWORK MONITORING</span>
          </h2>
          <p className="mt-4 text-base sm:text-lg text-[#A5A5BE] font-sans">
            End-to-end implementation architecture for SIH Problem Statement 26145 from physical packet capture to operator dashboard.
          </p>
        </div>

        {/* Elegant Connected Flow Pipeline Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
          {architectureNodes.map((node, index) => {
            const isSelected = activeNode === index;
            const isLast = index === architectureNodes.length - 1;

            return (
              <div
                key={node.id}
                onClick={() => setActiveNode(isSelected ? null : index)}
                className={`relative rounded-2xl p-6 sm:p-7 border transition-all duration-300 cursor-pointer flex flex-col justify-between group ${
                  isSelected
                    ? 'bg-[#15154A] border-[#A8F500] shadow-xl shadow-[#A8F500]/10 scale-[1.02]'
                    : 'bg-[#10103D]/70 hover:bg-[#15154A] border-[#242452] hover:border-[#39D7FF]/40'
                }`}
              >
                <div>
                  {/* Top metadata */}
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-[11px] font-mono font-bold text-[#A5A5BE]/60 tracking-wider">
                      STEP 0{index + 1}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#07072B] border border-[#242452] text-[#39D7FF]">
                      {node.layer}
                    </span>
                  </div>

                  {/* Title */}
                  <h3 className="font-heading font-extrabold text-xl text-[#F5F5F7] group-hover:text-[#A8F500] transition-colors mb-1 tracking-tight">
                    {node.title}
                  </h3>
                  <div className="text-xs font-semibold text-[#A8F500] font-sans mb-3">
                    {node.role}
                  </div>

                  {/* Description */}
                  <p className="text-xs sm:text-sm text-[#A5A5BE] leading-relaxed font-sans mb-5">
                    {node.desc}
                  </p>
                </div>

                {/* Bottom Tech Stack & Tag */}
                <div className="pt-4 border-t border-[#242452]/80 flex items-center justify-between text-xs font-mono">
                  <span className="text-[#F5F5F7]/80 truncate mr-2">
                    {node.tech}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#A8F500]/10 text-[#A8F500] text-[10px] shrink-0 border border-[#A8F500]/25">
                    {node.badge}
                  </span>
                </div>

                {/* Subtle sequence indicator arrow */}
                {!isLast && (
                  <div className="hidden lg:block absolute -right-3 top-1/2 -translate-y-1/2 z-20 pointer-events-none opacity-40 group-hover:opacity-100 group-hover:text-[#A8F500] transition-all">
                    {(index + 1) % 3 !== 0 && (
                      <ArrowRight className="w-5 h-5 text-[#242452]" />
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Real Codebase Tech Verification Footnote */}
        <div className="mt-12 rounded-xl bg-[#07072B] border border-[#242452] p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono text-[#A5A5BE]">
          <div className="flex items-center gap-3">
            <div className="w-2.5 h-2.5 rounded-full bg-[#A8F500] animate-pulse" />
            <span>
              <strong className="text-[#F5F5F7]">Repository Structure:</strong> Scapy sniffer in <code className="text-[#A8F500]">src/capture</code>, Flow & Feature extractor in <code className="text-[#A8F500]">src/features</code>, Detectors in <code className="text-[#A8F500]">src/detection</code>, FastAPI backend in <code className="text-[#A8F500]">src/api</code>
            </span>
          </div>
          <span className="text-[#7DDB52] shrink-0">
            STRICT ZERO PAYLOAD DECRYPTION
          </span>
        </div>
      </div>
    </section>
  );
};
