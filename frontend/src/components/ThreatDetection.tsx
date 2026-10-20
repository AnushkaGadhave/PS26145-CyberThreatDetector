import React from 'react';
import {
  Zap,
  Bot,
  Radar,
  Globe2,
  FileCode,
  UploadCloud,
  CheckCircle
} from 'lucide-react';

export const ThreatDetection: React.FC = () => {
  const threats = [
    {
      id: '01',
      title: 'DDoS',
      tagline: 'Volumetric and protocol-based abnormal traffic.',
      status: 'ACTIVE',
      statusColor: 'lime',
      icon: Zap,
      features: [
        'Forward & backward packet asymmetry',
        'Burst rate and PPS amplification surges',
        'TCP SYN/ACK state machine imbalance',
      ],
      metrics: 'Calibrated Random Forest • Low False Alarm Rate',
    },
    {
      id: '02',
      title: 'Botnet C2',
      tagline: 'Beaconing and repeated communication behavior.',
      status: 'ACTIVE',
      statusColor: 'lime',
      icon: Bot,
      features: [
        'Inter-arrival time (IAT) periodicity clustering',
        'Persistent egress communication heartbeats',
        'High destination repeat ratio over 60s windows',
      ],
      metrics: 'Multi-flow aggregation • High Precision (91%+)',
    },
    {
      id: '03',
      title: 'Recon / Port Scan',
      tagline: 'Source fan-out and destination-port activity.',
      status: 'ACTIVE',
      statusColor: 'lime',
      icon: Radar,
      features: [
        'Rapid target destination-port fan-out',
        'SYN-without-ACK or anomalous TCP flag ratios',
        'Single-flow anomaly thresholding',
      ],
      metrics: 'Heuristic & Anomaly Scoring • Early Recon Phase',
    },
    {
      id: '04',
      title: 'DGA / DNS Tunnelling',
      tagline: 'DNS behavior and suspicious query characteristics.',
      status: 'IN DEVELOPMENT',
      statusColor: 'muted',
      icon: Globe2,
      features: [
        'Domain entropy and consonant-vowel distribution',
        'Anomalous TXT / NULL record request volumes',
        'NXDOMAIN response spike monitoring',
      ],
      metrics: 'Model Pipeline Integration in Progress',
    },
    {
      id: '05',
      title: 'Encrypted Malware',
      tagline: 'Metadata-based analysis without payload decryption.',
      status: 'IN DEVELOPMENT',
      statusColor: 'muted',
      icon: FileCode,
      features: [
        'TLS ClientHello cipher-suite fingerprinting',
        'Initial packet length sequences (SPLT)',
        'Timing jitter during handshake exchange',
      ],
      metrics: 'Dataset Benchmarking & Model Training',
    },
    {
      id: '06',
      title: 'Data Exfiltration',
      tagline: 'Unusual outbound flow-volume behavior.',
      status: 'IN DEVELOPMENT',
      statusColor: 'muted',
      icon: UploadCloud,
      features: [
        'High outbound to inbound byte asymmetry',
        'Off-hours staging and sustained egress transfer',
        'Unusual destination ASN flow accumulation',
      ],
      metrics: 'Baseline Profile Evaluation in Progress',
    },
  ];

  return (
    <section id="threat-detection" className="py-24 md:py-32 relative bg-[#07072B] border-t border-[#242452]/70">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-4">
            <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
            THREAT RADAR
          </div>
          <h2 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight leading-tight">
            DETECTION ACROSS<br />
            <span className="text-[#39D7FF]">MULTIPLE THREAT SIGNALS</span>
          </h2>
          <p className="mt-4 text-base sm:text-lg text-[#A5A5BE] font-sans">
            Specialized detectors targeting distinct attack vectors across flow topologies, with transparent operational status.
          </p>
        </div>

        {/* 6 Visually Consistent Threat Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8">
          {threats.map((threat) => {
            const Icon = threat.icon;
            const isActive = threat.status === 'ACTIVE';

            return (
              <div
                key={threat.id}
                className="group relative rounded-2xl bg-[#10103D]/70 hover:bg-[#15154A] border border-[#242452] hover:border-[#39D7FF]/40 p-7 sm:p-8 transition-all duration-300 flex flex-col justify-between shadow-lg hover:shadow-xl"
              >
                {/* Top Row: Identifier, Status Badge, Icon */}
                <div>
                  <div className="flex items-center justify-between mb-6">
                    <span className="text-xs font-mono font-bold text-[#A5A5BE]/60 tracking-wider">
                      {threat.id}
                    </span>

                    {/* Truthful Operational Status Badge */}
                    <div
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono font-semibold tracking-wider ${
                        isActive
                          ? 'bg-[#A8F500]/15 text-[#A8F500] border border-[#A8F500]/30 shadow-[0_0_10px_rgba(168,245,0,0.2)]'
                          : 'bg-[#4C8DFF]/10 text-[#4C8DFF] border border-[#4C8DFF]/25'
                      }`}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          isActive ? 'bg-[#A8F500] animate-pulse' : 'bg-[#4C8DFF]'
                        }`}
                      />
                      {threat.status}
                    </div>

                    <div className="w-10 h-10 rounded-xl bg-[#07072B] border border-[#242452] flex items-center justify-center group-hover:border-[#39D7FF]/30 transition-colors">
                      <Icon
                        className={`w-5 h-5 ${
                          isActive ? 'text-[#A8F500]' : 'text-[#4C8DFF]'
                        }`}
                      />
                    </div>
                  </div>

                  {/* Threat Title & Tagline */}
                  <h3 className="font-heading font-extrabold text-2xl text-[#F5F5F7] tracking-tight mb-2">
                    {threat.title}
                  </h3>
                  <p className="text-sm text-[#A5A5BE] font-sans leading-relaxed mb-6">
                    {threat.tagline}
                  </p>

                  {/* Feature Checkpoints */}
                  <ul className="space-y-2.5 mb-6">
                    {threat.features.map((feat, idx) => (
                      <li
                        key={idx}
                        className="text-xs text-[#F5F5F7]/80 flex items-start gap-2.5 leading-snug"
                      >
                        <span
                          className={`w-1 h-1 rounded-full mt-1.5 shrink-0 ${
                            isActive ? 'bg-[#A8F500]' : 'bg-[#4C8DFF]'
                          }`}
                        />
                        <span>{feat}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Bottom Operational Footnote */}
                <div className="pt-4 border-t border-[#242452]/80 flex items-center justify-between text-[11px] font-mono text-[#A5A5BE]">
                  <span>{threat.metrics}</span>
                  {isActive ? (
                    <span className="text-[#A8F500] font-semibold">Ready</span>
                  ) : (
                    <span className="text-[#4C8DFF]">Roadmap</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Status Disclaimer Notice */}
        <div className="mt-12 p-4 rounded-xl bg-[#10103D]/50 border border-[#242452] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-[#A5A5BE]">
          <div className="flex items-center gap-2.5">
            <CheckCircle className="w-4 h-4 text-[#A8F500] shrink-0" />
            <span>
              <strong className="text-[#F5F5F7]">Production Provenance:</strong> DDoS, Botnet C2, and Recon / Port Scan detectors are fully integrated with calibrated inference in the active engine.
            </span>
          </div>
          <span className="font-mono text-[11px] text-[#A5A5BE]/70 shrink-0">
            DGA, Malware & Exfil in active laboratory development
          </span>
        </div>
      </div>
    </section>
  );
};
