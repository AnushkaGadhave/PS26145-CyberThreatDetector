import React from 'react';
import {
  ArrowRight,
  Activity,
  AlertTriangle,
  Radio
} from 'lucide-react';

interface ProductPreviewProps {
  onNavigate: (route: string) => void;
}

export const ProductPreview: React.FC<ProductPreviewProps> = ({ onNavigate }) => {
  const alertsPreview = [
    {
      id: '#ALT-9402',
      threat: 'BOTNET_C2',
      severity: 'HIGH',
      sevColor: 'text-[#FF8A3D] bg-[#FF8A3D]/15 border-[#FF8A3D]/30',
      src: '192.168.1.104',
      dst: '198.51.100.44:443',
      confidence: '91%',
      time: '14:28:10 UTC',
      evidence: 'IAT Regularity 0.94 • 18 Flows/60s',
    },
    {
      id: '#ALT-9401',
      threat: 'DDOS_SYN_FLOOD',
      severity: 'HIGH',
      sevColor: 'text-[#FF8A3D] bg-[#FF8A3D]/15 border-[#FF8A3D]/30',
      src: '10.0.4.88',
      dst: '192.168.1.1:80',
      confidence: '88%',
      time: '14:27:44 UTC',
      evidence: 'Forward/Backward packet ratio skew 24.1',
    },
    {
      id: '#ALT-9399',
      threat: 'RECON_PORTSCAN',
      severity: 'MEDIUM',
      sevColor: 'text-[#F7B84B] bg-[#F7B84B]/15 border-[#F7B84B]/30',
      src: '172.16.0.42',
      dst: '192.168.1.15 [Multi-Port]',
      confidence: '79%',
      time: '14:25:02 UTC',
      evidence: 'Destination port fan-out count: 64 ports',
    },
  ];

  return (
    <section className="py-24 md:py-32 relative bg-[#07072B] border-t border-[#242452]/70 overflow-hidden">
      {/* Background ambient lighting */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-[#A8F500]/5 blur-[160px] pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-14 sm:mb-18">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A8F500] mb-4">
            <Radio className="w-3.5 h-3.5 text-[#A8F500]" />
            LIVE ANALYST CONSOLE
          </div>
          <h2 className="font-heading font-extrabold text-3xl sm:text-4xl md:text-5xl text-[#F5F5F7] tracking-tight leading-tight">
            THE REAL-TIME<br />
            <span className="text-[#39D7FF]">MONITORING INTERFACE</span>
          </h2>
          <p className="mt-4 text-base sm:text-lg text-[#A5A5BE] font-sans">
            A high-density operational cockpit built for security analysts to observe temporal flow rates, triage incoming alerts, and verify explainable model evidence.
          </p>
        </div>

        {/* Big Dashboard Showcase Panel */}
        <div className="rounded-2xl sm:rounded-3xl bg-[#10103D] border border-[#242452] shadow-2xl p-4 sm:p-7 md:p-9 relative group backdrop-blur-xl">
          {/* Top Bar with Live Badge & Quick Action */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#242452] gap-4">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-[#A8F500] animate-ping-dot" />
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-heading font-bold text-lg text-[#F5F5F7]">
                    NETRA Security Operations Center
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#A8F500]/15 text-[#A8F500] border border-[#A8F500]/30">
                    CONSOLE PREVIEW
                  </span>
                </div>
                <span className="text-xs font-mono text-[#A5A5BE]">
                  Capture Mode: PASSIVE_TAP (Unidirectional) • Backend: FastAPI :8000
                </span>
              </div>
            </div>

            <button
              onClick={() => onNavigate('/dashboard')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-all duration-200 shadow hover:shadow-[#A8F500]/25 cursor-pointer self-start sm:self-auto"
            >
              <span>OPEN MONITORING DASHBOARD</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* KPI Summary Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 py-6 border-b border-[#242452]">
            <div className="p-4 rounded-xl bg-[#07072B]/70 border border-[#242452]">
              <div className="text-[11px] font-mono text-[#A5A5BE] uppercase mb-1">
                Monitored Flows (60m)
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-heading font-extrabold text-2xl sm:text-3xl text-[#F5F5F7]">
                  18,492
                </span>
                <span className="text-[11px] font-mono text-[#7DDB52] font-semibold">
                  +14.2%
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#07072B]/70 border border-[#242452]">
              <div className="text-[11px] font-mono text-[#A5A5BE] uppercase mb-1">
                Active Alerts
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-heading font-extrabold text-2xl sm:text-3xl text-[#FF8A3D]">
                  8
                </span>
                <span className="text-[11px] font-mono text-[#FF8A3D]">
                  2 High Severity
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#07072B]/70 border border-[#242452]">
              <div className="text-[11px] font-mono text-[#A5A5BE] uppercase mb-1">
                Sensor Ingestion Rate
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-heading font-extrabold text-2xl sm:text-3xl text-[#39D7FF]">
                  1.42
                </span>
                <span className="text-[11px] font-mono text-[#39D7FF]">
                  MB/s Wire Rate
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#07072B]/70 border border-[#242452]">
              <div className="text-[11px] font-mono text-[#A5A5BE] uppercase mb-1">
                Inference Latency
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-heading font-extrabold text-2xl sm:text-3xl text-[#A8F500]">
                  16.8
                </span>
                <span className="text-[11px] font-mono text-[#A8F500]">
                  ms / Batch
                </span>
              </div>
            </div>
          </div>

          {/* Center Split: Network Activity Chart + Distribution & Status */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 py-6 border-b border-[#242452]">
            {/* Chart Area (8 cols) */}
            <div className="lg:col-span-8 p-5 rounded-xl bg-[#07072B]/70 border border-[#242452] flex flex-col justify-between">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#A8F500]" />
                  <span className="font-heading font-bold text-sm text-[#F5F5F7]">
                    Flow Packet Rate & Telemetry Activity
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs font-mono">
                  <span className="flex items-center gap-1.5 text-[#A8F500]">
                    <span className="w-2 h-2 rounded-full bg-[#A8F500]" />
                    Forward (pkts)
                  </span>
                  <span className="flex items-center gap-1.5 text-[#39D7FF]">
                    <span className="w-2 h-2 rounded-full bg-[#39D7FF]" />
                    Backward (pkts)
                  </span>
                </div>
              </div>

              {/* Chart SVG */}
              <div className="h-44 w-full relative flex items-end">
                <svg className="w-full h-full" viewBox="0 0 700 160" preserveAspectRatio="none">
                  <defs>
                    <linearGradient id="chartGradLime" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#A8F500" stopOpacity="0.25" />
                      <stop offset="100%" stopColor="#A8F500" stopOpacity="0.0" />
                    </linearGradient>
                  </defs>

                  {/* Grid lines */}
                  <line x1="0" y1="40" x2="700" y2="40" stroke="#242452" strokeDasharray="3 3" />
                  <line x1="0" y1="80" x2="700" y2="80" stroke="#242452" strokeDasharray="3 3" />
                  <line x1="0" y1="120" x2="700" y2="120" stroke="#242452" strokeDasharray="3 3" />

                  {/* Filled Forward curve */}
                  <path
                    d="M 0 130 C 100 120, 150 90, 220 95 C 280 100, 330 40, 420 45 C 500 50, 560 20, 630 35 L 700 40 L 700 160 L 0 160 Z"
                    fill="url(#chartGradLime)"
                  />
                  <path
                    d="M 0 130 C 100 120, 150 90, 220 95 C 280 100, 330 40, 420 45 C 500 50, 560 20, 630 35 L 700 40"
                    fill="none"
                    stroke="#A8F500"
                    strokeWidth="2.5"
                  />

                  {/* Backward curve (Cyan) */}
                  <path
                    d="M 0 145 C 100 140, 180 130, 260 110 C 340 90, 430 85, 520 70 C 600 55, 650 65, 700 60"
                    fill="none"
                    stroke="#39D7FF"
                    strokeWidth="1.8"
                    strokeDasharray="4 4"
                  />

                  {/* High alert point */}
                  <circle cx="560" cy="20" r="5" fill="#FF8A3D" />
                  <circle cx="560" cy="20" r="9" fill="none" stroke="#FF8A3D" strokeWidth="1.5" className="animate-ping" />
                </svg>
              </div>

              <div className="flex justify-between text-[11px] font-mono text-[#A5A5BE] mt-2 pt-2 border-t border-[#242452]">
                <span>13:30 UTC</span>
                <span>13:45 UTC</span>
                <span>14:00 UTC</span>
                <span>14:15 UTC</span>
                <span className="text-[#A8F500]">LIVE (14:30 UTC)</span>
              </div>
            </div>

            {/* Threat Distribution & Model Status (4 cols) */}
            <div className="lg:col-span-4 space-y-4">
              {/* Distribution */}
              <div className="p-4 rounded-xl bg-[#07072B]/70 border border-[#242452]">
                <div className="text-xs font-mono text-[#A5A5BE] uppercase mb-3 flex items-center justify-between">
                  <span>Threat Class Distribution</span>
                  <span className="text-[#39D7FF]">3 Active Vectors</span>
                </div>
                <div className="space-y-2.5">
                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span className="text-[#F5F5F7]">DDoS (Volumetric)</span>
                      <span className="text-[#A8F500]">45%</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-[#10103D]">
                      <div className="h-full rounded-full bg-[#A8F500]" style={{ width: '45%' }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span className="text-[#F5F5F7]">Botnet C2 (Beaconing)</span>
                      <span className="text-[#FF8A3D]">35%</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-[#10103D]">
                      <div className="h-full rounded-full bg-[#FF8A3D]" style={{ width: '35%' }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-xs font-mono mb-1">
                      <span className="text-[#F5F5F7]">Recon / PortScan</span>
                      <span className="text-[#F7B84B]">20%</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-[#10103D]">
                      <div className="h-full rounded-full bg-[#F7B84B]" style={{ width: '20%' }} />
                    </div>
                  </div>
                </div>
              </div>

              {/* Model Status Card */}
              <div className="p-4 rounded-xl bg-[#07072B]/70 border border-[#242452]">
                <div className="text-xs font-mono text-[#A5A5BE] uppercase mb-2">
                  Engine Status & Provenance
                </div>
                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-[#A5A5BE]">DDoS Model</span>
                    <span className="text-[#7DDB52]">OPERATIONAL</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#A5A5BE]">Botnet C2 Model</span>
                    <span className="text-[#7DDB52]">OPERATIONAL</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#A5A5BE]">PortScan Model</span>
                    <span className="text-[#7DDB52]">OPERATIONAL</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#A5A5BE]">Payload Inspection</span>
                    <span className="text-[#A8F500]">STRICTLY DISABLED</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Alerts Table */}
          <div className="pt-6">
            <div className="flex items-center justify-between mb-4">
              <span className="font-heading font-bold text-sm text-[#F5F5F7] flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#FF8A3D]" />
                Recent Threat Alerts Queue
              </span>
              <span className="text-xs font-mono text-[#A5A5BE]">
                TOTAL QUEUED: 8
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-[#242452] text-[#A5A5BE]">
                    <th className="pb-3 font-normal">Alert ID</th>
                    <th className="pb-3 font-normal">Threat Class</th>
                    <th className="pb-3 font-normal">Severity</th>
                    <th className="pb-3 font-normal">Endpoints</th>
                    <th className="pb-3 font-normal">Confidence</th>
                    <th className="pb-3 font-normal">Time</th>
                    <th className="pb-3 font-normal text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#242452]/50 text-[#F5F5F7]">
                  {alertsPreview.map((alert) => (
                    <tr key={alert.id} className="hover:bg-[#15154A]/50 transition-colors">
                      <td className="py-3 text-[#A8F500] font-semibold">{alert.id}</td>
                      <td className="py-3 font-sans font-bold">{alert.threat}</td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${alert.sevColor}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 text-[#A5A5BE]">
                        {alert.src} → {alert.dst}
                      </td>
                      <td className="py-3 text-[#A8F500] font-bold">{alert.confidence}</td>
                      <td className="py-3 text-[#A5A5BE]">{alert.time}</td>
                      <td className="py-3 text-right">
                        <button
                          onClick={() => onNavigate('/dashboard')}
                          className="text-[#A8F500] hover:text-[#B7FF19] text-[11px] underline underline-offset-2"
                        >
                          View Evidence →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Bottom Callout Bar */}
          <div className="mt-8 pt-6 border-t border-[#242452] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <span className="text-xs text-[#A5A5BE]">
              Ready to explore live flows, alert queues, and system telemetry?
            </span>
            <button
              onClick={() => onNavigate('/dashboard')}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl font-semibold text-sm text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-all duration-200 shadow-md hover:shadow-[#A8F500]/25 cursor-pointer"
            >
              <span>OPEN MONITORING DASHBOARD</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};
