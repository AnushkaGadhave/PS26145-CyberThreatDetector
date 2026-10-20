import React from 'react';
import type { Severity } from '../../../types/telemetry';

interface SeverityBarProps {
  distribution: Record<Severity, number>;
}

export const SeverityBar: React.FC<SeverityBarProps> = ({ distribution }) => {
  const severities: { key: Severity; label: string; color: string; badge: string }[] = [
    { key: 'CRITICAL', label: 'Critical', color: '#FF4D5A', badge: 'bg-[#FF4D5A]/15 text-[#FF4D5A] border-[#FF4D5A]/30' },
    { key: 'HIGH', label: 'High', color: '#FF8A3D', badge: 'bg-[#FF8A3D]/15 text-[#FF8A3D] border-[#FF8A3D]/30' },
    { key: 'MEDIUM', label: 'Medium', color: '#F7B84B', badge: 'bg-[#F7B84B]/15 text-[#F7B84B] border-[#F7B84B]/30' },
    { key: 'LOW', label: 'Low', color: '#39D7FF', badge: 'bg-[#39D7FF]/15 text-[#39D7FF] border-[#39D7FF]/30' },
    { key: 'BENIGN', label: 'Benign', color: '#7DDB52', badge: 'bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/30' },
  ];

  const total = Object.values(distribution).reduce((a, b) => a + b, 0);

  return (
    <div className="w-full bg-[#10103D]/60 border border-[#242452] rounded-xl p-4 sm:p-5 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h4 className="text-sm font-heading font-semibold text-[#F5F5F7]">
            Alert Severity Breakdown
          </h4>
          <p className="text-[11px] text-[#A5A5BE]">
            Triage distribution across five operational severity bands
          </p>
        </div>
        <span className="text-xs font-mono text-[#A8F500]">
          {distribution.CRITICAL + distribution.HIGH} Actionable
        </span>
      </div>

      {/* Progress Multi-Bar */}
      <div className="w-full h-3 rounded-full bg-[#07072B] border border-[#242452] overflow-hidden flex mb-4">
        {severities.map((sev) => {
          const count = distribution[sev.key] || 0;
          const widthPct = total > 0 ? (count / total) * 100 : 0;
          if (widthPct === 0) return null;

          return (
            <div
              key={sev.key}
              style={{ width: `${widthPct}%`, backgroundColor: sev.color }}
              title={`${sev.label}: ${count} (${Math.round(widthPct)}%)`}
              className="h-full transition-all duration-300 relative group"
            />
          );
        })}
      </div>

      {/* Badges Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
        {severities.map((sev) => {
          const count = distribution[sev.key] || 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;

          return (
            <div
              key={sev.key}
              className={`p-2.5 rounded-lg border flex flex-col items-start justify-between font-mono ${sev.badge}`}
            >
              <div className="flex items-center justify-between w-full text-[11px]">
                <span className="font-bold">{sev.label}</span>
                <span className="text-[10px] opacity-80">{pct}%</span>
              </div>
              <span className="text-lg font-heading font-extrabold mt-1">
                {count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
