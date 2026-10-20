import React, { useState, useMemo } from 'react';

export interface DonutSegment {
  label: string;
  count: number;
  color: string;
  category: string;
}

interface DonutChartProps {
  segments: DonutSegment[];
  totalLabel?: string;
  title?: string;
}

export const DonutChart: React.FC<DonutChartProps> = ({
  segments,
  totalLabel = "Total Threats",
  title = "Threat Category Distribution"
}) => {
  const [hoveredCategory, setHoveredCategory] = useState<string | null>(null);

  const total = segments.reduce((sum, s) => sum + s.count, 0);

  const size = 180;
  const strokeWidth = 24;
  const radius = (size - strokeWidth) / 2;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;

  const slices = useMemo(() => {
    const result: (DonutSegment & { strokeDasharray: string; strokeDashoffset: number })[] = [];
    let accumulatedOffset = 0;
    for (const seg of segments) {
      const fraction = total > 0 ? seg.count / total : 0;
      const strokeDasharray = `${fraction * circumference} ${circumference}`;
      const strokeDashoffset = -accumulatedOffset;
      accumulatedOffset += fraction * circumference;
      result.push({
        ...seg,
        strokeDasharray,
        strokeDashoffset
      });
    }
    return result;
  }, [segments, total, circumference]);

  return (
    <div className="w-full bg-[#10103D]/60 border border-[#242452] rounded-xl p-4 sm:p-5 flex flex-col justify-between">
      <div className="mb-4">
        <h4 className="text-sm font-heading font-semibold text-[#F5F5F7] flex items-center justify-between">
          <span>{title}</span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#242452] text-[#A5A5BE]">
            Categorical
          </span>
        </h4>
        <p className="text-[11px] text-[#A5A5BE]">
          Classification breakdown across detection pipeline modules
        </p>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-center sm:justify-between gap-6">
        {/* SVG Donut */}
        <div className="relative w-[180px] h-[180px] shrink-0 flex items-center justify-center">
          <svg width={size} height={size} className="transform -rotate-90">
            {/* Background ring */}
            <circle
              cx={center}
              cy={center}
              r={radius}
              fill="transparent"
              stroke="#242452"
              strokeWidth={strokeWidth}
              strokeOpacity="0.4"
            />

            {/* Slices */}
            {slices.map((seg) => {
              const isHovered = hoveredCategory === seg.category;

              return (
                <circle
                  key={seg.category}
                  cx={center}
                  cy={center}
                  r={radius}
                  fill="transparent"
                  stroke={seg.color}
                  strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                  strokeDasharray={seg.strokeDasharray}
                  strokeDashoffset={seg.strokeDashoffset}
                  className="transition-all duration-300 cursor-pointer"
                  onMouseEnter={() => setHoveredCategory(seg.category)}
                  onMouseLeave={() => setHoveredCategory(null)}
                />
              );
            })}
          </svg>

          {/* Center text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
            <span className="text-2xl font-heading font-extrabold text-[#F5F5F7]">
              {total}
            </span>
            <span className="text-[10px] font-mono text-[#A5A5BE] uppercase tracking-wider">
              {totalLabel}
            </span>
          </div>
        </div>

        {/* Legend */}
        <div className="flex-grow space-y-2 w-full sm:w-auto">
          {segments.map((seg) => {
            const pct = total > 0 ? Math.round((seg.count / total) * 100) : 0;
            const isHovered = hoveredCategory === seg.category;

            return (
              <div
                key={seg.category}
                onMouseEnter={() => setHoveredCategory(seg.category)}
                onMouseLeave={() => setHoveredCategory(null)}
                className={`flex items-center justify-between p-2 rounded-lg transition-colors cursor-pointer text-xs font-mono ${
                  isHovered ? 'bg-[#15154A] border border-[#242452]' : 'hover:bg-[#15154A]/40'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: seg.color }}
                  />
                  <span className={isHovered ? 'text-[#F5F5F7] font-semibold' : 'text-[#A5A5BE]'}>
                    {seg.label}
                  </span>
                </div>
                <div className="flex items-center gap-2 font-mono">
                  <span className="text-[#F5F5F7] font-bold">{seg.count}</span>
                  <span className="text-[10px] text-[#A5A5BE] w-8 text-right">({pct}%)</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
