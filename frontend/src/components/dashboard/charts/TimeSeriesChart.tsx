import React, { useState } from 'react';

interface TimeSeriesPoint {
  time: string;
  flows: number;
  threats: number;
  pps: number;
}

interface TimeSeriesChartProps {
  data: TimeSeriesPoint[];
  title?: string;
}

export const TimeSeriesChart: React.FC<TimeSeriesChartProps> = ({
  data,
  title = "Traffic Velocity & Threat Surge Timeline"
}) => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  if (!data || data.length === 0) {
    return <div className="text-xs text-[#A5A5BE] p-4 text-center">No telemetry data available</div>;
  }

  const width = 700;
  const height = 220;
  const padding = { top: 20, right: 30, bottom: 35, left: 50 };

  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const maxFlows = Math.max(...data.map(d => d.flows), 100);
  const maxThreats = Math.max(...data.map(d => d.threats), 5);

  const getX = (index: number) => padding.left + (index / (data.length - 1)) * chartW;
  const getYFlows = (val: number) => padding.top + chartH - (val / maxFlows) * chartH;
  const getYThreats = (val: number) => padding.top + chartH - (val / maxThreats) * chartH;

  // Build SVG path for flow volume area and line
  const flowPoints = data.map((d, i) => `${getX(i)},${getYFlows(d.flows)}`);
  const flowAreaPath = `M ${getX(0)},${padding.top + chartH} ` +
    flowPoints.map((pt) => `L ${pt}`).join(' ') +
    ` L ${getX(data.length - 1)},${padding.top + chartH} Z`;
  const flowLinePath = `M ` + flowPoints.join(' L ');

  // Build SVG path for threats line
  const threatPoints = data.map((d, i) => `${getX(i)},${getYThreats(d.threats)}`);
  const threatLinePath = `M ` + threatPoints.join(' L ');

  const activePoint = hoveredIdx !== null ? data[hoveredIdx] : null;

  return (
    <div className="w-full bg-[#10103D]/60 border border-[#242452] rounded-xl p-4 sm:p-5 relative flex flex-col justify-between">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div>
          <h4 className="text-sm font-heading font-semibold text-[#F5F5F7] flex items-center gap-2">
            <span>{title}</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#242452]/80 text-[#39D7FF]">
              12 Ticks • UTC
            </span>
          </h4>
          <p className="text-[11px] text-[#A5A5BE]">
            Dual-axis normalized rates for observed IP flows vs. flagged threat anomalies
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#39D7FF]" />
            <span className="text-[#A5A5BE]">Flows / 5m</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-[#FF4D5A]" />
            <span className="text-[#A5A5BE]">Threat Events</span>
          </div>
        </div>
      </div>

      <div className="w-full overflow-x-auto">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-auto min-w-[500px]"
          onMouseLeave={() => setHoveredIdx(null)}
        >
          <defs>
            <linearGradient id="flowAreaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#39D7FF" stopOpacity="0.28" />
              <stop offset="100%" stopColor="#39D7FF" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="gridLineGradient" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#242452" stopOpacity="0.2" />
              <stop offset="100%" stopColor="#242452" stopOpacity="0.8" />
            </linearGradient>
          </defs>

          {/* Horizontal Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((pct, idx) => {
            const y = padding.top + chartH * (1 - pct);
            const flowVal = Math.round(maxFlows * pct);
            return (
              <g key={idx}>
                <line
                  x1={padding.left}
                  y1={y}
                  x2={width - padding.right}
                  y2={y}
                  stroke="#242452"
                  strokeDasharray="3 3"
                  strokeWidth="1"
                />
                <text
                  x={padding.left - 8}
                  y={y + 3}
                  textAnchor="end"
                  fill="#A5A5BE"
                  fontSize="9"
                  fontFamily="monospace"
                >
                  {flowVal}
                </text>
              </g>
            );
          })}

          {/* Area fill for Flows */}
          <path d={flowAreaPath} fill="url(#flowAreaGradient)" />

          {/* Line for Flows */}
          <path
            d={flowLinePath}
            fill="none"
            stroke="#39D7FF"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Line for Threats */}
          <path
            d={threatLinePath}
            fill="none"
            stroke="#FF4D5A"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Data Points and Interactivity */}
          {data.map((d, i) => {
            const cx = getX(i);
            const cyFlow = getYFlows(d.flows);
            const cyThreat = getYThreats(d.threats);
            const isHovered = hoveredIdx === i;

            return (
              <g key={i}>
                {/* Threat Points */}
                {d.threats > 0 && (
                  <circle
                    cx={cx}
                    cy={cyThreat}
                    r={isHovered ? 5.5 : 3.5}
                    fill="#FF4D5A"
                    stroke="#10103D"
                    strokeWidth="1.5"
                    className="transition-all"
                  />
                )}

                {/* Flow Points */}
                <circle
                  cx={cx}
                  cy={cyFlow}
                  r={isHovered ? 5 : 3}
                  fill="#39D7FF"
                  stroke="#10103D"
                  strokeWidth="1.5"
                  className="transition-all"
                />

                {/* X Axis Time Labels */}
                <text
                  x={cx}
                  y={height - 10}
                  textAnchor="middle"
                  fill={isHovered ? '#F5F5F7' : '#A5A5BE'}
                  fontSize="10"
                  fontFamily="monospace"
                >
                  {d.time}
                </text>

                {/* Invisible hover bar */}
                <rect
                  x={cx - (chartW / (data.length - 1)) / 2}
                  y={padding.top}
                  width={chartW / (data.length - 1)}
                  height={chartH}
                  fill="transparent"
                  onMouseEnter={() => setHoveredIdx(i)}
                  className="cursor-pointer"
                />

                {/* Hover line indicator */}
                {isHovered && (
                  <line
                    x1={cx}
                    y1={padding.top}
                    x2={cx}
                    y2={padding.top + chartH}
                    stroke="#A8F500"
                    strokeWidth="1"
                    strokeDasharray="2 2"
                  />
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Floating or pinned tooltip */}
      {activePoint && (
        <div className="mt-2 p-2.5 rounded-lg bg-[#07072B]/95 border border-[#A8F500]/40 flex items-center justify-between text-xs font-mono shadow-xl">
          <div className="flex items-center gap-2">
            <span className="text-[#A8F500] font-bold">@ {activePoint.time} UTC</span>
            <span className="text-[#A5A5BE]">|</span>
            <span className="text-[#39D7FF]">{activePoint.flows} Flows</span>
            <span className="text-[#A5A5BE]">|</span>
            <span className="text-[#FF4D5A] font-semibold">{activePoint.threats} Threat Alerts</span>
          </div>
          <span className="text-[11px] text-[#A5A5BE]">
            Rate: <strong className="text-[#F5F5F7]">{activePoint.pps.toLocaleString()} pps</strong>
          </span>
        </div>
      )}
    </div>
  );
};
