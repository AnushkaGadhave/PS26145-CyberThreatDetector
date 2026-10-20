import React, { useState } from 'react';
import {
  AlertTriangle,
  Info,
  Database,
  Clock
} from 'lucide-react';
import type { DetectionModelInfo } from '../../types/telemetry';
import type { ModelStatusResponse } from '../../services/api';

interface ModelsPageProps {
  models: DetectionModelInfo[];
  liveStatuses?: ModelStatusResponse[];
}

export const ModelsPage: React.FC<ModelsPageProps> = ({ models, liveStatuses = [] }) => {
  const [activeModelId, setActiveModelId] = useState<string>(models[0]?.id || 'ddos-random-forest');

  const selectedModel = models.find(m => m.id === activeModelId) || models[0];

  // Match live model status from database
  const getLiveRecord = (modelId: string) => {
    if (modelId === 'ddos-random-forest') {
      return liveStatuses.find(s => s.model_name === 'DDoS');
    }
    if (modelId === 'c2-hybrid-pipeline') {
      return liveStatuses.find(s => s.model_name === 'BOTNET_C2');
    }
    if (modelId === 'portscan-isolation-forest') {
      return liveStatuses.find(s => s.model_name === 'RECON_PORTSCAN');
    }
    return undefined;
  };

  const currentLive = getLiveRecord(activeModelId);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'FULLY_COMPATIBLE':
        return 'bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/30';
      case 'PARTIALLY_COMPATIBLE':
        return 'bg-[#F7B84B]/15 text-[#F7B84B] border-[#F7B84B]/30';
      default:
        return 'bg-[#FF4D5A]/15 text-[#FF4D5A] border-[#FF4D5A]/30';
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-heading font-extrabold text-[#F5F5F7] tracking-tight">
            Detection Components & Evaluation Metrics
          </h2>
          <p className="text-xs text-[#A5A5BE] font-mono mt-1">
            Live database model registry, historical benchmark evaluations, and scientific limitations
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-3 py-1.5 rounded-full bg-[#10103D] border border-[#242452] text-[#A8F500]">
            SIH Problem Statement 26145
          </span>
        </div>
      </div>

      {/* Scientific Transparency Alert Box */}
      <div className="p-4 rounded-2xl bg-[#10103D]/90 border border-[#242452] shadow-xl text-xs font-mono space-y-2">
        <div className="flex items-center gap-2 text-[#39D7FF] font-bold">
          <Info className="w-4 h-4 shrink-0" />
          <span>SCIENTIFIC DISCLOSURE: HISTORICAL BENCHMARK EVALUATION VS. RUNTIME TRAFFIC</span>
        </div>
        <p className="text-[#A5A5BE] font-sans leading-relaxed text-[11px]">
          Numerical accuracy, precision, and F1 scores displayed below are historical evaluation metrics derived from reproducible offline benchmark experiments (CIC-IDS2017 & CTU-13). Runtime inference on live traffic evaluates actual observed flows using these models. Known feature limitations are transparently audited.
        </p>
      </div>

      {/* Model Selection Tabs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {models.map((m) => {
          const isSelected = m.id === activeModelId;
          const liveRec = getLiveRecord(m.id);
          const displayStatus = liveRec ? liveRec.compatible : m.status;

          return (
            <button
              key={m.id}
              onClick={() => setActiveModelId(m.id)}
              className={`p-4 rounded-2xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                isSelected
                  ? 'bg-[#15154A] border-[#A8F500] shadow-lg shadow-[#A8F500]/10'
                  : 'bg-[#10103D]/60 border-[#242452] hover:bg-[#10103D] hover:border-[#39D7FF]/40'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${getStatusBadge(displayStatus)}`}>
                    {displayStatus}
                  </span>
                  <span className="text-[10px] font-mono text-[#A5A5BE]">
                    {m.feature_count} features
                  </span>
                </div>

                <h3 className="font-heading font-bold text-sm text-[#F5F5F7] mb-1">
                  {m.name}
                </h3>
                <p className="text-[11px] text-[#A5A5BE] font-sans line-clamp-2">
                  {m.family}
                </p>
              </div>

              <div className="mt-4 pt-2 border-t border-[#242452]/40 flex items-center justify-between text-xs font-mono">
                <span className="text-[#A5A5BE]">Historical F1</span>
                <span className="text-[#A8F500] font-bold">
                  {(m.metrics.f1_score * 100).toFixed(2)}%
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Live Database Model Registry Card */}
      {currentLive && (
        <div className="p-4 rounded-2xl bg-[#10103D]/80 border border-[#39D7FF]/40 shadow-xl text-xs font-mono">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[#39D7FF] font-bold flex items-center gap-2">
              <Database className="w-4 h-4 text-[#39D7FF]" />
              POSTGRESQL RUNTIME REGISTRY STATUS: {currentLive.model_name}
            </span>
            <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${getStatusBadge(currentLive.compatible)}`}>
              {currentLive.compatible}
            </span>
          </div>
          <p className="text-[#F5F5F7] font-sans text-xs leading-relaxed mb-2">
            <strong>Runtime Compatibility Rationale:</strong> {currentLive.reason}
          </p>
          {currentLive.updated_at && (
            <div className="flex items-center gap-1.5 text-[11px] text-[#A5A5BE]">
              <Clock className="w-3.5 h-3.5" />
              <span>Registry Verified: {new Date(currentLive.updated_at).toLocaleString()}</span>
            </div>
          )}
        </div>
      )}

      {/* Selected Model Detailed View */}
      {selectedModel && (
        <div className="space-y-6">
          {/* Card 1: Technical Architecture & Offline Evaluation */}
          <div className="rounded-2xl bg-[#10103D]/70 border border-[#242452] p-6 shadow-2xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
              <div>
                <h3 className="font-heading font-extrabold text-lg text-[#F5F5F7]">
                  {selectedModel.name}
                </h3>
                <span className="text-xs font-mono text-[#39D7FF]">
                  {selectedModel.family} • {selectedModel.architecture}
                </span>
              </div>

              <div className="text-xs font-mono text-[#A5A5BE]">
                Benchmark: <strong className="text-[#F5F5F7]">{selectedModel.benchmark_dataset}</strong>
              </div>
            </div>

            {/* Purpose */}
            <div className="mb-6 p-4 rounded-xl bg-[#07072B] border border-[#242452] text-xs font-sans text-[#A5A5BE] leading-relaxed">
              <strong className="text-[#F5F5F7] block font-heading mb-1 text-sm">Detection Purpose:</strong>
              {selectedModel.purpose}
            </div>

            {/* Offline Evaluation Grid */}
            <div className="mb-6">
              <span className="text-xs font-mono text-[#39D7FF] uppercase tracking-wider font-bold block mb-3">
                Historical Benchmark Evaluation Metrics (CIC-IDS2017 & CTU-13 Test Splits)
              </span>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block uppercase">Accuracy</span>
                  <span className="text-xl font-heading font-bold text-[#F5F5F7] mt-1 block">
                    {(selectedModel.metrics.accuracy * 100).toFixed(2)}%
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block uppercase">Precision</span>
                  <span className="text-xl font-heading font-bold text-[#39D7FF] mt-1 block">
                    {(selectedModel.metrics.precision * 100).toFixed(2)}%
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block uppercase">Recall</span>
                  <span className="text-xl font-heading font-bold text-[#F7B84B] mt-1 block">
                    {(selectedModel.metrics.recall * 100).toFixed(2)}%
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block uppercase">F1 Score</span>
                  <span className="text-xl font-heading font-bold text-[#A8F500] mt-1 block">
                    {(selectedModel.metrics.f1_score * 100).toFixed(2)}%
                  </span>
                </div>
              </div>

              {/* Confusion Matrix Numbers */}
              <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-[#10103D] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block">True Positives (TP)</span>
                  <span className="text-base font-bold text-[#A8F500] mt-1 block">
                    {selectedModel.metrics.true_positives.toLocaleString()}
                  </span>
                </div>

                <div className="p-2.5 rounded-lg bg-[#10103D] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block">False Positives (FP)</span>
                  <span className={`text-base font-bold mt-1 block ${
                    selectedModel.metrics.false_positives > 1000 ? 'text-[#FF4D5A]' : 'text-[#F7B84B]'
                  }`}>
                    {selectedModel.metrics.false_positives.toLocaleString()}
                  </span>
                </div>

                <div className="p-2.5 rounded-lg bg-[#10103D] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block">True Negatives (TN)</span>
                  <span className="text-base font-bold text-[#39D7FF] mt-1 block">
                    {selectedModel.metrics.true_negatives.toLocaleString()}
                  </span>
                </div>

                <div className="p-2.5 rounded-lg bg-[#10103D] border border-[#242452]">
                  <span className="text-[10px] text-[#A5A5BE] block">False Negatives (FN)</span>
                  <span className={`text-base font-bold mt-1 block ${
                    selectedModel.metrics.false_negatives > 1000 ? 'text-[#FF4D5A]' : 'text-[#F7B84B]'
                  }`}>
                    {selectedModel.metrics.false_negatives.toLocaleString()}
                  </span>
                </div>
              </div>
            </div>

            {/* Input Feature Information */}
            <div className="mb-6">
              <span className="text-xs font-mono text-[#A8F500] uppercase tracking-wider font-bold block mb-3">
                Extracted Feature Set ({selectedModel.feature_count} Total Engineered Features)
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                {selectedModel.key_features.map((feat, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-[#07072B] border border-[#242452] flex items-center gap-2 text-[#A5A5BE]">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
                    <span className="text-[#F5F5F7]">{feat}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Calibration & Threshold Notes */}
            <div className="p-4 rounded-xl bg-[#07072B] border border-[#242452] text-xs font-mono space-y-1 mb-6">
              <span className="text-[#F7B84B] font-bold block uppercase text-[11px]">
                Calibration & Operating Point Basis
              </span>
              <p className="text-[#A5A5BE] font-sans">
                {selectedModel.calibration_notes}
              </p>
            </div>

            {/* Operational Recommendation */}
            <div className="p-4 rounded-xl bg-[#07072B] border border-[#242452] text-xs font-mono space-y-1">
              <span className="text-[#7DDB52] font-bold block uppercase text-[11px]">
                Operational Recommendation in Streaming Ingress
              </span>
              <p className="text-[#A5A5BE] font-sans">
                {selectedModel.operational_recommendation}
              </p>
            </div>
          </div>

          {/* Card 2: Scientific Honesty & Known Limitations */}
          <div className="rounded-2xl bg-[#10103D]/70 border border-[#FF4D5A]/40 p-6 shadow-2xl">
            <div className="flex items-center gap-2 text-[#FF4D5A] font-heading font-extrabold text-base mb-4">
              <AlertTriangle className="w-5 h-5 shrink-0" />
              <span>Known Limitations & Scientific Integrity Audit</span>
            </div>

            <p className="text-xs font-sans text-[#A5A5BE] mb-4 leading-relaxed">
              In accordance with SIH Problem Statement 26145 audit guidelines, model constraints are rigorously disclosed rather than concealed:
            </p>

            <div className="space-y-3 text-xs font-mono">
              {selectedModel.limitations.map((lim, idx) => (
                <div key={idx} className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452] flex items-start gap-3">
                  <span className="text-[#FF4D5A] font-bold shrink-0 mt-0.5">•</span>
                  <span className="text-[#F5F5F7] font-sans leading-relaxed">{lim}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
