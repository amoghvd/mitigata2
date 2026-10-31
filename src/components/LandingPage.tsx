import React from 'react';
import { PageView } from '../types';
import { ArrowRight, Database, Cpu, BrainCircuit } from 'lucide-react';

interface LandingPageProps {
  onNavigate: (page: PageView) => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onNavigate }) => {
  return (
    <div className="w-full flex-1 flex flex-col justify-start">
      {/* Hero Section */}
      <section className="relative px-4 sm:px-6 lg:px-8 pt-16 pb-20 max-w-7xl mx-auto w-full">
        <div className="max-w-3xl">
          {/* Unboxed subtle kicker (NO PILL BADGE) */}
          <div className="text-xs font-mono tracking-wider uppercase text-emerald-600 dark:text-emerald-400 mb-4 flex items-center gap-2">
            <span>Cybersecurity Hackathon Architecture</span>
            <span aria-hidden="true" className="text-zinc-400 dark:text-zinc-600">/</span>
            <span>Deterministic Kill Chain Containment</span>
          </div>

          {/* Bold typography headline */}
          <h1 className="text-4xl sm:text-6xl font-bold tracking-tight text-zinc-950 dark:text-zinc-50 leading-[1.08] text-balance">
            Analyze, Secure, and Kill
          </h1>

          {/* Concise subtitle on kill chain path analysis */}
          <p className="mt-6 text-lg sm:text-xl text-zinc-600 dark:text-zinc-400 font-normal leading-relaxed text-balance">
            Deterministic graph traversal meets quantum statevector look-aheads.
            ASK pinpoints lateral threat vectors across complex multi-cloud topology
            and severs adversarial kill chains before privilege escalation can execute.
          </p>

          {/* Clean Action Buttons (No Quantum-Ops link) */}
          <div className="mt-8 flex flex-wrap items-center gap-4">
            <button
              type="button"
              onClick={() => onNavigate('dashboard')}
              className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-zinc-950 bg-emerald-400 hover:bg-emerald-300 dark:bg-emerald-400 dark:hover:bg-emerald-300 rounded-md transition-colors shadow-xs active:scale-[0.98] focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 cursor-pointer"
            >
              <span>Launch Incident Workspace</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {/* Quantitative Rigor Strip (Adjacency to Hero Claim - No pill badges) */}
          <div className="mt-14 pt-8 border-t border-zinc-200 dark:border-zinc-800/80 grid grid-cols-2 sm:grid-cols-3 gap-6 text-left">
            <div>
              <div className="text-2xl font-bold font-mono tracking-tight text-zinc-900 dark:text-zinc-100 tabular-nums">
                &lt; 0.65ms
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                DuckDB VPC log vector query
              </div>
            </div>
            <div>
              <div className="text-2xl font-bold font-mono tracking-tight text-emerald-600 dark:text-emerald-400 tabular-nums">
                5 Qubits
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                Qiskit statevector circuit depth
              </div>
            </div>
            <div>
              <div className="text-2xl font-bold font-mono tracking-tight text-amber-600 dark:text-amber-400 tabular-nums">
                99.4%
              </div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                Sarvam AI root-cause attribution
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 3-Column Technical Value Grid (DuckDB, Qiskit, Sarvam AI) */}
      <section className="px-4 sm:px-6 lg:px-8 py-16 border-t border-zinc-200 dark:border-zinc-800/80 bg-zinc-50/50 dark:bg-zinc-900/20">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <h2 className="text-xs font-mono uppercase tracking-widest text-zinc-500 dark:text-zinc-400">
              Technical Core Stack
            </h2>
            <p className="mt-1 text-2xl font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">
              Engineered for Real-Time Threat Eradication
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Column 1: DuckDB */}
            <div className="p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 flex flex-col justify-between shadow-xs">
              <div>
                <div className="w-10 h-10 rounded-md bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 flex items-center justify-center text-zinc-900 dark:text-zinc-100 mb-5">
                  <Database className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                </div>
                <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tracking-tight">
                  DuckDB Vectorized Analytics
                </h3>
                <p className="mt-2.5 text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">
                  In-process columnar execution that digests gigabytes of VPC flow logs, audit records, and Zeek network captures directly into local memory. Eliminates network roundtrips to compute instant anomaly scores.
                </p>
              </div>

              <div className="mt-6 pt-4 border-t border-zinc-100 dark:border-zinc-800/60 font-mono text-xs text-zinc-500 dark:text-zinc-400 flex items-center justify-between">
                <span>Parquet Engine</span>
                <span className="text-zinc-700 dark:text-zinc-300 tabular-nums">Zero-overhead scan</span>
              </div>
            </div>

            {/* Column 2: Qiskit */}
            <div className="p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 flex flex-col justify-between shadow-xs">
              <div>
                <div className="w-10 h-10 rounded-md bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 flex items-center justify-center text-zinc-900 dark:text-zinc-100 mb-5">
                  <Cpu className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                </div>
                <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tracking-tight">
                  Qiskit Quantum Next-Hop
                </h3>
                <p className="mt-2.5 text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">
                  Translates network topology graphs into Hamiltonian operator states. Continuous-time quantum walks calculate multi-path infection superposition and identify critical choke-points for immediate isolation.
                </p>
              </div>

              <div className="mt-6 pt-4 border-t border-zinc-100 dark:border-zinc-800/60 font-mono text-xs text-zinc-500 dark:text-zinc-400 flex items-center justify-between">
                <span>Hamiltonian Walks</span>
                <span className="text-zinc-700 dark:text-zinc-300 tabular-nums">Statevector collapse</span>
              </div>
            </div>

            {/* Column 3: Sarvam AI */}
            <div className="p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/60 flex flex-col justify-between shadow-xs">
              <div>
                <div className="w-10 h-10 rounded-md bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 flex items-center justify-center text-zinc-900 dark:text-zinc-100 mb-5">
                  <BrainCircuit className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                </div>
                <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tracking-tight">
                  Sarvam AI Threat Intelligence
                </h3>
                <p className="mt-2.5 text-sm text-zinc-600 dark:text-zinc-400 leading-relaxed">
                  High-speed contextual reasoning engine that maps low-level telemetry bursts to MITRE ATT&CK kill chain stages, generating plain-text forensic briefings and one-click containment instructions.
                </p>
              </div>

              <div className="mt-6 pt-4 border-t border-zinc-100 dark:border-zinc-800/60 font-mono text-xs text-zinc-500 dark:text-zinc-400 flex items-center justify-between">
                <span>Contextual Synthesis</span>
                <span className="text-zinc-700 dark:text-zinc-300 tabular-nums">Real-time playbooks</span>
              </div>
            </div>
          </div>
        </div>
      </section>
      {/* Footer completely removed as requested */}
    </div>
  );
};
