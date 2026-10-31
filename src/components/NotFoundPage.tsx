import React from 'react';
import { ArrowLeft } from 'lucide-react';
import { PageView } from '../types';

interface NotFoundPageProps {
  onNavigate: (page: PageView) => void;
}

export const NotFoundPage: React.FC<NotFoundPageProps> = ({ onNavigate }) => {
  return (
    <div className="w-full flex-1 flex items-center justify-center px-4 bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 transition-colors">
      <div className="max-w-md w-full text-center">
        {/* Monospace "404" label with quiet technical styling */}
        <div className="font-mono text-xs tracking-widest uppercase text-emerald-600 dark:text-emerald-400 mb-3">
          Error Status
        </div>
        
        <div className="font-mono text-7xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100 mb-4 select-none tabular-nums">
          404
        </div>

        {/* Clean system message */}
        <h1 className="text-lg font-semibold text-zinc-900 dark:text-zinc-200 tracking-tight">
          Target route or incident context not found
        </h1>

        <p className="mt-2 text-xs font-mono text-zinc-600 dark:text-zinc-400 leading-relaxed">
          The requested telemetry node, incident UUID, or quantum circuit state does not exist in the active cluster graph.
        </p>

        {/* Crisp Return Link to Dashboard */}
        <div className="mt-8">
          <button
            type="button"
            onClick={() => onNavigate('dashboard')}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold tracking-wide text-zinc-950 bg-emerald-400 hover:bg-emerald-300 dark:bg-emerald-400 dark:hover:bg-emerald-300 rounded-md transition-colors shadow-xs active:scale-[0.98] focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Return to Incident Workspace</span>
          </button>
        </div>
      </div>
    </div>
  );
};
