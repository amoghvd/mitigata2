import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { PageView } from '../types';

interface NavbarProps {
  activePage: PageView;
  onNavigate: (page: PageView) => void;
  isDark: boolean;
  onToggleTheme: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activePage,
  onNavigate,
  isDark,
  onToggleTheme,
}) => {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-zinc-200 dark:border-zinc-800/80 bg-white/90 dark:bg-zinc-950/90 backdrop-blur-md transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Brand wordmark & Logo */}
        <button
          onClick={() => onNavigate('landing')}
          className="flex items-center gap-2.5 text-left group focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 rounded-md shrink-0 cursor-pointer"
        >
          <img
            src="/logo.png"
            alt="ASK Logo"
            className="w-8 h-8 object-contain"
          />
          <span className="text-base font-bold tracking-tight text-zinc-900 dark:text-zinc-100 font-sans whitespace-nowrap">
            ASK
          </span>
        </button>

        {/* Zone 2: Navigation Links (Overview & Incident Workspace only - no 404, no quantum-ops, no docs link) */}
        <nav className="flex items-center gap-7 text-sm font-medium text-zinc-600 dark:text-zinc-400">
          <button
            onClick={() => onNavigate('landing')}
            className={`whitespace-nowrap transition-colors hover:text-zinc-900 dark:hover:text-zinc-100 py-1 cursor-pointer ${
              activePage === 'landing'
                ? 'text-zinc-900 dark:text-zinc-100 font-semibold border-b-2 border-emerald-500 dark:border-emerald-400'
                : ''
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => onNavigate('dashboard')}
            className={`whitespace-nowrap transition-colors hover:text-zinc-900 dark:hover:text-zinc-100 py-1 cursor-pointer ${
              activePage === 'dashboard'
                ? 'text-zinc-900 dark:text-zinc-100 font-semibold border-b-2 border-emerald-500 dark:border-emerald-400'
                : ''
            }`}
          >
            Incident Workspace
          </button>
        </nav>

        {/* Zone 3: GitHub Link & Theme Toggle */}
        <div className="flex items-center gap-2.5 shrink-0">
          <a
            href="https://github.com/rahul-gupta-2004/mitigata_hackathon_ask"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Mitigata GitHub Repository"
            className="h-9 px-3 rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 hover:text-zinc-950 dark:hover:text-zinc-100 hover:border-zinc-300 dark:hover:border-zinc-700 flex items-center gap-2 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 whitespace-nowrap cursor-pointer"
          >
            <svg
              className="w-4 h-4 fill-current shrink-0"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                fillRule="evenodd"
                clipRule="evenodd"
                d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
              />
            </svg>
            <span className="hidden sm:inline">GitHub</span>
          </a>

          <button
            type="button"
            onClick={onToggleTheme}
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            className="w-9 h-9 rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-zinc-100 hover:border-zinc-300 dark:hover:border-zinc-700 flex items-center justify-center transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 cursor-pointer"
          >
            {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>
      </div>
    </header>
  );
};
