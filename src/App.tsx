/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { PageView } from './types';
import { Navbar } from './components/Navbar';
import { LandingPage } from './components/LandingPage';
import { DashboardPage } from './components/DashboardPage';
import { NotFoundPage } from './components/NotFoundPage';

export default function App() {
  const [activePage, setActivePage] = useState<PageView>('landing');
  const [isDark, setIsDark] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('ask_theme') || localStorage.getItem('mitigata_theme');
      if (stored) return stored === 'dark';
      return true; // default dark for cybersecurity command center
    }
    return true;
  });

  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add('dark');
      localStorage.setItem('ask_theme', 'dark');
    } else {
      root.classList.remove('dark');
      localStorage.setItem('ask_theme', 'light');
    }
  }, [isDark]);

  const toggleTheme = () => {
    setIsDark((prev) => !prev);
  };

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 flex flex-col font-sans transition-colors duration-150">
      {/* Navbar (shared layout) */}
      <Navbar
        activePage={activePage}
        onNavigate={setActivePage}
        isDark={isDark}
        onToggleTheme={toggleTheme}
      />

      {/* Main Page Content Router */}
      <main className="flex-1 flex flex-col">
        {activePage === 'landing' && (
          <LandingPage onNavigate={setActivePage} />
        )}

        {activePage === 'dashboard' && (
          <DashboardPage />
        )}

        {activePage === '404' && (
          <NotFoundPage onNavigate={setActivePage} />
        )}
      </main>
    </div>
  );
}
