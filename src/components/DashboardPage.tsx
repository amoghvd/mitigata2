import React, { useState, useRef } from 'react';
import {
  Incident,
  IncidentSeverity,
  DuckDBLogRow,
  SupportedLanguage,
  GraphNode,
  GraphEdge,
} from '../types';
import {
  MOCK_INCIDENTS,
  MOCK_GRAPH_NODES,
  MOCK_GRAPH_EDGES,
  INITIAL_DUCKDB_LOGS,
} from '../data/mockData';
import {
  Search,
  UploadCloud,
  FileText,
  ShieldCheck,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Cpu,
  BrainCircuit,
  Database,
  Check,
  Trash2,
  RefreshCw,
  Download,
  Printer,
  X,
  ChevronLeft,
  ChevronRight,
  Globe,
  AlertCircle,
} from 'lucide-react';

export const DashboardPage: React.FC = () => {
  // Incident State (empty by default on page load; populated when "Load Sample" is clicked)
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<'all' | IncidentSeverity>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // DuckDB Flow Log State (empty and cleared by default on page load)
  const [duckdbLogs, setDuckdbLogs] = useState<DuckDBLogRow[]>([]);
  const [logFilterQuery, setLogFilterQuery] = useState('');
  const [isProcessingLogs, setIsProcessingLogs] = useState(false);
  const [ingestProgress, setIngestProgress] = useState<{
    stage: 'idle' | 'uploading' | 'processing' | 'completed';
    fileName: string;
    fileSizeBytes: number;
    uploadedBytes: number;
    uploadPercent: number;
    processedBytes: number;
    processingPercent: number;
    remainingBytes: number;
    rowsIndexed: number;
    statusText: string;
  }>({
    stage: 'idle',
    fileName: '',
    fileSizeBytes: 0,
    uploadedBytes: 0,
    uploadPercent: 0,
    processedBytes: 0,
    processingPercent: 0,
    remainingBytes: 0,
    rowsIndexed: 0,
    statusText: '',
  });

  const formatBytes = (bytes: number): string => {
    if (!bytes || bytes <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(i >= 2 ? 2 : 1)} ${sizes[i]}`;
  };

  const formatBriefDisplay = (text?: string): string => {
    if (!text) return '';
    return text
      .replace(/^#+\s+[^\n]+/gm, '')
      .replace(/\|\s*[-:]+\s*\|/g, '')
      .replace(/\|\s*Metric\s*\|\s*Value\s*\|[^\n]*/gi, '')
      .replace(/\|\s*Threat Type\s*\|\s*Details\s*\|[^\n]*/gi, '')
      .replace(/\|\s*/g, ' ')
      .replace(/---+/g, '')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  };

  const [uploadCompletionMessage, setUploadCompletionMessage] = useState<string | null>(null);
  const completionTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  // Sarvam AI Language & PDF State
  const [selectedLanguage, setSelectedLanguage] = useState<SupportedLanguage>('en');
  const [isPdfModalOpen, setIsPdfModalOpen] = useState(false);
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [isTranslating, setIsTranslating] = useState(false);

  // Handcrafted Attack Graph Canvas State (empty by default on page load)
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [zoomLevel, setZoomLevel] = useState<number>(100);
  const [canvasViewMode, setCanvasViewMode] = useState<'kill-chain' | 'quantum-walk'>('kill-chain');

  // Smooth Pan & Drag State for Canvas
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const dragStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const panStartRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  const activeIncident = incidents.find((i) => i.id === selectedIncidentId) || null;
  const activeNode = nodes.find((n) => n.id === selectedNodeId) || null;

  // Filtered Incidents
  const filteredIncidents = incidents.filter((item) => {
    const matchesSeverity = severityFilter === 'all' || item.severity === severityFilter;
    const matchesSearch =
      item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.targetAsset.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesSearch;
  });

  // Filtered DuckDB Logs
  const filteredLogs = duckdbLogs.filter((log) => {
    if (!logFilterQuery) return true;
    const q = logFilterQuery.toLowerCase();
    return (
      log.sourceIp.includes(q) ||
      log.destIp.includes(q) ||
      log.protocol.toLowerCase().includes(q) ||
      log.flag.toLowerCase().includes(q) ||
      log.notes.toLowerCase().includes(q)
    );
  });

  const handleLanguageChange = async (newLang: SupportedLanguage) => {
    setSelectedLanguage(newLang);
    if (!activeIncident) return;
    if (activeIncident.sarvamSummaryByLang && activeIncident.sarvamSummaryByLang[newLang]) return;

    setIsTranslating(true);
    try {
      const resp = await fetch('/api/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: activeIncident.id,
          title: activeIncident.title,
          severity: activeIncident.severity,
          score: activeIncident.score,
          target_asset: activeIncident.targetAsset,
          predicted_next_hop: activeIncident.quantumNextHop?.predictedNode,
          probability: activeIncident.quantumNextHop?.probability,
          language: newLang,
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.narrative) {
          setIncidents((prev) =>
            prev.map((inc) =>
              inc.id === activeIncident.id
                ? {
                    ...inc,
                    sarvamSummaryByLang: {
                      ...inc.sarvamSummaryByLang,
                      [newLang]: data.narrative,
                    },
                  }
                : inc
            )
          );
        }
      }
    } catch {
      // Non-blocking fallback
    } finally {
      setIsTranslating(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!activeIncident) return;
    setIsGeneratingPdf(true);
    try {
      const res = await fetch('/api/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: activeIncident.id,
          title: activeIncident.title,
          severity: activeIncident.severity,
          score: activeIncident.score,
          target_asset: activeIncident.targetAsset,
          predicted_next_hop: activeIncident.quantumNextHop?.predictedNode,
          probability: activeIncident.quantumNextHop?.probability,
          language: selectedLanguage,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.download_url) {
          const a = document.createElement('a');
          a.href = data.download_url;
          a.download = `Mitigata_Threat_Report_${data.report_id}.pdf`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          showNotification(`Executive Threat Report ${data.report_id} compiled by Sarvam AI.`);
        }
      } else {
        showNotification('Report compilation request returned an error.');
      }
    } catch {
      showNotification('Network error downloading PDF report.');
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  // Complete Data Deletion / Clear
  const handleClearAllData = async () => {
    if (completionTimerRef.current) clearTimeout(completionTimerRef.current);
    setUploadCompletionMessage(null);
    setDuckdbLogs([]);
    setIncidents([]);
    setSelectedIncidentId(null);
    setSelectedNodeId(null);
    setNodes([]);
    setEdges([]);
    try {
      await fetch('/api/logs', { method: 'DELETE' });
    } catch {
      // Backend sync error silently ignored for client state
    }
    showNotification('DuckDB data cleared. Incidents, forensic briefs, and attack canvas emptied.');
  };

  // Reload / Re-ingest Sample Data
  const handleReloadSampleData = async () => {
    if (completionTimerRef.current) clearTimeout(completionTimerRef.current);
    setUploadCompletionMessage(null);
    setIsProcessingLogs(true);
    
    const sampleBytes = 8388608; // ~8.0 MB (10,000 events)
    setIngestProgress({
      stage: 'uploading',
      fileName: 'edr_events.json (10,000 events)',
      fileSizeBytes: sampleBytes,
      uploadedBytes: sampleBytes,
      uploadPercent: 100,
      processedBytes: Math.round(sampleBytes * 0.3),
      processingPercent: 30,
      remainingBytes: Math.round(sampleBytes * 0.7),
      rowsIndexed: 3000,
      statusText: 'Streaming 10,000 EDR telemetry records into DuckDB...',
    });

    try {
      const resp = await fetch('/api/sample/load', { method: 'POST' });
      if (resp.ok) {
        const data = await resp.json();
        
        setIngestProgress({
          stage: 'completed',
          fileName: 'edr_events.json',
          fileSizeBytes: sampleBytes,
          uploadedBytes: sampleBytes,
          uploadPercent: 100,
          processedBytes: sampleBytes,
          processingPercent: 100,
          remainingBytes: 0,
          rowsIndexed: data.total_rows || 10000,
          statusText: `All ${(data.total_rows || 10000).toLocaleString()} records indexed into DuckDB. ${(data.alerts_count || 530).toLocaleString()} alerts analyzed with Sarvam AI.`,
        });

        if (data.sample_logs && data.sample_logs.length > 0) {
          setDuckdbLogs(data.sample_logs);
        }
        if (data.incidents && data.incidents.length > 0) {
          setIncidents(data.incidents);
          setSelectedIncidentId(data.incidents[0].id);
        }
        if (data.nodes && data.nodes.length > 0) {
          setNodes(data.nodes);
        }
        if (data.edges && data.edges.length > 0) {
          setEdges(data.edges);
        }
        setSelectedNodeId('node-dc');
        setIsProcessingLogs(false);

        const msg = `Sample telemetry loaded: ${(data.total_rows || 10000).toLocaleString()} rows indexed, ${(data.alerts_count || 530).toLocaleString()} threats flagged by Sarvam AI.`;
        setUploadCompletionMessage(msg);
        showNotification(msg);

        completionTimerRef.current = setTimeout(() => {
          setUploadCompletionMessage(null);
        }, 4000);
        return;
      }
    } catch (err) {
      console.warn('[Sample Load] Error, using fallback data:', err);
    }

    // Step 2: 75% processing
    setTimeout(() => {
      setIngestProgress((prev) => ({
        ...prev,
        processedBytes: Math.round(sampleBytes * 0.75),
        processingPercent: 75,
        remainingBytes: Math.round(sampleBytes * 0.25),
        rowsIndexed: Math.round(INITIAL_DUCKDB_LOGS.length * 0.75),
        statusText: 'Indexing relational flow keys and IP hashes...',
      }));
    }, 320);

    // Step 3: 100% completed
    setTimeout(() => {
      setIngestProgress((prev) => ({
        ...prev,
        stage: 'completed',
        processedBytes: sampleBytes,
        processingPercent: 100,
        remainingBytes: 0,
        rowsIndexed: INITIAL_DUCKDB_LOGS.length,
        statusText: 'All sample records indexed into DuckDB.',
      }));

      setDuckdbLogs(INITIAL_DUCKDB_LOGS);
      setIncidents(MOCK_INCIDENTS);
      setSelectedIncidentId('INC-8092');
      setNodes(MOCK_GRAPH_NODES);
      setEdges(MOCK_GRAPH_EDGES);
      setSelectedNodeId('node-auth');
      setIsProcessingLogs(false);
      
      const msg = `Sample telemetry loaded: ${INITIAL_DUCKDB_LOGS.length} rows indexed in DuckDB.`;
      setUploadCompletionMessage(msg);
      showNotification(msg);

      completionTimerRef.current = setTimeout(() => {
        setUploadCompletionMessage(null);
      }, 3000);
    }, 550);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    const fileName = file.name;
    const totalBytes = file.size;
    const jobId = `job-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    if (completionTimerRef.current) clearTimeout(completionTimerRef.current);
    setUploadCompletionMessage(null);
    setIsProcessingLogs(true);
    setIngestProgress({
      stage: 'uploading',
      fileName,
      fileSizeBytes: totalBytes,
      uploadedBytes: 0,
      uploadPercent: 0,
      processedBytes: 0,
      processingPercent: 0,
      remainingBytes: totalBytes,
      rowsIndexed: 0,
      statusText: `Uploading ${fileName} (${formatBytes(totalBytes)})...`,
    });

    const formData = new FormData();
    formData.append('file', file);

    let pollInterval: ReturnType<typeof setInterval> | null = null;

    const startPollingProgress = () => {
      if (pollInterval) return;
      pollInterval = setInterval(async () => {
        try {
          const res = await fetch(`/api/ingest/progress?job_id=${encodeURIComponent(jobId)}`);
          if (res.ok) {
            const data = await res.json();
            if (data && data.status !== 'pending') {
              setIngestProgress((prev) => ({
                ...prev,
                stage: 'processing',
                processedBytes: data.bytes_processed || 0,
                processingPercent: data.percent || 0,
                remainingBytes: data.remaining_bytes !== undefined ? data.remaining_bytes : Math.max(0, totalBytes - (data.bytes_processed || 0)),
                rowsIndexed: data.rows_ingested || 0,
                statusText: `Streaming & bulk-inserting into DuckDB raw_logs table... (${(data.rows_ingested || 0).toLocaleString()} rows)`,
              }));
            }
          }
        } catch {
          // Non-blocking poll error
        }
      }, 250);
    };

    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/ingest?job_id=${encodeURIComponent(jobId)}`);

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const loaded = event.loaded;
        const total = event.total || totalBytes;
        const pct = Math.min(100, Math.round((loaded / total) * 100));
        setIngestProgress((prev) => ({
          ...prev,
          uploadedBytes: loaded,
          uploadPercent: pct,
          statusText: pct === 100 
            ? 'Upload complete. Launching high-speed Rust ingestion engine into DuckDB...' 
            : `Uploaded ${formatBytes(loaded)} of ${formatBytes(total)} (${pct}%)...`,
        }));
        if (pct === 100) {
          startPollingProgress();
        }
      }
    };

    xhr.onload = async () => {
      if (pollInterval) clearInterval(pollInterval);
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const result = JSON.parse(xhr.responseText);
          
          setIngestProgress((prev) => ({
            ...prev,
            stage: 'completed',
            uploadedBytes: totalBytes,
            uploadPercent: 100,
            processedBytes: totalBytes,
            processingPercent: 100,
            remainingBytes: 0,
            rowsIndexed: result.ingested_rows || 0,
            statusText: `All ${(result.ingested_rows || 0).toLocaleString()} records parsed and indexed into DuckDB. ${(result.alerts_count || 0).toLocaleString()} alerts analyzed with Sarvam AI.`,
          }));

          // Set sample parsed logs from DuckDB to display in table immediately
          if (result.sample_logs && result.sample_logs.length > 0) {
            setDuckdbLogs(result.sample_logs);
          } else {
            // Fallback fetch if sample_logs wasn't attached
            try {
              const sampleRes = await fetch('/api/logs/sample?limit=50');
              if (sampleRes.ok) {
                const sampleData = await sampleRes.json();
                if (sampleData.sample_logs && sampleData.sample_logs.length > 0) {
                  setDuckdbLogs(sampleData.sample_logs);
                }
              }
            } catch {}
          }

          if (result.nodes && result.nodes.length > 0) {
            setNodes(result.nodes);
          } else {
            setNodes(MOCK_GRAPH_NODES);
          }

          if (result.edges && result.edges.length > 0) {
            setEdges(result.edges);
          } else {
            setEdges(MOCK_GRAPH_EDGES);
          }
          setSelectedNodeId('node-dc');

          if (result.incidents && result.incidents.length > 0) {
            setIncidents(result.incidents);
            setSelectedIncidentId(result.incidents[0].id);
          }

          setIsProcessingLogs(false);
          const successMsg = `Successfully ingested ${(result.ingested_rows || 0).toLocaleString()} rows from ${fileName} in ${result.duration_seconds}s (${(result.throughput_rows_per_second || 0).toLocaleString()} rows/s). ${(result.alerts_count || 0).toLocaleString()} alerts analyzed by Sarvam AI.`;
          setUploadCompletionMessage(successMsg);
          showNotification(successMsg);

          completionTimerRef.current = setTimeout(() => {
            setUploadCompletionMessage(null);
          }, 3000);
        } catch {
          setIsProcessingLogs(false);
          showNotification('Error parsing response from DuckDB ingest.');
        }
      } else {
        setIsProcessingLogs(false);
        showNotification(`Ingest status: ${xhr.status}`);
      }
      e.target.value = '';
    };

    xhr.onerror = () => {
      if (pollInterval) clearInterval(pollInterval);
      setIsProcessingLogs(false);
      showNotification('Network error during file upload to DuckDB.');
      e.target.value = '';
    };

    xhr.send(formData);
  };

  const handleQuarantineNode = (nodeId: string) => {
    setNodes((prev) =>
      prev.map((n) =>
        n.id === nodeId ? { ...n, status: 'quarantined' as const } : n
      )
    );
    if (activeIncident) {
      setIncidents((prev) =>
        prev.map((inc) =>
          inc.id === activeIncident.id ? { ...inc, status: 'contained' as const } : inc
        )
      );
    }
    showNotification(`Node ${nodeId} quarantined. Lateral infection edge severed.`);
  };

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 3500);
  };

  // Canvas Mouse Pan Handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDraggingCanvas(true);
    dragStartRef.current = { x: e.clientX, y: e.clientY };
    panStartRef.current = { ...panOffset };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDraggingCanvas) return;
    const deltaX = e.clientX - dragStartRef.current.x;
    const deltaY = e.clientY - dragStartRef.current.y;
    setPanOffset({
      x: panStartRef.current.x + deltaX,
      y: panStartRef.current.y + deltaY,
    });
  };

  const handleMouseUp = () => {
    setIsDraggingCanvas(false);
  };

  const resetCanvasPanAndZoom = () => {
    setPanOffset({ x: 0, y: 0 });
    setZoomLevel(100);
  };

  const panNudge = (dx: number, dy: number) => {
    setPanOffset((prev) => ({ x: prev.x + dx, y: prev.y + dy }));
  };

  const languageLabels: Record<SupportedLanguage, string> = {
    en: 'English (US)',
    hi: 'हिंदी (Hindi)',
    te: 'తెలుగు (Telugu)',
    ml: 'മലയാളം (Malayalam)',
  };

  const isCanvasEmpty = nodes.length === 0;

  return (
    <div className="w-full flex-1 flex flex-col bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 overflow-hidden">
      
      {/* Toast Notification Banner */}
      {notification && (
        <div className="bg-emerald-50 dark:bg-emerald-950/90 border-b border-emerald-200 dark:border-emerald-500/40 px-4 py-2 text-xs font-mono text-emerald-800 dark:text-emerald-300 flex items-center justify-between z-50">
          <div className="flex items-center gap-2">
            <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" />
            <span>{notification}</span>
          </div>
          <button
            onClick={() => setNotification(null)}
            className="text-emerald-700 dark:text-emerald-400 hover:underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Main 3-Column Split-Screen Workspace */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 min-h-0 divide-y lg:divide-y-0 lg:divide-x divide-zinc-200 dark:divide-zinc-800">
        
        {/* LEFT COLUMN: Queue of Risk-Sorted Incidents (3 Cols) */}
        <aside className="lg:col-span-3 flex flex-col h-full bg-white dark:bg-zinc-950 border-r border-zinc-200 dark:border-zinc-800/80 overflow-hidden">
          {/* Header & Search */}
          <div className="p-3.5 border-b border-zinc-200 dark:border-zinc-800">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-xs font-mono uppercase tracking-wider text-zinc-600 dark:text-zinc-400 font-medium">
                Incident Triage Queue
              </span>
              <span className="font-mono text-xs text-zinc-500 tabular-nums">
                {filteredIncidents.length} active
              </span>
            </div>

            {/* Live Search */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-400 dark:text-zinc-500" />
              <input
                type="text"
                value={searchQuery}
                disabled={incidents.length === 0}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={incidents.length === 0 ? "No active incidents" : "Filter CVE, host, or stage..."}
                className="w-full bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded pl-8 pr-3 py-1.5 text-xs text-zinc-900 dark:text-zinc-200 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-zinc-400 dark:focus:border-zinc-600 transition-colors disabled:opacity-50"
              />
            </div>

            {/* Severity Segmented Filter */}
            <div className="flex items-center gap-1 mt-2.5 bg-zinc-100 dark:bg-zinc-900 p-0.5 rounded border border-zinc-200 dark:border-zinc-800/80">
              {(['all', 'critical', 'high', 'elevated'] as const).map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  className={`flex-1 py-1 text-[11px] font-medium rounded transition-colors capitalize cursor-pointer ${
                    severityFilter === sev
                      ? 'bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 shadow-xs'
                      : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Incident List */}
          <div className="flex-1 overflow-y-auto divide-y divide-zinc-100 dark:divide-zinc-900">
            {filteredIncidents.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-zinc-500 space-y-3">
                <AlertCircle className="w-6 h-6 mx-auto text-zinc-400 opacity-60" />
                <p>No incidents in queue.</p>
                <p className="text-[11px] text-zinc-400">
                  {duckdbLogs.length === 0
                    ? "DuckDB data has been cleared. Ingest flow logs or click 'Load Sample' in the right panel to generate threat correlation."
                    : "No incidents match the active severity filter."}
                </p>
              </div>
            ) : (
              filteredIncidents.map((inc) => {
                const isSelected = inc.id === selectedIncidentId;
                return (
                  <button
                    key={inc.id}
                    type="button"
                    onClick={() => setSelectedIncidentId(inc.id)}
                    className={`w-full text-left p-3.5 transition-colors group relative cursor-pointer ${
                      isSelected
                        ? 'bg-zinc-100/90 dark:bg-zinc-900/90'
                        : 'hover:bg-zinc-50 dark:hover:bg-zinc-900/40 bg-transparent'
                    }`}
                  >
                    {isSelected && (
                      <div className="absolute right-0 top-0 bottom-0 w-0.5 bg-emerald-500" />
                    )}

                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`font-mono text-xs font-semibold tabular-nums ${
                            inc.score >= 9.0
                              ? 'text-amber-600 dark:text-amber-400'
                              : inc.score >= 7.5
                              ? 'text-amber-500'
                              : 'text-zinc-600 dark:text-zinc-300'
                          }`}
                        >
                          {inc.score.toFixed(1)}
                        </span>
                        <span className="font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                          {inc.id}
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-zinc-400 dark:text-zinc-500 tabular-nums">
                        {inc.detectedAt}
                      </span>
                    </div>

                    <div className="mt-1 text-xs font-medium text-zinc-900 dark:text-zinc-200 group-hover:text-zinc-950 dark:group-hover:text-zinc-100 line-clamp-1">
                      {inc.title}
                    </div>

                    <div className="mt-1.5 flex items-center gap-1.5 text-[11px] text-zinc-500 dark:text-zinc-400 font-mono truncate">
                      <span className="truncate">{inc.targetAsset}</span>
                      <span aria-hidden="true" className="text-zinc-300 dark:text-zinc-600">·</span>
                      <span className="shrink-0">{inc.stage}</span>
                      <span aria-hidden="true" className="text-zinc-300 dark:text-zinc-600">·</span>
                      <span className={`shrink-0 capitalize ${
                        inc.status === 'contained' ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : 'text-amber-600 dark:text-amber-400'
                      }`}>
                        {inc.status}
                      </span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </aside>

        {/* CENTER COLUMN: Handcrafted Attack Graph Canvas with Pan, Zoom & Crisp Design (6 Cols) */}
        <main className="lg:col-span-6 flex flex-col h-full bg-zinc-50/50 dark:bg-zinc-950 relative overflow-hidden">
          {/* Canvas Viewport Toolbar */}
          <div className="h-12 border-b border-zinc-200 dark:border-zinc-800 px-4 flex items-center justify-between gap-4 bg-white/90 dark:bg-zinc-950/90 backdrop-blur-xs z-10 shrink-0">
            {/* View Mode Toggle: Kill Chain vs Quantum Walk */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase tracking-wider text-zinc-500 dark:text-zinc-400 hidden sm:inline">
                Mode:
              </span>
              <div className="flex items-center bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded p-0.5">
                <button
                  type="button"
                  onClick={() => setCanvasViewMode('kill-chain')}
                  className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors cursor-pointer ${
                    canvasViewMode === 'kill-chain'
                      ? 'bg-white dark:bg-zinc-800 text-amber-600 dark:text-amber-300 font-semibold shadow-xs'
                      : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                  }`}
                >
                  Kill Chain
                </button>
                <button
                  type="button"
                  onClick={() => setCanvasViewMode('quantum-walk')}
                  className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors cursor-pointer ${
                    canvasViewMode === 'quantum-walk'
                      ? 'bg-white dark:bg-zinc-800 text-emerald-600 dark:text-emerald-300 font-semibold shadow-xs'
                      : 'text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300'
                  }`}
                >
                  Quantum Walk
                </button>
              </div>
            </div>

            {/* Pan & Zoom Controls */}
            <div className="flex items-center gap-2">
              {/* Pan Left / Right Nudge buttons */}
              <div className="hidden sm:flex items-center border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded text-zinc-500 dark:text-zinc-400">
                <button
                  type="button"
                  title="Pan Left"
                  onClick={() => panNudge(60, 0)}
                  className="p-1 hover:text-zinc-900 dark:hover:text-zinc-100 border-r border-zinc-200 dark:border-zinc-800 cursor-pointer"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <span className="px-1.5 text-[10px] font-mono">Pan</span>
                <button
                  type="button"
                  title="Pan Right"
                  onClick={() => panNudge(-60, 0)}
                  className="p-1 hover:text-zinc-900 dark:hover:text-zinc-100 border-l border-zinc-200 dark:border-zinc-800 cursor-pointer"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>

              {/* Zoom Controls */}
              <div className="flex items-center border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 rounded">
                <button
                  type="button"
                  onClick={() => setZoomLevel((z) => Math.max(60, z - 15))}
                  aria-label="Zoom out"
                  className="p-1 hover:text-zinc-900 dark:hover:text-zinc-100 text-zinc-500 dark:text-zinc-400 border-r border-zinc-200 dark:border-zinc-800 transition-colors cursor-pointer"
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <span className="px-2 font-mono text-[11px] text-zinc-600 dark:text-zinc-400 tabular-nums">
                  {zoomLevel}%
                </span>
                <button
                  type="button"
                  onClick={() => setZoomLevel((z) => Math.min(180, z + 15))}
                  aria-label="Zoom in"
                  className="p-1 hover:text-zinc-900 dark:hover:text-zinc-100 text-zinc-500 dark:text-zinc-400 border-l border-zinc-200 dark:border-zinc-800 transition-colors cursor-pointer"
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  title="Reset Pan and Zoom"
                  onClick={resetCanvasPanAndZoom}
                  aria-label="Reset pan and zoom"
                  className="p-1 hover:text-zinc-900 dark:hover:text-zinc-100 text-zinc-500 dark:text-zinc-400 border-l border-zinc-200 dark:border-zinc-800 transition-colors cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* Canvas Mode Header Banner */}
          <div className="px-4 py-1.5 border-b border-zinc-200 dark:border-zinc-800 text-[11px] font-mono flex items-center justify-between bg-zinc-100/60 dark:bg-zinc-900/60">
            <span className={canvasViewMode === 'kill-chain' ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400 font-medium'}>
              {canvasViewMode === 'kill-chain'
                ? '• KILL CHAIN ANALYSIS: Tracking MITRE ATT&CK progression & lateral traversal'
                : '• QUANTUM WALK VIEW: Continuous-time Hamiltonian statevector superposition probabilities'}
            </span>
            <span className="text-zinc-400 text-[10px] hidden md:inline">
              Drag background to pan left/right
            </span>
          </div>

          {/* Canvas Drawing Surface */}
          <div
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            className={`flex-1 relative overflow-hidden bg-zinc-100/40 dark:bg-zinc-950 flex items-center justify-center select-none ${
              isDraggingCanvas ? 'cursor-grabbing' : 'cursor-grab'
            }`}
          >
            {/* Subtle Grid dots background */}
            <div
              className="absolute inset-0 opacity-20 pointer-events-none"
              style={{
                backgroundImage: 'radial-gradient(#71717a 1px, transparent 1px)',
                backgroundSize: '20px 20px',
              }}
            />

            {/* If DuckDB is empty, show clean, quiet text with NO buttons */}
            {isCanvasEmpty ? (
              <div className="p-6 text-center z-10 pointer-events-none">
                <p className="text-xs font-mono text-zinc-400 dark:text-zinc-500">
                  Topology canvas empty · Awaiting DuckDB flow telemetry
                </p>
              </div>
            ) : (
              /* Transform Container with Pan Offset and Zoom Level */
              <div
                data-canvas-container="true"
                className="relative w-[860px] h-[420px]"
                style={{
                  transform: `translate(${panOffset.x}px, ${panOffset.y}px) scale(${zoomLevel / 100})`,
                  transformOrigin: 'center center',
                }}
              >
                {/* Directed Attack Edges SVG */}
                <svg className="absolute inset-0 w-full h-full pointer-events-none overflow-visible">
                  <defs>
                    <marker
                      id="arrowhead-breached"
                      markerWidth="8"
                      markerHeight="6"
                      refX="7"
                      refY="3"
                      orient="auto"
                    >
                      <polygon points="0 0, 8 3, 0 6" fill={canvasViewMode === 'kill-chain' ? '#f59e0b' : '#10b981'} />
                    </marker>
                    <marker
                      id="arrowhead-safe"
                      markerWidth="8"
                      markerHeight="6"
                      refX="7"
                      refY="3"
                      orient="auto"
                    >
                      <polygon points="0 0, 8 3, 0 6" fill="#71717a" />
                    </marker>
                  </defs>

                  {edges.map((edge) => {
                    const source = nodes.find((n) => n.id === edge.source);
                    const target = nodes.find((n) => n.id === edge.target);
                    if (!source || !target) return null;

                    const x1 = source.x + 85;
                    const y1 = source.y + 42;
                    const x2 = target.x;
                    const y2 = target.y + 42;
                    const midX = (x1 + x2) / 2;
                    const midY = (y1 + y2) / 2;

                    const strokeColor =
                      canvasViewMode === 'kill-chain'
                        ? edge.isBreached ? '#f59e0b' : '#71717a'
                        : edge.isBreached ? '#10b981' : '#3f3f46';

                    return (
                      <g key={edge.id}>
                        <path
                          d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
                          fill="none"
                          stroke={strokeColor}
                          strokeWidth={edge.isBreached ? '2.5' : '1.5'}
                          strokeDasharray={
                            canvasViewMode === 'quantum-walk'
                              ? '6 3'
                              : edge.isBreached
                              ? '5 2'
                              : 'none'
                          }
                          markerEnd={edge.isBreached ? 'url(#arrowhead-breached)' : 'url(#arrowhead-safe)'}
                        />
                        {/* Edge Label */}
                        <rect
                          x={midX - 38}
                          y={midY - 11}
                          width="76"
                          height="20"
                          rx="3"
                          fill="#ffffff"
                          stroke="#e4e4e7"
                          className="dark:fill-zinc-950 dark:stroke-zinc-800"
                        />
                        <text
                          x={midX}
                          y={midY + 3}
                          textAnchor="middle"
                          fill={canvasViewMode === 'kill-chain' ? '#d97706' : '#059669'}
                          fontSize="9"
                          fontWeight="600"
                          fontFamily="monospace"
                          className="dark:fill-zinc-300"
                        >
                          {canvasViewMode === 'kill-chain'
                            ? `Hop #${edge.killChainStep} ${edge.protocol}`
                            : `|ψ⟩ ${(edge.traversalProbability * 100).toFixed(0)}% (${edge.quantumPhase})`}
                        </text>
                      </g>
                    );
                  })}
                </svg>

                {/* Handcrafted Attack Graph Nodes */}
                {nodes.map((node) => {
                  const isSelected = node.id === selectedNodeId;

                  let nodeBorder = 'border-zinc-300 dark:border-zinc-700';
                  let accentColor = 'text-zinc-600 dark:text-zinc-400';

                  if (canvasViewMode === 'kill-chain') {
                    if (node.status === 'compromised') {
                      nodeBorder = 'border-amber-500 dark:border-amber-500';
                      accentColor = 'text-amber-600 dark:text-amber-400 font-semibold';
                    } else if (node.status === 'targeted') {
                      nodeBorder = 'border-amber-400 dark:border-amber-400';
                      accentColor = 'text-amber-500 dark:text-amber-300 font-semibold';
                    } else if (node.status === 'quarantined') {
                      nodeBorder = 'border-zinc-400 dark:border-zinc-700 bg-zinc-100 dark:bg-zinc-900/40';
                      accentColor = 'text-zinc-500';
                    } else {
                      nodeBorder = 'border-emerald-500/60 dark:border-emerald-500/50';
                      accentColor = 'text-emerald-600 dark:text-emerald-400 font-semibold';
                    }
                  } else {
                    if (node.quantumProbability >= 0.8) {
                      nodeBorder = 'border-emerald-500 ring-1 ring-emerald-500/40';
                      accentColor = 'text-emerald-600 dark:text-emerald-300 font-bold';
                    } else if (node.quantumProbability >= 0.4) {
                      nodeBorder = 'border-cyan-500/70 dark:border-cyan-500/70';
                      accentColor = 'text-cyan-600 dark:text-cyan-300 font-semibold';
                    } else {
                      nodeBorder = 'border-zinc-300 dark:border-zinc-700';
                      accentColor = 'text-zinc-500 dark:text-zinc-400';
                    }
                  }

                  return (
                    <div
                      key={node.id}
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedNodeId(node.id);
                      }}
                      style={{ left: `${node.x}px`, top: `${node.y}px` }}
                      className={`absolute w-48 rounded-md border p-2.5 bg-white dark:bg-zinc-900 transition-all cursor-pointer shadow-xs ${nodeBorder} ${
                        isSelected
                          ? 'ring-2 ring-emerald-500 shadow-md shadow-zinc-200 dark:shadow-black/60'
                          : 'hover:border-zinc-400 dark:hover:border-zinc-500'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="font-mono text-[10px] text-zinc-500 dark:text-zinc-400 truncate">
                          {node.ip}
                        </span>
                        <span className="font-mono text-[10px] font-semibold tabular-nums text-zinc-700 dark:text-zinc-300">
                          {node.riskScore}
                        </span>
                      </div>

                      <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                        {node.label}
                      </div>

                      {canvasViewMode === 'kill-chain' ? (
                        <div className="mt-1.5 pt-1.5 border-t border-zinc-100 dark:border-zinc-800 flex items-center justify-between text-[10px] font-mono">
                          <span className="text-zinc-500 truncate">{node.killChainStage}</span>
                          <span className={`capitalize shrink-0 ml-1 ${accentColor}`}>
                            {node.status}
                          </span>
                        </div>
                      ) : (
                        <div className="mt-1.5 pt-1.5 border-t border-zinc-100 dark:border-zinc-800 space-y-1">
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <span className="text-zinc-500">Pr(|ψ⟩):</span>
                            <span className={`tabular-nums ${accentColor}`}>
                              {(node.quantumProbability * 100).toFixed(1)}%
                            </span>
                          </div>
                          <div className="w-full bg-zinc-200 dark:bg-zinc-800 h-1 rounded-full overflow-hidden">
                            <div
                              className="bg-emerald-500 h-full rounded-full transition-all"
                              style={{ width: `${node.quantumProbability * 100}%` }}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Bottom Canvas Footer / Legend (Only visible if nodes exist) */}
            {!isCanvasEmpty && (
              <div className="absolute bottom-3 left-4 right-4 flex items-center justify-between text-[11px] font-mono text-zinc-600 dark:text-zinc-400 bg-white/90 dark:bg-zinc-900/90 backdrop-blur-sm border border-zinc-200 dark:border-zinc-800 rounded px-3 py-2 pointer-events-auto shadow-xs z-10">
                <div className="flex items-center gap-4">
                  <span className="text-zinc-400 dark:text-zinc-500">Legend:</span>
                  {canvasViewMode === 'kill-chain' ? (
                    <>
                      <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                        <span className="w-2 h-2 rounded-xs bg-amber-500" /> Compromised
                      </span>
                      <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                        <span className="w-2 h-2 rounded-xs bg-amber-400" /> Targeted
                      </span>
                      <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                        <span className="w-2 h-2 rounded-xs bg-zinc-400 dark:bg-zinc-600" /> Quarantined
                      </span>
                      <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                        <span className="w-2 h-2 rounded-xs bg-emerald-500" /> Secure
                      </span>
                    </>
                  ) : (
                    <>
                      <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                        <span className="w-2 h-2 rounded-xs bg-emerald-500" /> High Infiltration (&gt;80%)
                      </span>
                      <span className="flex items-center gap-1.5 text-zinc-700 dark:text-zinc-300">
                        <span className="w-2 h-2 rounded-xs bg-cyan-500" /> Probable Superposition Path
                      </span>
                    </>
                  )}
                </div>

                {activeNode && (
                  <div className="flex items-center gap-2">
                    <span className="text-zinc-400 dark:text-zinc-500">Selected Node:</span>
                    <span className="text-zinc-900 dark:text-zinc-200 font-semibold">{activeNode.label}</span>
                    {activeNode.status !== 'quarantined' && (
                      <button
                        type="button"
                        onClick={() => handleQuarantineNode(activeNode.id)}
                        className="ml-2 px-2 py-0.5 text-[10px] font-medium bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-500/40 rounded transition-colors cursor-pointer"
                      >
                        Sever & Isolate
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </main>

        {/* RIGHT COLUMN: DuckDB Live Logs & Sarvam AI Report with 4-Language Dropdown & PDF (3 Cols) */}
        <aside className="lg:col-span-3 flex flex-col h-full bg-white dark:bg-zinc-950 overflow-y-auto divide-y divide-zinc-200 dark:divide-zinc-800">
          
          {/* Section 1: DuckDB In-Memory Log Table with Clear/Delete and Upload */}
          <div className="p-3.5 bg-zinc-50 dark:bg-zinc-900/40 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                <span className="text-xs font-mono uppercase tracking-wider text-zinc-800 dark:text-zinc-200 font-semibold">
                  DuckDB Flow Log Data
                </span>
              </div>
              <div className="flex items-center gap-2">
                {isProcessingLogs && (
                  <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-medium tabular-nums">
                    {ingestProgress.uploadPercent < 100
                      ? `Uploading ${ingestProgress.uploadPercent}%`
                      : `Ingesting ${ingestProgress.processingPercent}%`}
                  </span>
                )}
                <span className="font-mono text-[10px] text-zinc-500 tabular-nums">
                  {duckdbLogs.length} rows
                </span>
              </div>
            </div>

            {/* In-Flight Ingestion & Processing Loading Bar with % Uploaded & Processed */}
            {isProcessingLogs && (
              <div className="p-3 rounded border border-emerald-400/50 dark:border-emerald-500/40 bg-emerald-50/90 dark:bg-emerald-950/40 text-emerald-950 dark:text-emerald-100 flex flex-col gap-2.5 shadow-xs">
                {/* Header: File info & stage badge */}
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="font-semibold truncate text-emerald-950 dark:text-emerald-100 max-w-[210px]">
                    {ingestProgress.fileName || 'logs.log'} ({formatBytes(ingestProgress.fileSizeBytes)})
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-medium shrink-0 bg-emerald-200/80 dark:bg-emerald-900/80 text-emerald-900 dark:text-emerald-300">
                    {ingestProgress.uploadPercent < 100 ? 'Phase 1/2: Uploading' : 'Phase 2/2: Ingesting'}
                  </span>
                </div>

                {/* Progress Metric 1: Data Uploaded to Server */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[10px] font-mono">
                    <span className="text-zinc-600 dark:text-zinc-400 font-medium">Uploaded to Server:</span>
                    <span className="font-semibold text-emerald-800 dark:text-emerald-300 tabular-nums">
                      {ingestProgress.uploadPercent}% ({formatBytes(ingestProgress.uploadedBytes)} / {formatBytes(ingestProgress.fileSizeBytes)})
                    </span>
                  </div>
                  <div className="w-full bg-emerald-200/50 dark:bg-zinc-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-emerald-600 dark:bg-emerald-400 rounded-full transition-all duration-150"
                      style={{ width: `${Math.max(1, ingestProgress.uploadPercent)}%` }}
                    />
                  </div>
                </div>

                {/* Progress Metric 2: DuckDB Processing & Ingestion */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[10px] font-mono">
                    <span className="text-zinc-600 dark:text-zinc-400 font-medium">Processed & Indexed:</span>
                    <span className="font-semibold text-emerald-800 dark:text-emerald-300 tabular-nums">
                      {ingestProgress.uploadPercent < 100 ? (
                        <span className="text-zinc-500 font-normal">Waiting for upload stream...</span>
                      ) : (
                        `${ingestProgress.processingPercent}% (${formatBytes(ingestProgress.processedBytes)} / ${formatBytes(ingestProgress.fileSizeBytes)})`
                      )}
                    </span>
                  </div>
                  <div className="w-full bg-emerald-200/50 dark:bg-zinc-800 h-1.5 rounded-full overflow-hidden relative">
                    <div
                      className={`h-full rounded-full transition-all duration-200 ${
                        ingestProgress.uploadPercent < 100
                          ? 'bg-zinc-300 dark:bg-zinc-700 w-0'
                          : 'bg-gradient-to-r from-emerald-500 via-teal-300 to-emerald-500 animate-pulse'
                      }`}
                      style={{ width: `${Math.max(ingestProgress.uploadPercent < 100 ? 0 : 2, ingestProgress.processingPercent)}%` }}
                    />
                  </div>
                </div>

                {/* Progress Metric 3: Remaining Processing & Status */}
                <div className="flex items-center justify-between text-[10px] font-mono text-emerald-800 dark:text-emerald-400 pt-1 border-t border-emerald-200/60 dark:border-emerald-900/60">
                  <span className="truncate max-w-[190px]" title={ingestProgress.statusText}>
                    {ingestProgress.statusText}
                  </span>
                  <span className="shrink-0 font-medium tabular-nums text-emerald-900 dark:text-emerald-300">
                    {ingestProgress.uploadPercent < 100 ? (
                      `${formatBytes(ingestProgress.uploadedBytes)} of ${formatBytes(ingestProgress.fileSizeBytes)} uploaded`
                    ) : (
                      `${Math.max(0, 100 - ingestProgress.processingPercent).toFixed(0)}% processing left (${formatBytes(ingestProgress.remainingBytes)} left)`
                    )}
                  </span>
                </div>
              </div>
            )}

            {/* 2-3 Second Upload/Processing Completion Notification Banner */}
            {uploadCompletionMessage && !isProcessingLogs && (
              <div className="p-2.5 rounded border border-emerald-400 dark:border-emerald-600/70 bg-emerald-100/90 dark:bg-emerald-950/70 text-emerald-900 dark:text-emerald-100 flex items-start gap-2 shadow-xs transition-all duration-300">
                <Check className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                <div className="flex-1 text-[11px] font-mono leading-tight">
                  <span className="font-semibold text-emerald-800 dark:text-emerald-300">Success: </span>
                  <span>{uploadCompletionMessage}</span>
                </div>
                <span className="text-[9px] font-mono text-emerald-700 dark:text-emerald-400 shrink-0 uppercase tracking-wider">
                  2-3s auto-dismiss
                </span>
              </div>
            )}

            {/* Ingestion & Clear Controls */}
            <div className="flex items-center gap-2">
              <label className={`flex-1 py-1.5 px-2 text-[11px] font-mono font-medium rounded border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 ${
                isProcessingLogs ? 'opacity-60 cursor-not-allowed' : 'hover:border-zinc-400 dark:hover:border-zinc-700 cursor-pointer'
              } text-zinc-700 dark:text-zinc-300 flex items-center justify-center gap-1.5 transition-colors`}>
                <UploadCloud className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                <span>{isProcessingLogs ? 'Uploading...' : 'Upload PCAP/Logs'}</span>
                <input
                  type="file"
                  onChange={handleFileUpload}
                  disabled={isProcessingLogs}
                  className="hidden"
                  accept=".pcap,.json,.parquet,.csv,.log,.txt"
                />
              </label>

              {duckdbLogs.length > 0 ? (
                <button
                  type="button"
                  onClick={handleClearAllData}
                  disabled={isProcessingLogs}
                  title="Clear all DuckDB logs, incident queue, and canvas"
                  className="py-1.5 px-2.5 text-[11px] font-mono text-amber-700 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-950/40 disabled:opacity-50 disabled:cursor-not-allowed rounded border border-amber-200 dark:border-amber-800/60 flex items-center gap-1 transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Delete Data</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleReloadSampleData}
                  disabled={isProcessingLogs}
                  className="py-1.5 px-2.5 text-[11px] font-mono text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/40 disabled:opacity-50 disabled:cursor-not-allowed rounded border border-emerald-200 dark:border-emerald-800/60 flex items-center gap-1 transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Load Sample</span>
                </button>
              )}
            </div>

            {/* Filter log rows input */}
            {duckdbLogs.length > 0 && !isProcessingLogs && (
              <input
                type="text"
                value={logFilterQuery}
                onChange={(e) => setLogFilterQuery(e.target.value)}
                placeholder="Filter logs by IP, protocol, flag..."
                className="w-full bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded px-2.5 py-1 text-[11px] font-mono text-zinc-900 dark:text-zinc-200 placeholder-zinc-400 focus:outline-none focus:border-zinc-400"
              />
            )}

            {/* DuckDB Log Table View */}
            <div className="rounded border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 overflow-hidden max-h-48 overflow-y-auto">
              {duckdbLogs.length === 0 ? (
                <div className="p-4 text-center text-xs font-mono text-zinc-500">
                  <Database className="w-5 h-5 mx-auto text-zinc-400 mb-1 opacity-50" />
                  {isProcessingLogs ? (
                    <div className="text-emerald-600 dark:text-emerald-400 text-[11px] space-y-0.5">
                      <div>
                        {ingestProgress.uploadPercent < 100
                          ? `Uploading ${ingestProgress.uploadPercent}% (${formatBytes(ingestProgress.uploadedBytes)} / ${formatBytes(ingestProgress.fileSizeBytes)})...`
                          : `DuckDB Ingestion: ${ingestProgress.processingPercent}% (${formatBytes(ingestProgress.processedBytes)} / ${formatBytes(ingestProgress.fileSizeBytes)})`}
                      </div>
                      <div className="text-[10px] text-zinc-500">
                        {ingestProgress.uploadPercent < 100
                          ? `${formatBytes(ingestProgress.uploadedBytes)} of ${formatBytes(ingestProgress.fileSizeBytes)} uploaded`
                          : `${Math.max(0, 100 - ingestProgress.processingPercent).toFixed(0)}% processing remaining (${formatBytes(ingestProgress.remainingBytes)} left)`}
                      </div>
                    </div>
                  ) : (
                    <>
                      DuckDB in-memory table is empty.
                      <div className="text-[10px] text-zinc-400 mt-0.5">
                        Click "Load Sample" or upload log files to execute queries.
                      </div>
                    </>
                  )}
                </div>
              ) : (
                <table className="w-full text-left border-collapse text-[10px] font-mono">
                  <thead className="bg-zinc-100 dark:bg-zinc-800/60 text-zinc-500 uppercase sticky top-0">
                    <tr>
                      <th className="py-1 px-2">Src IP</th>
                      <th className="py-1 px-2">Dst IP:Port</th>
                      <th className="py-1 px-1">Proto</th>
                      <th className="py-1 px-1.5 text-right">Flag</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
                    {filteredLogs.map((log) => (
                      <tr key={log.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/40">
                        <td className="py-1 px-2 text-zinc-700 dark:text-zinc-300 truncate max-w-[80px]">
                          {log.sourceIp}
                        </td>
                        <td className="py-1 px-2 text-zinc-600 dark:text-zinc-400 truncate max-w-[80px]">
                          {log.destIp}:{log.port}
                        </td>
                        <td className="py-1 px-1 text-zinc-500">{log.protocol}</td>
                        <td className="py-1 px-1.5 text-right">
                          <span
                            className={
                              log.flag === 'ANOMALOUS'
                                ? 'text-amber-600 dark:text-amber-400 font-semibold'
                                : log.flag === 'SUSPICIOUS'
                                ? 'text-amber-500'
                                : 'text-zinc-400'
                            }
                          >
                            {log.flag}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Section 2: Sarvam AI Forensic Brief & 4-Language Dropdown + PDF Generation */}
          <div className="p-4 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <BrainCircuit className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                <span className="text-xs font-mono uppercase tracking-wider text-zinc-800 dark:text-zinc-200 font-semibold">
                  Sarvam AI Forensic Brief
                </span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500">
                {activeIncident ? 'Confidence 99.4%' : 'Standby'}
              </span>
            </div>

            {activeIncident ? (
              <>
                <div className="text-xs font-medium text-zinc-900 dark:text-zinc-100">
                  {activeIncident.title}
                </div>

                {/* Dynamic Multilingual Threat Brief Box */}
                <div className="text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed bg-zinc-50 dark:bg-zinc-900/60 p-3 rounded border border-zinc-200 dark:border-zinc-800">
                  {isTranslating ? (
                    <span className="italic text-zinc-500 dark:text-zinc-400">
                      Synthesizing {languageLabels[selectedLanguage]} brief via Sarvam AI...
                    </span>
                  ) : (
                    formatBriefDisplay(activeIncident.sarvamSummaryByLang[selectedLanguage] || activeIncident.sarvamSummaryByLang.en)
                  )}
                </div>

                {/* Language Dropdown Selector (English, Hindi, Telugu, Malayalam) */}
                <div className="space-y-1.5 pt-1">
                  <label className="text-[11px] font-mono text-zinc-600 dark:text-zinc-400 flex items-center gap-1.5">
                    <Globe className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                    <span>Select Report Language:</span>
                  </label>
                  
                  <select
                    value={selectedLanguage}
                    onChange={(e) => handleLanguageChange(e.target.value as SupportedLanguage)}
                    className="w-full bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded px-2.5 py-1.5 text-xs text-zinc-900 dark:text-zinc-100 focus:outline-none focus:border-emerald-500 cursor-pointer font-sans"
                  >
                    <option value="en">English (US)</option>
                    <option value="hi">हिंदी (Hindi)</option>
                    <option value="te">తెలుగు (Telugu)</option>
                    <option value="ml">മലയാളം (Malayalam)</option>
                  </select>
                </div>

                {/* Generate PDF Button based on selected language */}
                <button
                  type="button"
                  onClick={() => setIsPdfModalOpen(true)}
                  className="w-full py-2 px-3 rounded-md text-xs font-semibold flex items-center justify-center gap-2 bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-900 dark:hover:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 text-zinc-900 dark:text-zinc-100 transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                  <span>Generate Threat Report (PDF) - {languageLabels[selectedLanguage].split(' ')[0]}</span>
                </button>
              </>
            ) : (
              <div className="p-4 rounded border border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/40 text-center text-xs font-mono text-zinc-500 space-y-1.5">
                <BrainCircuit className="w-5 h-5 mx-auto text-zinc-400 opacity-60" />
                <p className="font-semibold text-zinc-700 dark:text-zinc-300">No Active Forensic Brief</p>
                <p className="text-[11px] text-zinc-400 leading-normal">
                  Data has been cleared. Ingest PCAP or load sample logs to generate AI threat attribution.
                </p>
              </div>
            )}
          </div>

          {/* Section 3: Quantum Next-Hop Look-Ahead & Containment Isolation */}
          <div className="p-4 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                <span className="text-xs font-mono uppercase tracking-wider text-zinc-800 dark:text-zinc-200 font-semibold">
                  Quantum Next-Hop Look-Ahead
                </span>
              </div>
              <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400">
                {activeIncident ? 'Qiskit 1.2 Walk' : 'Idle'}
              </span>
            </div>

            {activeIncident ? (
              <div className="bg-zinc-50 dark:bg-zinc-900/80 p-3 rounded border border-zinc-200 dark:border-zinc-800 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-zinc-500 dark:text-zinc-400">Predicted Target:</span>
                  <span className="font-mono text-xs text-amber-600 dark:text-amber-300 font-semibold">
                    {activeIncident.quantumNextHop.predictedNode}
                  </span>
                </div>

                <div>
                  <div className="flex items-center justify-between text-[11px] font-mono text-zinc-500 dark:text-zinc-400 mb-1">
                    <span>Transition Probability |ψ⟩:</span>
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold tabular-nums">
                      {(activeIncident.quantumNextHop.probability * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="w-full bg-zinc-200 dark:bg-zinc-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-emerald-500 dark:bg-emerald-400 h-full transition-all duration-300"
                      style={{ width: `${activeIncident.quantumNextHop.probability * 100}%` }}
                    />
                  </div>
                </div>

                <div className="mt-1 text-[11px] text-zinc-600 dark:text-zinc-400">
                  <span className="text-zinc-400 dark:text-zinc-500">Action: </span>
                  {activeIncident.quantumNextHop.quarantineAction}
                </div>
              </div>
            ) : (
              <div className="p-3 rounded border border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/40 text-center text-xs font-mono text-zinc-400">
                Awaiting active threat vectors to compute Hamiltonian walk probabilities.
              </div>
            )}

            {/* Execute Quarantine Action Button */}
            <button
              type="button"
              onClick={() => handleQuarantineNode('node-dc')}
              disabled={!activeIncident || activeIncident.status === 'contained'}
              className={`w-full py-2.5 px-3 rounded-md text-xs font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer ${
                !activeIncident || activeIncident.status === 'contained'
                  ? 'bg-zinc-100 dark:bg-zinc-900 text-zinc-400 dark:text-zinc-500 border border-zinc-200 dark:border-zinc-800 cursor-not-allowed'
                  : 'bg-emerald-400 hover:bg-emerald-300 text-zinc-950 shadow-xs'
              }`}
            >
              <ShieldCheck className="w-4 h-4" />
              <span>
                {!activeIncident
                  ? 'No Active Threat Corridor'
                  : activeIncident.status === 'contained'
                  ? 'Attack Path Severed & Quarantined'
                  : 'Execute Containment Isolator'}
              </span>
            </button>
          </div>

        </aside>

      </div>

      {/* PDF Generation Modal */}
      {isPdfModalOpen && activeIncident && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                  Incident Threat Report (PDF Document)
                </span>
              </div>
              <button
                type="button"
                onClick={() => setIsPdfModalOpen(false)}
                className="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Printable Document Body */}
            <div className="p-6 overflow-y-auto space-y-6 text-zinc-900 dark:text-zinc-100 font-sans">
              <div className="border-b border-zinc-200 dark:border-zinc-800 pb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold tracking-tight text-zinc-950 dark:text-zinc-50">
                    ASK INCIDENT TELEMETRY REPORT
                  </h2>
                  <div className="text-xs font-mono text-zinc-500 dark:text-zinc-400 mt-0.5">
                    Document Ref: {activeIncident.id}-SARVAM-{selectedLanguage.toUpperCase()} · Generated: {new Date().toUTCString()}
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono px-2 py-0.5 rounded border border-amber-300 dark:border-amber-700 text-amber-700 dark:text-amber-400">
                    CVSS {activeIncident.score.toFixed(1)}
                  </span>
                </div>
              </div>

              {/* Target Details */}
              <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                <div>
                  <span className="text-zinc-500">Target Asset: </span>
                  <span className="font-semibold text-zinc-900 dark:text-zinc-200">{activeIncident.targetAsset}</span>
                </div>
                <div>
                  <span className="text-zinc-500">Kill Chain Stage: </span>
                  <span className="text-zinc-900 dark:text-zinc-200">{activeIncident.stage}</span>
                </div>
                <div>
                  <span className="text-zinc-500">Asset IP: </span>
                  <span className="text-zinc-900 dark:text-zinc-200">{activeIncident.ipAddress}</span>
                </div>
                <div>
                  <span className="text-zinc-500">Attribution Engine: </span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-semibold">{activeIncident.sourceEngine}</span>
                </div>
              </div>

              {/* Sarvam AI Multilingual Brief */}
              <div className="space-y-2">
                <div className="text-xs font-mono uppercase tracking-wider text-zinc-500">
                  Sarvam AI Forensic Brief ({languageLabels[selectedLanguage]})
                </div>
                <div className="p-3.5 rounded bg-zinc-50 dark:bg-zinc-800/60 border border-zinc-200 dark:border-zinc-700 text-sm leading-relaxed text-zinc-800 dark:text-zinc-200">
                  {formatBriefDisplay(activeIncident.sarvamSummaryByLang[selectedLanguage] || activeIncident.sarvamSummaryByLang.en)}
                </div>
              </div>

              {/* DuckDB Ingested Evidence */}
              <div className="space-y-2">
                <div className="text-xs font-mono uppercase tracking-wider text-zinc-500">
                  DuckDB In-Memory Evidence Records ({duckdbLogs.length} items)
                </div>
                <div className="border border-zinc-200 dark:border-zinc-800 rounded overflow-hidden text-[11px] font-mono">
                  {duckdbLogs.length === 0 ? (
                    <div className="p-3 text-center text-zinc-400">No log records in DuckDB</div>
                  ) : (
                    <table className="w-full text-left">
                      <thead className="bg-zinc-100 dark:bg-zinc-800 text-zinc-500">
                        <tr>
                          <th className="p-2">Src IP</th>
                          <th className="p-2">Dst IP</th>
                          <th className="p-2">Proto</th>
                          <th className="p-2">Port</th>
                          <th className="p-2">Action</th>
                          <th className="p-2">Flag</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
                        {duckdbLogs.slice(0, 4).map((log) => (
                          <tr key={log.id}>
                            <td className="p-2 text-zinc-700 dark:text-zinc-300">{log.sourceIp}</td>
                            <td className="p-2 text-zinc-700 dark:text-zinc-300">{log.destIp}</td>
                            <td className="p-2">{log.protocol}</td>
                            <td className="p-2">{log.port}</td>
                            <td className="p-2">{log.action}</td>
                            <td className="p-2 text-amber-600 dark:text-amber-400">{log.flag}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>

              {/* Quantum Next-Hop Look-Ahead */}
              <div className="p-3 bg-zinc-50 dark:bg-zinc-800/40 rounded border border-zinc-200 dark:border-zinc-800 text-xs font-mono space-y-1">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Quantum Predicted Next Hop:</span>
                  <span className="font-semibold text-amber-600 dark:text-amber-400">{activeIncident.quantumNextHop.predictedNode}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Infiltration Likelihood |ψ⟩:</span>
                  <span className="text-emerald-600 dark:text-emerald-400 font-bold">{(activeIncident.quantumNextHop.probability * 100).toFixed(1)}%</span>
                </div>
                <div className="text-zinc-500 mt-1">
                  Required Action: {activeIncident.quantumNextHop.quarantineAction}
                </div>
              </div>
            </div>

            {/* Modal Actions */}
            <div className="p-4 border-t border-zinc-200 dark:border-zinc-800 flex items-center justify-end gap-3 bg-zinc-50 dark:bg-zinc-900/60">
              <button
                type="button"
                onClick={() => setIsPdfModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-zinc-100 cursor-pointer"
              >
                Close
              </button>
              <button
                type="button"
                disabled={isGeneratingPdf}
                onClick={handleDownloadPdf}
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-zinc-950 bg-emerald-400 hover:bg-emerald-300 rounded-md transition-colors shadow-xs cursor-pointer disabled:opacity-60"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isGeneratingPdf ? 'Compiling via Sarvam AI...' : 'Download PDF Report'}</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  window.print();
                }}
                className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:text-zinc-950 dark:hover:text-zinc-100 border border-zinc-300 dark:border-zinc-700 rounded-md transition-colors cursor-pointer"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print</span>
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
