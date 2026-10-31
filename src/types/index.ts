export type PageView = 'landing' | 'dashboard' | '404';

export type IncidentSeverity = 'critical' | 'high' | 'elevated' | 'medium';

export type SupportedLanguage = 'en' | 'hi' | 'te' | 'ml';

export interface DuckDBLogRow {
  id: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  protocol: string;
  port: number;
  bytes: number;
  action: 'ACCEPT' | 'REJECT';
  flag: 'ANOMALOUS' | 'SUSPICIOUS' | 'NORMAL';
  notes: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: IncidentSeverity;
  score: number;
  stage: string;
  targetAsset: string;
  ipAddress: string;
  detectedAt: string;
  sourceEngine: 'DuckDB' | 'Qiskit' | 'Sarvam AI';
  status: 'active' | 'investigating' | 'contained';
  description: string;
  sarvamSummaryByLang: Record<SupportedLanguage, string>;
  quantumNextHop: {
    predictedNode: string;
    probability: number;
    mitreTechnique: string;
    quarantineAction: string;
  };
}

export interface GraphNode {
  id: string;
  label: string;
  role: 'ingress' | 'bastion' | 'auth' | 'database' | 'domain-controller' | 'workstation';
  ip: string;
  status: 'compromised' | 'targeted' | 'quarantined' | 'secure';
  x: number;
  y: number;
  riskScore: number;
  quantumProbability: number;
  killChainStage: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  traversalProbability: number;
  protocol: string;
  isBreached: boolean;
  quantumPhase: string;
  killChainStep: number;
}
