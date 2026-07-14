export type CaptureMode = "gateway" | "proxy";
export type CaptureStatus = "complete" | "streaming" | "error";
export type EvidenceLevel = "observed" | "derived" | "unknown";
export type InspectorTab = "anatomy" | "timeline" | "raw";

export interface CaptureState {
  active: boolean;
  mode: CaptureMode;
  profile: string;
  endpoint: string;
  storage: string;
  requestCount: number;
}

export interface AnatomyItem {
  id: string;
  label: string;
  role?: string;
  content: string;
  source: string;
}

export interface AnatomySection {
  id: string;
  title: string;
  tokenCount?: number;
  count: number;
  evidence: EvidenceLevel;
  items: AnatomyItem[];
}

export interface TimelineEvent {
  id: string;
  offsetMs: number;
  kind: string;
  title: string;
  detail: string;
}

export interface RequestDetail {
  anatomy: AnatomySection[];
  timeline: TimelineEvent[];
  raw: Record<string, unknown>;
}

export interface CapturedRequest {
  id: string;
  time: string;
  application: string;
  provider: string;
  operation: string;
  model: string;
  tokens: number;
  durationMs: number;
  status: CaptureStatus;
  hasTools: boolean;
  promptPreview: string;
  detail: RequestDetail;
}

export interface WorkspaceBootstrap {
  fixture: "synthetic";
  capture: CaptureState;
  requests: CapturedRequest[];
}
