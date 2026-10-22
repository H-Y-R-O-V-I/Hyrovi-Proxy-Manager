import * as api from "./base";

export interface SecurityVisitor {
  id: string;
  name: string;
  notes: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
  pageViews: number;
  actions: number;
  active: boolean;
  interactive: boolean;
  engagementSeconds: number;
  lastVisibleAt: string | null;
  lastInteractiveAt: string | null;
  lastHost: string | null;
  lastPage: {host: string; path: string; at: string} | null;
  sessionDetails: Array<{id: string; host: string; firstSeen: string; lastSeen: string; pageViews: number; actions: number; visibleSeconds: number}>;
  sessions: number;
  sites: Array<{host: string; count: number}>;
  browsers: string[];
  platforms: string[];
  languages: string[];
  timezones: string[];
  viewports: string[];
}
export interface SecurityVisitorEvent {
  id: string; timestamp: string; host: string; type: string; path: string;
  action: string; referrerHost: string; scrollDepth: number; visibleSeconds: number;
  language: string; viewport: string;
}
export interface SecuritySiteActivity {
  host: string;
  configured?: boolean;
  source: "Pi" | "VPS";
  browserViews: number;
  browserActions: number;
  browserScroll: number;
  browserEngagementSeconds: number;
  browserLastSeen: string | null;
  requests: number;
  clientSignatures: number;
  automationSignals: number;
  pages: number;
  writes: number;
  failures: number;
  latest: string | null;
  sections: Array<{ section: string; count: number }>;
}
export interface AnonymousBrowserEvent {
  id: string; source: "VPS" | "Pi"; host: string;
  type: "page_view" | "route_change" | "scroll" | "engagement" | "action";
  time: string; section: string; scrollDepth: number; visibleSeconds: number;
}
export interface SmartSecuritySite {
  host: string;
  source: "Pi" | "VPS";
  configured: boolean;
  requests: number;
  failures: number;
  automationSignals: number;
  writes: number;
  clientSignatures: number;
  failurePercent: number;
  automationPercent: number;
  score: number | null;
  confidence: "sample-large" | "sample-limited" | "insufficient";
  assessment: "investigate" | "review" | "no-specific-signal" | "too-little-data";
  evidence: Array<{code: string; points: number; label: string; detail: string}>;
}
export interface SmartSecurityReport {
  schema: number; generatedAt: string; mode: "aggregate-security-only";
  coverage: string; totalHosts: number; analyzedHosts: number; hostsToReview: number;
  sites: SmartSecuritySite[];
}
export interface AutomaticSiteActivity {
  smart?: SmartSecurityReport;
  anonymousBrowserEvents: AnonymousBrowserEvent[];
  remoteGeneratedAt: string | null;
  browserViews: number;
  browserEvents: number;
  requests: number;
  window: string;
  websites: SecuritySiteActivity[];
}
// A dead/restarting HPM backend must not leave the mobile page in a forever-loading
// state. Some auth paths in the legacy API client intentionally return a never-resolving
// promise during a redirect; the per-call timeout also covers that case.
function boundedRequest<T>(run: (controller: AbortController) => Promise<T>, seconds = 12): Promise<T> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(new Error("Die HPM-API antwortet nicht. Bitte Verbindung oder Anmeldung prüfen und erneut versuchen."));
    }, seconds * 1000);
  });
  return Promise.race([run(controller), deadline]).finally(() => {
    if (timeout) clearTimeout(timeout);
  });
}

export interface SmartHostConfig {
  hosts: string[];
  available: string[];
  scope: "smart-dashboard-only";
}
export const getSmartHosts = (): Promise<SmartHostConfig> =>
  boundedRequest(controller => api.get({url:"/security/smart/hosts"},controller));
export const addSmartHost = (host:string): Promise<{hosts:string[]}> =>
  api.post({url:"/security/smart/hosts",data:{host}});
export const removeSmartHost = (host:string): Promise<{hosts:string[]}> =>
  api.del({url:"/security/smart/hosts/"+encodeURIComponent(host)});

export const getSecurityVisitors = (): Promise<{visitors: SecurityVisitor[]; totalEvents: number; note: string; automaticActivity: AutomaticSiteActivity}> =>
  boundedRequest((controller) => api.get({ url: "/security/visitors" }, controller));
export const getSecurityVisitor = (id: string): Promise<{visitor: SecurityVisitor; timeline: SecurityVisitorEvent[]}> =>
  boundedRequest((controller) => api.get({ url: "/security/visitors/" + encodeURIComponent(id) }, controller));
export const saveSecurityVisitor = (id: string, data: {name: string; notes: string}): Promise<{id: string; name: string; notes: string}> =>
  api.put({ url: "/security/visitors/" + encodeURIComponent(id), data });

export interface TestStudioEvent {
  at: string;
  kind: "page" | "button" | "scroll" | "heartbeat" | "section" | "visible";
  detail: string;
}
export interface TestStudioSession {
  id: string;
  name: string;
  browser: string;
  platform: string;
  language: string;
  signature: string;
  diagnostics: Record<string,string>;
  started: string;
  last: string;
  active: boolean;
  buttonActions: number;
  pageViews: number;
  sectionChanges: number;
  scrollActions: number;
  heartbeats: number;
  eventsCount: number;
  activityScore: number;
  durationSeconds: number;
  events?: TestStudioEvent[];
}
export interface TestStudioOverview {
  scope: string;
  online: boolean;
  generatedAt: string | null;
  sessions: TestStudioSession[];
  browsers: TestStudioBrowser[];
  total: number;
  active: number;
}
export const getTestStudioOverview = (): Promise<TestStudioOverview> =>
  boundedRequest((controller) => api.get({url:"/security/test-studio"}, controller), 8);
export const getTestStudioDetail = (id: string): Promise<{session:TestStudioSession; generatedAt:string}> =>
  boundedRequest((controller) => api.get({url:"/security/test-studio/"+encodeURIComponent(id)}, controller), 8);

export interface TestStudioBrowser {
  id: string;
  signature: string;
  name: string;
  browser: string;
  platform: string;
  language: string;
  diagnostics: Record<string,string>;
  firstSeen: string;
  last: string;
  active: boolean;
  sessionsCount: number;
  aliases: string[];
  sessionIds: string[];
  buttonActions: number;
  pageViews: number;
  sectionChanges: number;
  scrollActions: number;
  heartbeats: number;
  eventsCount: number;
  activityScore: number;
}
export interface TestStudioBrowserDetail {
  browser: TestStudioBrowser;
  sessions: TestStudioSession[];
  timeline: Array<TestStudioEvent & {sessionId: string; name: string}>;
  timelineTruncated: boolean;
  generatedAt: string;
}
export const getTestStudioBrowserDetail = (id: string): Promise<TestStudioBrowserDetail> =>
  boundedRequest((controller) => api.get({url:"/security/test-studio/browser/"+encodeURIComponent(id)},controller), 8);
