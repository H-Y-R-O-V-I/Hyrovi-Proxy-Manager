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
export interface AutomaticSiteActivity {
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

export const getSecurityVisitors = (): Promise<{visitors: SecurityVisitor[]; totalEvents: number; note: string; automaticActivity: AutomaticSiteActivity}> =>
  boundedRequest((controller) => api.get({ url: "/security/visitors" }, controller));
export const getSecurityVisitor = (id: string): Promise<{visitor: SecurityVisitor; timeline: SecurityVisitorEvent[]}> =>
  boundedRequest((controller) => api.get({ url: "/security/visitors/" + encodeURIComponent(id) }, controller));
export const saveSecurityVisitor = (id: string, data: {name: string; notes: string}): Promise<{id: string; name: string; notes: string}> =>
  api.put({ url: "/security/visitors/" + encodeURIComponent(id), data });
