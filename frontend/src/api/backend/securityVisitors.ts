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
export const getSecurityVisitors = (): Promise<{visitors: SecurityVisitor[]; totalEvents: number; note: string}> =>
  api.get({ url: "/security/visitors" });
export const getSecurityVisitor = (id: string): Promise<{visitor: SecurityVisitor; timeline: SecurityVisitorEvent[]}> =>
  api.get({ url: "/security/visitors/" + encodeURIComponent(id) });
export const saveSecurityVisitor = (id: string, data: {name: string; notes: string}): Promise<{id: string; name: string; notes: string}> =>
  api.put({ url: "/security/visitors/" + encodeURIComponent(id), data });
