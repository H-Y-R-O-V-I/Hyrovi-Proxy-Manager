// HYROVI Smart: bounded, explainable per-host security indicators.
// Only existing aggregate counters: no new visitor or device identifiers.
const nonnegative = (value) => Number.isFinite(Number(value))
  ? Math.max(0, Math.min(1_000_000_000, Math.floor(Number(value)))) : 0;

export function analyzeSite(site) {
  const requests = nonnegative(site.requests);
  const failures = Math.min(requests, nonnegative(site.failures));
  const automation = Math.min(requests, nonnegative(site.automationSignals));
  const writes = Math.min(requests, nonnegative(site.writes));
  const signatures = nonnegative(site.clientSignatures);
  const percent = (count) => requests ? Math.round(1000 * count / requests) / 10 : 0;
  const evidence = [];
  let score = 0;

  // Low sample sizes must never be promoted to confident judgments.
  if (requests >= 20 && failures >= 10 && failures / requests >= 0.25) {
    const points = failures / requests >= 0.6 ? 40 : 25;
    score += points;
    evidence.push({ code: "http_errors", points, label: "Auffällige HTTP-Fehlerquote",
      detail: `${failures} von ${requests} Anfragen ergeben HTTP 4xx/5xx.` });
  }
  if (requests >= 20 && automation >= 5 && automation / requests >= 0.1) {
    const points = automation / requests >= 0.5 ? 35 : 20;
    score += points;
    evidence.push({ code: "automation_hints", points, label: "Automations-Hinweise",
      detail: `${automation} von ${requests} Anfragen haben typische Bot-/Tool-User-Agents.` });
  }
  // APIs legitimately have many writes: show as context, not as evidence of abuse.
  if (requests >= 20 && writes >= 10 && writes / requests >= 0.5) {
    evidence.push({ code: "write_activity", points: 0, label: "Viele Schreibanfragen",
      detail: `${writes} von ${requests} Anfragen nutzen POST/PUT/PATCH/DELETE (kein Angriffsbeweis).` });
  }
  const confidence = requests >= 100 ? "sample-large" : requests >= 20 ? "sample-limited" : "insufficient";
  return {
    host: String(site.host || "").slice(0, 253),
    source: site.source === "VPS" ? "VPS" : "Pi",
    configured: Boolean(site.configured),
    requests, failures, automationSignals: automation, writes, clientSignatures: signatures,
    failurePercent: percent(failures), automationPercent: percent(automation),
    score: confidence === "insufficient" ? null : Math.min(100, score),
    confidence,
    assessment: confidence === "insufficient" ? "too-little-data"
      : score >= 50 ? "investigate" : score >= 20 ? "review" : "no-specific-signal",
    evidence,
  };
}

export function analyzeAutomaticActivity(activity) {
  const sites = (Array.isArray(activity?.websites) ? activity.websites : [])
    .slice(0, 200).map(analyzeSite)
    .sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || b.requests - a.requests);
  return {
    schema: 1,
    generatedAt: new Date().toISOString(),
    mode: "aggregate-security-only",
    coverage: "per-host counters from bounded Pi/VPS proxy log windows; not individuals or unique devices",
    totalHosts: sites.length,
    analyzedHosts: sites.filter(s => s.score !== null).length,
    hostsToReview: sites.filter(s => s.assessment === "review" || s.assessment === "investigate").length,
    sites,
  };
}

export default { analyzeAutomaticActivity, analyzeSite };
