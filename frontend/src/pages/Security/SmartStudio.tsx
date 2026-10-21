import { useMemo, useState } from "react";
import { IconArrowLeft, IconRefresh, IconShieldCheck } from "@tabler/icons-react";
import type { SmartSecurityReport, SmartSecuritySite } from "src/api/backend/securityVisitors";

const labels: Record<SmartSecuritySite["assessment"], string> = {
  "investigate": "Untersuchen",
  "review": "Prüfen",
  "no-specific-signal": "Keine auffälligen Signale im Ausschnitt",
  "too-little-data": "Zu wenige Daten",
};
const confidence: Record<SmartSecuritySite["confidence"], string> = {
  "sample-large": "Größerer Log-Ausschnitt",
  "sample-limited": "Begrenzter Log-Ausschnitt",
  "insufficient": "Keine Bewertung möglich",
};

export default function SmartStudio({ report, loading, error, onBack, onRefresh }: {
  report?: SmartSecurityReport;
  loading: boolean;
  error: Error | null;
  onBack: () => void;
  onRefresh: () => void;
}) {
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const sites = useMemo(() => (report?.sites || []).filter(site =>
    (site.host + " " + site.source).toLowerCase().includes(search.trim().toLowerCase())), [report, search]);
  const focused = sites.find(site => site.source + ":" + site.host === selected);
  return <div>
    <div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
      <div>
        <div className="small text-secondary">HYROVI SEC / HYROVI SMART / SECURITY</div>
        <h2 className="mb-1"><IconShieldCheck className="me-2"/>HYROVI Smart</h2>
        <p className="text-secondary mb-0">Automatische, erklärbare Sicherheitsanalyse der Proxy-Hosts auf Pi und VPS.</p>
      </div>
      <div className="d-flex gap-2 flex-wrap">
        <button type="button" className="btn btn-outline-secondary" onClick={onBack}><IconArrowLeft size={16}/> Zur Analytics</button>
        <button type="button" className="btn btn-primary" onClick={onRefresh}><IconRefresh size={16}/> Aktualisieren</button>
      </div>
    </div>
    <div className="alert alert-info">
      Kein Cookie, kein Browser-Fingerprinting und keine dauerhafte Geräte-ID für diese automatische Analyse.
      Es werden nur bereits vorhandene, aggregierte HTTP-Fehler-, Bot-/Tool- und Anfragezähler ausgewertet.
      Ein Hinweis ist <strong>kein Nachweis</strong> eines Angriffs. Die Beobachtungszeiträume von Pi und VPS unterscheiden sich.
      Das System blockiert nichts automatisch.
    </div>
    {error && <div className="alert alert-danger" role="alert">{String(error)} <button className="btn btn-outline-danger" onClick={onRefresh}>Erneut versuchen</button></div>}
    {loading && <p role="status" className="text-secondary">Lade HYROVI Smart…</p>}
    <div className="row g-3 mb-3">
      {[
        ["Proxy-Hosts", report?.totalHosts ?? "—"],
        ["Auswertbare Hosts", report?.analyzedHosts ?? "—"],
        ["Hosts mit Prüfhinweisen", report?.hostsToReview ?? "—"]
      ].map(([name, value]) => <div className="col-12 col-md-4" key={name}><div className="card"><div className="card-body">
        <div className="small text-secondary">{name}</div><h2 className="mb-0">{value}</h2>
      </div></div></div>)}
    </div>
    <div className="row g-3">
      <div className="col-lg-6"><div className="card">
        <div className="card-header"><h3 className="card-title">Sicherheitssignale pro Host</h3></div>
        <div className="card-body"><input className="form-control" aria-label="Smart Hosts filtern"
          placeholder="Domain oder Node suchen…" value={search} onChange={e => setSearch(e.target.value)} /></div>
        <div className="list-group list-group-flush" style={{maxHeight:600,overflowY:"auto"}}>
          {sites.map(site => <button type="button" key={site.source + ":" + site.host}
            className={"list-group-item list-group-item-action text-start " +
              (selected === site.source + ":" + site.host ? "active" : "")}
            onClick={() => setSelected(site.source + ":" + site.host)}>
            <div className="d-flex justify-content-between gap-2 flex-wrap"><strong>{site.host}</strong><span>{site.source}</span></div>
            <div className="small opacity-75 mt-1">{labels[site.assessment]}</div>
            <div className="small opacity-75">{site.requests} Requests · {site.failures} Fehler · {site.automationSignals} Tool-Signale</div>
          </button>)}
          {!loading && sites.length === 0 && <div className="p-3 text-secondary">Keine Daten im verfügbaren Log-Ausschnitt.</div>}
        </div>
      </div></div>
      <div className="col-lg-6">
        {!focused ? <div className="card"><div className="card-body text-secondary">Wähle links einen Host für die Analyse und ihre Begründungen.</div></div> :
          <div className="card"><div className="card-header"><h3 className="card-title text-break">{focused.host} ({focused.source})</h3></div>
            <div className="card-body">
              <h3>{labels[focused.assessment]}</h3>
              <p className="text-secondary small">{confidence[focused.confidence]}. Ein Wert von 0 ist kein Sicherheitsnachweis.</p>
              <dl className="row">
                <dt className="col-7">Signalpunktzahl</dt><dd className="col-5">{focused.score === null ? "Nicht bewertet" : focused.score + " / 100"}</dd>
                <dt className="col-7">HTTP-Fehlerquote</dt><dd className="col-5">{focused.failurePercent}%</dd>
                <dt className="col-7">Automations-Hinweise</dt><dd className="col-5">{focused.automationPercent}%</dd>
                <dt className="col-7">Header-Signaturtypen</dt><dd className="col-5">{focused.clientSignatures}</dd>
                <dt className="col-7">Schreibanfragen</dt><dd className="col-5">{focused.writes}</dd>
              </dl>
              <h4>Erklärungen</h4>
              {focused.evidence.length ? focused.evidence.map(item =>
                <div className="border rounded p-2 mb-2" key={item.code}>
                  <strong>{item.label}</strong><div className="text-secondary small">{item.detail}</div>
                </div>) : <p className="text-secondary">Keine der derzeit implementierten Regeln hat ausgelöst.</p>}
              <p className="text-secondary small mb-0">Heuristische Signale aus anonymen Host-Aggregaten. Keine Aussage darüber, wie viele verschiedene Geräte oder Menschen beteiligt waren.</p>
            </div></div>}
      </div>
    </div>
  </div>;
}
