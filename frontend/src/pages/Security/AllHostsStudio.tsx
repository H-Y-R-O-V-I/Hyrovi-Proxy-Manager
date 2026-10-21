import { useMemo, useState } from "react";
import { IconActivity, IconArrowsSort, IconRefresh, IconSearch, IconServer, IconShieldCheck } from "@tabler/icons-react";
import type { AutomaticSiteActivity, SecuritySiteActivity } from "src/api/backend/securityVisitors";

const stamp = (date: string | null | undefined) =>
  date ? new Date(date).toLocaleString("de-DE") : "Kein Ereignis im Log-Ausschnitt";
type Source = "all" | "Pi" | "VPS";
type Order = "requests" | "browserViews" | "failures" | "automationSignals" | "last";
const value = (site: SecuritySiteActivity, sort: Order) =>
  sort === "last" ? Date.parse(site.browserLastSeen || site.latest || "") || 0 : site[sort] || 0;

export default function AllHostsStudio({data, loading, error, onRefresh, onTests, onVisitors, onSmart, testProfileCount}:{
  data?:AutomaticSiteActivity; loading:boolean; error:Error | null;
  onRefresh:()=>void; onTests:()=>void; onVisitors:()=>void; onSmart:()=>void;
  testProfileCount?:number
}) {
  const [search,setSearch]=useState("");
  const [source,setSource]=useState<Source>("all");
  const [sort,setSort]=useState<Order>("requests");
  const [selected,setSelected]=useState<string|null>(null);
  const [onlyWithTraffic,setOnlyWithTraffic]=useState(false);
  const sites = useMemo(() => (data?.websites || [])
    .filter(site => (source==="all" || site.source === source) &&
      (!search || site.host.toLowerCase().includes(search.trim().toLowerCase())) &&
      (!onlyWithTraffic || site.requests > 0 || site.browserViews > 0))
    .sort((a,b)=>value(b,sort)-value(a,sort)||a.host.localeCompare(b.host)),
    [data,source,sort,search,onlyWithTraffic]);
  const focused = sites.find(site=>site.source+":"+site.host===selected) || null;
  const recentEvents = useMemo(() => focused ? (data?.anonymousBrowserEvents || [])
    .filter(e=>e.host===focused.host && e.source===focused.source)
    .slice(0,40) : [], [data,focused]);
  const totalConfigured = (data?.websites || []).filter(s=>s.configured).length;
  const active = (data?.websites || []).filter(s=>s.requests>0 || s.browserViews>0).length;
  const counts = [
    {label:"Proxy-Hosts mit Sicherheitsintegration",value:data?totalConfigured:"—"},
    {label:"Hosts mit jüngster Aktivität",value:data?active:"—"},
    {label:"HTTP-Anfragen (Log-Ausschnitt)",value:data?.requests ?? "—"},
    {label:"Browser-Seitenaufrufe",value:data?.browserViews ?? "—"}
  ];
  return <div>
    <div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
      <div>
        <div className="text-secondary small mb-1">HYROVI SEC / USERS / MULTI-NODE</div>
        <h2 className="mb-1">Alle Hosts · Security Studio</h2>
        <p className="text-secondary mb-0">Zentrale Sicherheitsaktivität und Signaturtypen der HPM-Proxy-Hosts auf Pi und VPS.</p>
      </div>
      <div className="d-flex flex-wrap gap-2">
        <button type="button" className="btn btn-primary" onClick={onSmart}>HYROVI Smart</button>
        <button type="button" className="btn btn-outline-primary" onClick={onTests}>Live Test Studio</button>
        <button type="button" className="btn btn-primary" onClick={onVisitors}>Browser-Besuche & Profile</button>
        <button type="button" className="btn btn-primary" onClick={onRefresh}><IconRefresh size={16} className="me-1"/>Aktualisieren</button>
      </div>
    </div>
    <div className="alert alert-info py-2">
      Sicherheitslogging und das vorhandene Analytics-Skript werden durch die HPM-Proxy-Templates
      automatisch eingebunden. Die Werte basieren auf begrenzten Pi- und VPS-Log-Ausschnitten.
      Identische Header-Signaturen bedeuten nicht zwangsläufig dasselbe Gerät oder dieselbe Person.
      Sensible Inhalte und personenbezogene Browserprofile werden hier nicht zusammengeführt.
    </div>
    {error && <div className="alert alert-danger" role="alert">
      Daten konnten nicht geladen werden: {String(error)}
      <button type="button" className="btn btn-outline-danger ms-2" onClick={onRefresh}>Erneut versuchen</button>
    </div>}
    <div className="alert alert-secondary py-2">
      <strong>Browsererkennung:</strong> {data?.browserEvents ?? "—"} Browserereignisse im
      Auswertungsausschnitt, {data?.browserViews ?? "—"} gemeldete Seitenaufrufe;
      {" "}{testProfileCount ?? "—"} zusammengefasste Test-Browserprofile.
      Die Ereignisse anderer Websites werden nicht automatisch als unterschiedliche Personen gezählt.
      <button type="button" className="btn btn-sm btn-outline-primary ms-2 mt-1 mb-1"
        onClick={onVisitors}>Besucher und Ereignisse anzeigen</button>
    </div>
    <div className="row g-3 mb-3">
      {counts.map((item,i)=><div className="col-6 col-lg-3" key={item.label}>
        <div className="card"><div className="card-body">
          <div className="small text-secondary mb-2">{i===0?<IconShieldCheck size={16} className="me-1"/>:
            i===1?<IconServer size={16} className="me-1"/>:<IconActivity size={16} className="me-1"/>}{item.label}</div>
          <h2 className="mb-0">{item.value}</h2>
        </div></div>
      </div>)}
    </div>
    <div className="row g-3">
      <div className="col-lg-6">
        <div className="card">
          <div className="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
            <h3 className="card-title">Aktivitätsranking ({sites.length})</h3>
            <span className="badge bg-blue-lt"><IconArrowsSort size={14} className="me-1"/>Pi + VPS</span>
          </div>
          <div className="card-body">
            <div className="row g-2">
              <div className="col-12"><div className="input-icon">
                <span className="input-icon-addon"><IconSearch size={17}/></span>
                <input aria-label="Hosts suchen" className="form-control" value={search}
                  placeholder="Domain filtern…" onChange={e=>setSearch(e.target.value)}/>
              </div></div>
              <div className="col-6">
                <select className="form-select" aria-label="Node filtern" value={source}
                  onChange={e=>setSource(e.target.value as Source)}>
                  <option value="all">Alle Nodes</option><option value="Pi">Pi</option><option value="VPS">VPS</option>
                </select>
              </div>
              <div className="col-6">
                <select className="form-select" aria-label="Sortierung" value={sort}
                  onChange={e=>setSort(e.target.value as Order)}>
                  <option value="requests">Meiste HTTP-Anfragen</option>
                  <option value="browserViews">Meiste Browser-Aufrufe</option>
                  <option value="failures">Meiste HTTP-Fehler</option>
                  <option value="automationSignals">Meiste Bot-/Tool-Hinweise</option>
                  <option value="last">Zuletzt aktiv</option>
                </select>
              </div>
            </div>
            <label className="form-check mt-2 mb-0">
              <input type="checkbox" className="form-check-input" checked={onlyWithTraffic}
                onChange={e=>setOnlyWithTraffic(e.target.checked)}/>
              <span className="form-check-label">Nur Hosts mit jüngster Aktivität</span>
            </label>
          </div>
          <div className="list-group list-group-flush" style={{maxHeight:660,overflowY:"auto"}}>
            {loading && <div className="p-3 text-secondary" role="status">Lade Proxy-Hosts…</div>}
            {!loading && !error && sites.length===0 && <div className="p-3 text-secondary">Keine passenden Hosts im Auswertungsausschnitt.</div>}
            {sites.map((site,i)=>{
              const id=site.source+":"+site.host;
              return <button type="button" key={id} onClick={()=>setSelected(id)}
                className={"list-group-item list-group-item-action text-start "+(id===selected?"active":"")}>
                <div className="d-flex align-items-center justify-content-between flex-wrap gap-2">
                  <strong>#{i+1} · {site.host}</strong>
                  <span className="badge bg-secondary-lt">{site.source}</span>
                </div>
                <div className="small opacity-75 mt-1">
                  {site.requests} Requests · {site.browserViews} Browser-Aufrufe · {site.clientSignatures} Signaturtypen
                </div>
                <div className="small opacity-75">{site.failures} Fehler · {site.automationSignals} Bot-/Tool-Hinweise
                  {site.configured && site.requests===0 ? " · Kein aktueller Log-Eintrag" : ""}</div>
              </button>;
            })}
          </div>
        </div>
      </div>
      <div className="col-lg-6">
        {!focused ? <div className="card"><div className="card-body text-secondary">
          Wähle links einen Host. Hier siehst du sein Sicherheitsprofil, Bereiche und die verfügbaren Browserereignisse.
        </div></div> : <div className="d-flex flex-column gap-3">
          <div className="card">
            <div className="card-header"><h3 className="card-title text-break">{focused.host} <span className="badge bg-secondary-lt ms-2">{focused.source}</span></h3></div>
            <div className="card-body">
              <dl className="row mb-0">
                <dt className="col-6">Sicherheitsintegration</dt><dd className="col-6">{focused.configured?"HPM-Template erkannt":"Log-Traffic erkannt"}</dd>
                <dt className="col-6">HTTP-Anfragen</dt><dd className="col-6">{focused.requests}</dd>
                <dt className="col-6">Browser-Seitenaufrufe</dt><dd className="col-6">{focused.browserViews}</dd>
                <dt className="col-6">Header-Signaturtypen</dt><dd className="col-6">{focused.clientSignatures}</dd>
                <dt className="col-6">Bot-/Tool-Hinweise</dt><dd className="col-6">{focused.automationSignals}</dd>
                <dt className="col-6">HTTP-Fehler (4xx/5xx)</dt><dd className="col-6">{focused.failures}</dd>
                <dt className="col-6">Schreibanfragen</dt><dd className="col-6">{focused.writes}</dd>
                <dt className="col-6">Scroll-Ereignisse</dt><dd className="col-6">{focused.browserScroll}</dd>
                <dt className="col-6">Gemeldete Sichtbarkeit</dt><dd className="col-6">{focused.browserEngagementSeconds} s</dd>
                <dt className="col-6">Letzte Aktivität</dt><dd className="col-6">{stamp(focused.browserLastSeen||focused.latest)}</dd>
              </dl>
            </div>
            <div className="card-header"><h3 className="card-title">URL-Bereiche (aggregiert)</h3></div>
            <div className="table-responsive"><table className="table table-vcenter card-table">
              <thead><tr><th>Bereich</th><th>Anfragen</th></tr></thead>
              <tbody>{focused.sections.map(section=><tr key={section.section}>
                <td>{section.section}</td><td>{section.count}</td>
              </tr>)}
                {focused.sections.length===0 && <tr><td colSpan={2} className="text-secondary">Noch keine HTTP-Pfade im Log-Ausschnitt.</td></tr>}
              </tbody>
            </table></div>
          </div>
          <div className="card">
            <div className="card-header"><h3 className="card-title">Browser-Sicherheitsereignisse</h3></div>
            <div className="card-body text-secondary small">
              Ereignisse aus dem begrenzten VPS-Export, einzeln anklickbar, ohne verlässliche Besucherzuordnung.
              Pi-Ereignisse ohne Einwilligung werden hier nicht als Profile zusammengefasst.
            </div>
            <div className="list-group list-group-flush" style={{maxHeight:430,overflowY:"auto"}}>
              {recentEvents.map(e=><div key={e.id} className="list-group-item">
                <div className="d-flex justify-content-between gap-2 small">
                  <strong>{e.type==="page_view"?"Seite geöffnet":
                    e.type==="route_change"?"Seitenwechsel":
                    e.type==="scroll"?"Gescrollt":
                    e.type==="engagement"?"Seite sichtbar":"Aktion"}</strong>
                  <span className="text-secondary">{stamp(e.time)}</span>
                </div>
                <div className="small text-secondary">
                  {e.section}{e.type==="scroll"?" · "+e.scrollDepth+"%":""}
                  {e.type==="engagement"?" · "+e.visibleSeconds+"s":""}
                </div>
              </div>)}
              {!recentEvents.length && <div className="p-3 text-secondary small">
                Im jüngsten anonymen Browser-Ereignisausschnitt liegen für diesen Host keine Details vor.
              </div>}
            </div>
          </div>
        </div>}
      </div>
    </div>
    <p className="text-secondary small mt-3">
      Abfragen ungefähr alle 12 Sekunden; VPS-Aggregate werden etwa minütlich aktualisiert.
      Die Statistik ist kein vollständiges 24-Stunden-Archiv: Pi zählt die jüngsten 2 MiB
      des Proxy-Logs, VPS einen begrenzten Ausschnitt der letzten 24 Stunden.
      Kein automatisches Identitätsprofil oder Tracking privater Eingaben.
    </p>
  </div>;
}
