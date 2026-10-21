import { useQuery } from "@tanstack/react-query";
import { IconArrowLeft, IconRefresh, IconChartBar, IconExternalLink } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import { getTestStudioOverview, getTestStudioDetail } from "src/api/backend/securityVisitors";

const fmt = (value: string | null | undefined) => value ? new Date(value).toLocaleString("de-DE") : "—";
const eventNames: Record<string,string> = {
  page:"Seitenaufruf", button:"Button-Aktion", section:"Bereichswechsel",
  scroll:"Scrolltiefe", heartbeat:"Aktivitätsmeldung", visible:"Sichtbarkeit",
};
const displayName: Record<string,string> = {
  timezone:"Zeitzone", screen:"Bildschirmklasse", viewport:"Viewport-Klasse",
  touch:"Touch-Punkte", cpu:"CPU-Kerne", memory:"Speicherklasse",
  theme:"Farbschema", motion:"Animationspräferenz", pixelRatio:"Pixeldichte",
  deviceType:"Geräteklasse", screenPixels:"Bildschirm (CSS-Pixel)",
  viewportPixels:"Fenster (CSS-Pixel)", colorDepth:"Farbtiefe",
  orientation:"Ausrichtung", connection:"Verbindungsqualität",
  features:"Unterstützte Browserfunktionen",
};
export default function SmartAnalyticsStudio({ onBack, onSecurity }: {
  onBack:()=>void; onSecurity:()=>void;
}) {
  const [query,setQuery] = useState("");
  const [selected,setSelected] = useState<string|null>(null);
  const report = useQuery({
    queryKey:["security-tests-studio"], queryFn:getTestStudioOverview,
    staleTime:3000,refetchInterval:6000,retry:1,
  });
  const detail = useQuery({
    queryKey:["security-smart-analytics-detail",selected],
    queryFn:()=>getTestStudioDetail(selected || ""),
    enabled:Boolean(selected),staleTime:3000,refetchInterval:selected?6000:false,retry:1,
  });
  // Session IDs, not fingerprints. Multiple sessions cannot be assumed to
  // come from the same physical device.
  const sessions = useMemo(() => (report.data?.sessions || [])
    .filter(x=>[x.name,x.browser,x.platform,x.language].join(" ").toLowerCase()
      .includes(query.trim().toLowerCase()))
    .sort((a,b)=>Date.parse(b.last)-Date.parse(a.last)),[report.data,query]);
  const chosen=detail.data?.session;
  const totalEvents=(report.data?.sessions||[]).reduce((n,s)=>n+s.eventsCount,0);
  return <div>
    <div className="d-flex flex-wrap justify-content-between gap-2 align-items-center mb-3">
      <div>
        <div className="small text-secondary">HYROVI SEC / USERS / SMART / ANALYTICS</div>
        <h2 className="mb-1"><IconChartBar className="me-2"/>HYROVI Smart · Analytics</h2>
        <p className="text-secondary mb-0">Gerätedetails und Aktionen für bewusst gestartete Testsitzungen – ohne Fingerprint-Matching.</p>
      </div>
      <div className="d-flex gap-2 flex-wrap">
        <button className="btn btn-outline-secondary" type="button" onClick={onBack}><IconArrowLeft size={16}/> Alle Hosts</button>
        <button className="btn btn-outline-secondary" type="button" onClick={onSecurity}>Sicherheitsanalyse</button>
        <button className="btn btn-primary" type="button" onClick={()=>{void report.refetch();if(selected)void detail.refetch();}}><IconRefresh size={16}/> Aktualisieren</button>
      </div>
    </div>
    <div className="alert alert-info">
      Testbereich: <a href="https://tests.hyrovi.com" target="_blank" rel="noopener noreferrer">tests.hyrovi.com <IconExternalLink size={14}/></a>.
      Daten werden erst nach „Test starten“ erfasst. Keine Cookies, dauerhaften Gerätekennungen,
      Bildschirmaufzeichnung, Texteingaben oder Aufzeichnung anderer Domains.
      Sitzungen werden nicht miteinander verknüpft. Aufbewahrung maximal 24 Stunden.
    </div>
    {report.isError && <div className="alert alert-danger">Analytics-Daten nicht erreichbar: {String(report.error)}</div>}
    <div className="row g-3 mb-3">
      {[
        ["Testsitzungen (24h)",report.data?.total ?? "—"],
        ["Aktive Sitzungen",report.data?.active ?? "—"],
        ["Gespeicherte Ereignisse",report.data?totalEvents:"—"],
      ].map(([label,value])=><div key={label} className="col-4"><div className="card">
        <div className="card-body"><div className="text-secondary small">{label}</div><h2 className="mb-0">{value}</h2></div>
      </div></div>)}
    </div>
    <div className="row g-3">
      <div className="col-lg-5"><div className="card">
        <div className="card-header"><h3 className="card-title">Testsitzungen</h3></div>
        <div className="card-body"><input aria-label="Analytics Sitzungen suchen" className="form-control"
          placeholder="Testname oder Browser suchen" value={query} onChange={e=>setQuery(e.target.value)}/></div>
        <div className="list-group list-group-flush" style={{maxHeight:600,overflowY:"auto"}}>
          {report.isLoading && <div role="status" className="p-3 text-secondary">Lade Sitzungen…</div>}
          {sessions.map(s=><button type="button" key={s.id} onClick={()=>setSelected(s.id)}
            className={"list-group-item list-group-item-action text-start "+(selected===s.id?"active":"")}>
            <div className="d-flex justify-content-between gap-2"><strong>{s.name}</strong><span>{s.active?"Live":"Beendet"}</span></div>
            <div className="small opacity-75">{s.browser} · {s.platform} · {s.eventsCount} Ereignisse</div>
            <div className="small opacity-75">Zuletzt: {fmt(s.last)}</div>
          </button>)}
          {!report.isLoading&&!sessions.length&&<p className="p-3 text-secondary">Noch keine gestarteten Testsitzungen im 24-Stunden-Zeitraum.</p>}
        </div>
      </div></div>
      <div className="col-lg-7">
        {!selected?<div className="card"><div className="card-body text-secondary">Wähle links eine Testsitzung, um Gerätedetails und die Ereignis-Timeline zu sehen.</div></div>:
         <div className="card">
          <div className="card-header"><h3 className="card-title">Geräte- und Sitzungsdetails</h3></div>
          {detail.isLoading&&<div className="p-3 text-secondary">Lade Ereignisse…</div>}
          {detail.isError&&<div className="p-3 text-danger">Details konnten nicht geladen werden.</div>}
          {chosen&&<>
            <div className="card-body">
              <h3>{chosen.name}</h3>
              <div className="small text-secondary">Browser: {chosen.browser} · Betriebssystem: {chosen.platform} · Sprache: {chosen.language||"—"}</div>
              <dl className="row mt-3 mb-1">
                <dt className="col-5">Start</dt><dd className="col-7">{fmt(chosen.started)}</dd>
                <dt className="col-5">Letzte Aktivität</dt><dd className="col-7">{fmt(chosen.last)}</dd>
                <dt className="col-5">Ereignisse</dt><dd className="col-7">{chosen.eventsCount}</dd>
                <dt className="col-5">Seiten / Buttons</dt><dd className="col-7">{chosen.pageViews} / {chosen.buttonActions}</dd>
              </dl>
              <h4 className="mt-3">Browser- und Gerätedetails</h4>
              <div className="row g-2">{Object.entries(chosen.diagnostics||{}).map(([key,value])=>
                <div className="col-sm-6" key={key}><div className="border rounded p-2 h-100">
                  <div className="small text-secondary">{displayName[key]||key}</div>
                  <strong className="text-break">{value}</strong>
                </div></div>)}</div>
              {!Object.keys(chosen.diagnostics||{}).length&&<p className="text-secondary">Keine zusätzlichen Diagnosedaten.</p>}
            </div>
            <div className="card-header"><h3 className="card-title">Ereignis-Timeline</h3></div>
            <div className="table-responsive" style={{maxHeight:550,overflowY:"auto"}}>
              <table className="table table-vcenter card-table">
                <thead><tr><th>Zeit</th><th>Ereignis</th></tr></thead>
                <tbody>{(chosen.events||[]).slice().reverse().map((e,i)=>
                  <tr key={i}><td className="small text-secondary" style={{whiteSpace:"nowrap"}}>{fmt(e.at)}</td>
                    <td>{eventNames[e.kind]||e.kind} <span className="text-secondary">· {e.detail}</span></td></tr>)}
                </tbody>
              </table>
            </div>
            {chosen.eventsCount>(chosen.events?.length||0)&&<p className="small text-secondary p-2">Es werden nur die neuesten Ereignisse übertragen.</p>}
          </>}
         </div>}
      </div>
    </div>
  </div>;
}
