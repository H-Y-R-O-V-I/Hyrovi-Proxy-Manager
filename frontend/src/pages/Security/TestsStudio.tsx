import { useQuery } from "@tanstack/react-query";
import { IconActivity, IconRefresh, IconUsers, IconWorld, IconArrowUpRight, IconClock } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import { getTestStudioBrowserDetail, getTestStudioOverview, type TestStudioEvent } from "src/api/backend/securityVisitors";

const time = (iso: string | null | undefined) => iso ? new Date(iso).toLocaleString("de-DE") : "—";
const when = (iso: string) => {
  const elapsed = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (elapsed < 60) return "vor " + elapsed + " Sek.";
  if (elapsed < 3600) return "vor " + Math.floor(elapsed / 60) + " Min.";
  return time(iso);
};
const eventLabel:Record<string,string> = {
  page:"Seite besucht",section:"Bereich gewechselt",button:"Testaktion",scroll:"Gescrollt",
  heartbeat:"Aktivitätsmeldung",visible:"Sichtbarkeit"
};
const detailLabel:Record<string,string> = {
  home:"Übersicht", features:"Features", activity:"Aktivität", about:"Info", tap:"Testbutton gedrückt",
  toggle:"Ansicht umgeschaltet",counter:"Zähler erhöht",reset:"Zurückgesetzt",
  scroll25:"25% Scrolltiefe",scroll50:"50% Scrolltiefe",scroll75:"75% Scrolltiefe",scroll100:"100% Scrolltiefe",
  visible:"Tab sichtbar",hidden:"Tab im Hintergrund",focus:"Fokus",open:"Geöffnet"
};
const formatEvent = (e:TestStudioEvent) => (eventLabel[e.kind]||e.kind) + " · " + (detailLabel[e.detail]||e.detail);

export default function TestsStudio({onOverview,onVisitors,initialBrowserId}:{
  onOverview:()=>void;onVisitors:()=>void;initialBrowserId?:string|null
}) {
  const [selectedId,setSelectedId] = useState<string|null>(initialBrowserId || null);
  const [query,setQuery] = useState("");
  const [activeOnly,setActiveOnly] = useState(false);
  const report = useQuery({
    queryKey:["security-tests-studio"],
    queryFn:getTestStudioOverview,
    staleTime:2000,
    refetchInterval:5000,
    refetchIntervalInBackground:false,
    retry:1
  });
  const details = useQuery({
    queryKey:["security-tests-browser",selectedId],
    queryFn:()=>getTestStudioBrowserDetail(selectedId || ""),
    enabled:!!selectedId,
    staleTime:2000,
    refetchInterval:selectedId?5000:false,
    retry:1
  });
  useEffect(()=>{
    if(selectedId && report.data && !(report.data.browsers||[]).some(s=>s.id===selectedId))setSelectedId(null);
  },[selectedId,report.data]);

  const rows = useMemo(()=>(report.data?.browsers||[])
    .filter(s=>(!activeOnly||s.active) && (!query || (s.name+" "+s.id+" "+s.aliases.join(" ")).toLowerCase().includes(query.trim().toLowerCase())))
    .sort((a,b)=>b.activityScore-a.activityScore || Date.parse(b.last)-Date.parse(a.last)),
    [report.data,query,activeOnly]);
  const top = rows[0];
  const allActions=(report.data?.sessions||[]).reduce((n,s)=>n+s.buttonActions+s.sectionChanges+s.scrollActions,0);
  const session=details.data?.browser;
  const timeline=details.data?.timeline || [];
  return <div>
    <div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
      <div>
        <div className="text-secondary small mb-1">HYROVI SEC / USERS / ISOLATED LAB</div>
        <h2 className="mb-1">Live Test Studio</h2>
        <p className="text-secondary mb-0">Browser-Profile mit zusammengefassten Testsitzungen auf <a href="https://tests.hyrovi.com/" target="_blank" rel="noopener noreferrer">tests.hyrovi.com <IconArrowUpRight size={14}/></a></p>
      </div>
      <div className="d-flex flex-wrap gap-2">
        <button type="button" className="btn btn-outline-secondary" onClick={onOverview}>Proxy-Übersicht</button>
        <button type="button" className="btn btn-outline-secondary" onClick={onVisitors}>Browser-Ereignisse</button>
        <button type="button" className="btn btn-primary" onClick={()=>{void report.refetch();if(selectedId)void details.refetch();}}>
          <IconRefresh size={16} className="me-1"/>Aktualisieren
        </button>
      </div>
    </div>
    <div className={"alert py-2 " + (report.data?.online ? "alert-success" : "alert-warning")} role="status">
      <strong>{report.data?.online ? "Live-Verbindung aktiv" : report.isLoading?"Testdaten werden geladen…":"Testdaten-Synchronisierung derzeit nicht verfügbar"}</strong>
      {" · "}Automatische Aktualisierung alle 5 Sekunden · Daten nur von tests.hyrovi.com
      {report.data?.generatedAt ? " · Stand " + time(report.data.generatedAt) : ""}
    </div>
    {report.isError && <div className="alert alert-danger" role="alert">
      Fehler bei der Abfrage: {String(report.error)}
      <button type="button" className="btn btn-outline-danger ms-2" onClick={()=>void report.refetch()}>Erneut versuchen</button>
    </div>}
    <div className="row g-3 mb-3">
      <div className="col-6 col-lg-3"><div className="card"><div className="card-body">
        <div className="text-secondary small"><IconUsers size={16} className="me-1"/>Browser-Profile (24h)</div>
        <h2 className="mb-0">{report.data ? (report.data.browsers||[]).length : "—"}</h2>
      </div></div></div>
      <div className="col-6 col-lg-3"><div className="card"><div className="card-body">
        <div className="text-secondary small"><IconActivity size={16} className="me-1"/>Jetzt aktiv</div>
        <h2 className="mb-0">{report.data ? (report.data.browsers||[]).filter(s=>s.active).length : "—"}</h2>
      </div></div></div>
      <div className="col-6 col-lg-3"><div className="card"><div className="card-body">
        <div className="text-secondary small"><IconWorld size={16} className="me-1"/>Testaktionen insgesamt</div>
        <h2 className="mb-0">{report.data ? allActions : "—"}</h2>
      </div></div></div>
      <div className="col-6 col-lg-3"><div className="card"><div className="card-body">
        <div className="text-secondary small"><IconClock size={16} className="me-1"/>Aktivster Browser</div>
        <h2 className="mb-0 text-truncate" style={{fontSize:20}}>{top?.name || "—"}</h2>
      </div></div></div>
    </div>
    <div className="row g-3">
      <div className="col-lg-5">
        <div className="card">
          <div className="card-header d-flex flex-wrap align-items-center justify-content-between gap-2">
            <h3 className="card-title">Aktivste Browser-Profile</h3>
            <span className="badge bg-blue-lt">Rangliste</span>
          </div>
          <div className="card-body d-flex flex-column gap-2">
            <input className="form-control" aria-label="Browser-Profile suchen" placeholder="Browser oder Testnamen suchen…"
              value={query} onChange={e=>setQuery(e.target.value)}/>
            <label className="form-check">
              <input className="form-check-input" type="checkbox" checked={activeOnly}
                onChange={e=>setActiveOnly(e.target.checked)}/>
              <span className="form-check-label">Nur aktive Browser</span>
            </label>
          </div>
          <div className="list-group list-group-flush" style={{maxHeight:650,overflowY:"auto"}}>
            {report.isLoading && <div className="p-3 text-secondary">Rangliste wird geladen…</div>}
            {report.isSuccess && rows.length===0 && <div className="p-3 text-secondary">
              Noch keine gestarteten Testsitzungen. Öffne <a href="https://tests.hyrovi.com/" target="_blank" rel="noopener noreferrer">tests.hyrovi.com</a>,
              tippe auf „Test starten“ und probiere die Buttons aus.
            </div>}
            {rows.map((s,idx)=><button key={s.id} type="button"
              className={"list-group-item list-group-item-action text-start "+(selectedId===s.id?"active":"")}
              onClick={()=>setSelectedId(s.id)}>
              <div className="d-flex align-items-center justify-content-between gap-2">
                <strong>#{idx+1} · {s.name}</strong>
                <span className={"badge "+(s.active?"bg-success-lt text-success":"bg-secondary-lt")}>
                  {s.active?"Live":"Zuletzt aktiv"}
                </span>
              </div>
              <div className="small opacity-75 mt-1"><strong>{s.sessionsCount} Testsitzung{s.sessionsCount===1?"":"en"}</strong> · {s.buttonActions} Buttons · {s.pageViews} Seiten · {s.sectionChanges} Wechsel · {s.scrollActions} Scrolls</div>
              <div className="small opacity-75">{s.browser} · {s.platform} · {s.activityScore} Punkte · {when(s.last)}</div>
            </button>)}
          </div>
        </div>
        <p className="text-secondary small mt-2">
          Aktivitätspunkte: Testbutton ×4, Bereichswechsel ×2, Seitenaufruf ×1, Scrollereignis ×1.
          Heartbeats erhöhen den Rang nicht. Neue Testsitzungen bleiben voneinander getrennt,
          auch wenn sie von demselben Gerät kommen. Für neue Tests wird kein Header-Fingerprint erzeugt.
          Eventuelle ältere Signaturen verschwinden mit der 24-Stunden-Aufbewahrung.
        </p>
      </div>
      <div className="col-lg-7">
        {!selectedId ? <div className="card"><div className="card-body text-secondary">
          Wähle links ein Browser-Profil. Hier erscheinen alle zugehörigen Testsitzungen und ihre gemeinsame Ereignisfolge.
        </div></div> : <div className="card">
          <div className="card-header"><h3 className="card-title">Browser-Profil und Testsitzungen</h3></div>
          {details.isLoading && <div className="p-3 text-secondary">Details werden geladen…</div>}
          {details.isError && <div className="p-3 text-danger">Die Sitzung konnte nicht geladen werden.</div>}
          {session && <>
            <div className="card-body">
              <div className="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
                <h3 className="mb-0">{session.name}</h3>
                <span className={"badge "+(session.active?"bg-success-lt text-success":"bg-secondary-lt")}>{session.active?"Aktiv":"Nicht aktiv"}</span>
              </div>
              <div className="small text-secondary text-break">Browser-Gruppen-ID: {session.id.slice(0,16)}…</div>
              <div className="small text-secondary mt-2">
                Keine geräteübergreifende Identifizierung.
                <div>{session.browser || "Unbekannt"} · {session.platform || "Unbekannt"} · Sprache {session.language || "—"}</div>
                <div>Neue Testsitzungen erhalten nur eine zufällige, auf diese Sitzung begrenzte Kennung.</div>
                <div className="mt-1">Weitere Testsitzungsnamen: {session.aliases.join(", ") || "—"}</div>
              </div>
              <dl className="row mt-3 mb-0">
                <dt className="col-5">Erstmals getestet</dt><dd className="col-7">{time(session.firstSeen)}</dd>
                <dt className="col-5">Zuletzt aktiv</dt><dd className="col-7">{when(session.last)}</dd>
                <dt className="col-5">Testsitzungen</dt><dd className="col-7">{session.sessionsCount}</dd>
                <dt className="col-5">Buttons</dt><dd className="col-7">{session.buttonActions}</dd>
                <dt className="col-5">Seitenwechsel</dt><dd className="col-7">{session.sectionChanges}</dd>
                <dt className="col-5">Ereignisse</dt><dd className="col-7">{session.eventsCount}</dd>
              </dl>
              <div className="small text-secondary mt-3"><strong>Weitere Testdiagnostik</strong></div>
              <div className="row g-1 small mt-1">
                {Object.entries(session.diagnostics||{}).map(([key,value])=><div className="col-6" key={key}>
                  <span className="text-secondary">{({timezone:"Zeitzone",screen:"Bildschirmklasse",viewport:"Viewport",touch:"Touch",cpu:"CPU-Klasse",memory:"RAM-Klasse",theme:"Farbschema",motion:"Bewegungen",pixelRatio:"Pixel-Dichte"} as Record<string,string>)[key]||key}: </span>{value}
                </div>)}
              </div>
              <div className="small text-secondary mt-3"><strong>Testsitzungen in diesem Browser-Profil</strong></div>
              <div className="mt-2 d-flex flex-column gap-1">
                {(details.data?.sessions||[]).map((test,index)=><div className="border rounded p-2 small" key={test.id}>
                  <strong>{index+1}. {test.name}</strong> · {time(test.started)} · {test.eventsCount} Ereignisse · {test.activityScore} Punkte
                </div>)}
              </div>
            </div>
            <div className="card-header"><h3 className="card-title">Gemeinsamer Aktivitätsverlauf · neueste zuerst</h3></div>
            <div className="table-responsive" style={{maxHeight:560,overflowY:"auto"}}>
              <table className="table table-vcenter card-table">
                <thead><tr><th>Uhrzeit</th><th>Aktion</th></tr></thead>
                <tbody>{timeline.map((e,i)=><tr key={i}>
                  <td className="text-secondary small" style={{whiteSpace:"nowrap"}}>{time(e.at)}</td>
                  <td className="text-break">{formatEvent(e)}<div className="text-secondary small">Testsitzung: {e.name}</div></td>
                </tr>)}
                  {!timeline.length && <tr><td colSpan={2} className="text-secondary">Noch keine Testereignisse.</td></tr>}
                </tbody>
              </table>
            </div>
            {details.data?.timelineTruncated && <p className="text-secondary small p-2">Nur die jüngsten 250 Ereignisse werden im Gesamtverlauf angezeigt.</p>}
          </>}
        </div>}
      </div>
    </div>
    <p className="text-secondary small mt-3">
      Isolierter Testmodus: keine systemweite Besucher-Wiedererkennung, keine Protokollierung von
      Passwörtern oder Eingabefeldern. Aufgezeichnet werden ausschließlich die definierten Aktionen,
      die nach dem Start auf tests.hyrovi.com ausgeführt wurden.
    </p>
  </div>;
}
