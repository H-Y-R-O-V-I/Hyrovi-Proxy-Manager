import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconActivity, IconDeviceDesktop, IconRefresh, IconUser } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import { getSecurityVisitor, getSecurityVisitors, saveSecurityVisitor } from "src/api/backend/securityVisitors";

const stamp = (value: string | null) => value ? new Date(value).toLocaleString() : "—";

export default function UsersStudio() {
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [mode, setMode] = useState<"activity" | "visitors">("activity");
  const [expandedSite, setExpandedSite] = useState<string | null>(null);
  const [activeOnly, setActiveOnly] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAnonEventId, setSelectedAnonEventId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const list = useQuery({
    queryKey: ["security-visitors"], queryFn: getSecurityVisitors,
    refetchInterval: mode === "visitors" ? 15_000 : 60_000, staleTime: 10_000, retry: false
  });
  const detail = useQuery({
    queryKey: ["security-visitor", selectedId],
    queryFn: () => getSecurityVisitor(selectedId || ""),
    enabled: mode === "visitors" && Boolean(selectedId), staleTime: 10_000, retry: false,
    refetchInterval: mode === "visitors" && selectedId ? 20_000 : false
  });
  const selected = detail.data?.visitor;
  useEffect(() => {
    if (selected) { setName(selected.name); setNotes(selected.notes); }
  }, [selected?.id, selected?.name, selected?.notes]);
  const save = useMutation({
    mutationFn: () => saveSecurityVisitor(selectedId || "", { name, notes }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["security-visitors"] });
      client.invalidateQueries({ queryKey: ["security-visitor", selectedId] });
    }
  });
  const filtered = useMemo(() => (list.data?.visitors || []).filter((visitor) => {
    const q = search.trim().toLowerCase();
    return (!activeOnly || visitor.active) && (!q || [visitor.name, visitor.id, visitor.browsers.join(" "),
      visitor.platforms.join(" "), ...visitor.sites.map((site) => site.host)]
      .join(" ").toLowerCase().includes(q));
  }), [list.data, search, activeOnly]);

  if (mode === "activity") {
    const traffic = list.data?.automaticActivity;
    const websites = (traffic?.websites || []).filter((website) =>
      !search.trim() || website.host.toLowerCase().includes(search.trim().toLowerCase())
    );
    const totalFailures = (traffic?.websites || []).reduce((sum, site) => sum + site.failures, 0);
    return <div>
      <div className="d-flex align-items-center justify-content-between gap-2 flex-wrap mb-3">
        <div><h2 className="mb-1">Users <span className="text-secondary">/ Übersicht</span></h2>
          <p className="text-secondary mb-0">Besuche über Pi und VPS, ohne individuelle Browser-Zuordnung</p></div>
        <div className="d-flex flex-wrap gap-2">
          <button className="btn btn-outline-primary" type="button" onClick={() => {setMode("visitors");setSearch("");}}>
            Liste · Browser-Besucher
          </button>
          <button className="btn btn-outline-secondary" type="button" onClick={() => list.refetch()}>
            <IconRefresh size={16}/> Refresh
          </button>
        </div>
      </div>
      <div className="alert alert-info py-2">
        HTTP-Anfragen kommen aus den Proxy-Logs. Browser-Seitenaufrufe stammen zusätzlich vom eingebundenen
        Website-Skript, auch auf dem VPS. Sie zeigen ausgeführtes JavaScript, aber keine verifizierten Menschen.
        Einzelne Besucher und ihre Aktionen erscheinen erst bei Zustimmung zur individuellen Analyse.
      </div>
      <div className="row g-3 mb-3">
        <div className="col-md-4"><div className="card"><div className="card-body">
          <div className="text-secondary small">HTTP-Anfragen (Pi + VPS)</div><h2 className="mb-0">{traffic?.requests ?? "—"}</h2>
        </div></div></div>
        <div className="col-md-4"><div className="card"><div className="card-body">
          <div className="text-secondary small">Browser-Seitenaufrufe (Pi + VPS)</div><h2 className="mb-0">{traffic?.browserViews ?? "—"}</h2>
        </div></div></div>
        <div className="col-md-4"><div className="card"><div className="card-body">
          <div className="text-secondary small">HTTP 4xx / 5xx</div><h2 className="mb-0">{traffic ? totalFailures : "—"}</h2>
        </div></div></div>
      </div>
      <div className="card">
        <div className="card-header d-flex align-items-center justify-content-between flex-wrap gap-2">
          <h3 className="card-title">Websites mit Aktivität ({websites.length})</h3>
          <input aria-label="Filter websites" className="form-control" style={{maxWidth:300}} placeholder="Domain filtern…"
            value={search} onChange={(e) => setSearch(e.target.value)}/>
        </div>
        {list.isLoading && <div className="p-3 text-secondary" role="status">
          Lade Proxy-Aktivität… (maximal 12 Sekunden)
        </div>}
        {list.isError && <div className="alert alert-danger m-3" role="alert">
          <strong>Die Website-Aktivität konnte nicht geladen werden.</strong>
          <div className="mt-2">{String((list.error as Error)?.message || list.error)}</div>
          <button className="btn btn-outline-danger mt-2" type="button" onClick={() => list.refetch()}>Erneut versuchen</button>
        </div>}
        {list.isSuccess && websites.length===0 && <p className="p-3 text-secondary">
          Im letzten Log-Ausschnitt ist kein Website-Traffic vorhanden.
        </p>}
        <div className="table-responsive">
          <table className="table table-vcenter card-table">
            <thead><tr><th>Website / Node</th><th>Browser-Aufrufe</th><th>HTTP-Anfragen</th><th>Schreibzugriffe</th><th>Fehler</th><th>Zuletzt</th></tr></thead>
            <tbody>
              {websites.map(site => <tr key={site.source + site.host}>
                <td>
                  <button type="button" className="btn btn-link p-0 text-start"
                    onClick={() => setExpandedSite(expandedSite===site.source+site.host ? null : site.source+site.host)}>
                    {site.host} {expandedSite===site.source+site.host?"−":"+"}
                  </button>
                  <span className="badge bg-secondary-lt ms-2">{site.source}</span>
                  {expandedSite===site.source+site.host && <div className="small mt-2 text-secondary">
                    {site.browserViews} Browser-Seitenaufrufe · {site.browserScroll} Scroll-Ereignisse · {site.browserEngagementSeconds} sichtbare Sekunden
                    {site.sections.map(section => <div key={section.section}>
                      {section.section} · {section.count} requests
                    </div>)}
                    <div className="mt-1">Nur aggregierte URL-Bereiche aus HTTP-Logs; keine individuellen IPs oder Browser-Sitzungen.</div>
                  </div>}
                </td>
                <td><strong>{site.browserViews}</strong></td><td>{site.requests}</td><td>{site.writes}</td>
                <td>{site.failures}</td><td className="small text-secondary">{stamp(site.browserLastSeen || site.latest)}</td>
              </tr>)}
            </tbody>
          </table>
        </div>
      </div>
      <p className="small text-secondary mt-3">{traffic?.window || "Jüngster Log-Ausschnitt"}.
        Browser-Aufrufe werden ohne individuelle Besucher-ID gezählt. VPS-Daten zuletzt synchronisiert:
        {traffic?.remoteGeneratedAt ? " " + stamp(traffic.remoteGeneratedAt) : " nicht verfügbar"}.</p>
    </div>;
  }

  return <div>
    <div className="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
      <div>
        <h2 className="mb-1">Users <span className="text-secondary">/ Liste · Fingerprint Studio</span></h2>
        <p className="text-secondary mb-0">Browserbesuche, aktive Sitzungen, Seiten und Aktionen</p>
      </div>
      <div className="d-flex flex-wrap gap-2">
      <button type="button" className="btn btn-outline-primary" onClick={() => {setMode("activity");setSearch("");}}>
        Übersicht
      </button>
      <button type="button" className="btn btn-outline-secondary"
        onClick={() => { list.refetch(); if (selectedId) detail.refetch(); }}>
        <IconRefresh size={16} className="me-1" /> Refresh
      </button></div>
    </div>
    <div className="alert alert-info py-2" role="status">
      Oben erscheinen anklickbare technische Browser-Ereignisse. Echte, wiedererkennbare Besucherprofile darunter benötigen eine separate Rechtsgrundlage und zuverlässige Zuordnung.
      Ein Browserereignis beweist keine menschliche Identität. Seitenbesuche, Sichtbarkeitszeit und
      allgemeine Link-/Button-Klicks werden erfasst, aber keine Formulare, Passwörter, Klickkoordinaten oder Eingaben.
    </div>
    <div className="row g-3 mb-3">
      <div className="col-sm-4"><div className="card"><div className="card-body d-flex align-items-center gap-3">
        <IconUser size={26} /><div><div className="text-secondary small">Erfasste Browser-Besucher</div>
          <h3 className="mb-0">{list.data?.visitors.length ?? "—"}</h3></div>
      </div></div></div>
      <div className="col-sm-4"><div className="card"><div className="card-body d-flex align-items-center gap-3">
        <IconActivity size={26} /><div><div className="text-secondary small">Ereignisse im Archiv</div>
          <h3 className="mb-0">{list.data?.totalEvents ?? "—"}</h3></div>
      </div></div></div>
      <div className="col-sm-4"><div className="card"><div className="card-body d-flex align-items-center gap-3">
        <IconDeviceDesktop size={26} /><div><div className="text-secondary small">Besuchte Websites</div>
          <h3 className="mb-0">{new Set((list.data?.visitors ?? []).flatMap(v => v.sites.map(s => s.host))).size}</h3></div>
      </div></div></div>
    </div>
    <div className="card mb-3">
      <div className="card-header"><h3 className="card-title">Browser-Sicherheitsereignisse · anklickbar</h3></div>
      <div className="card-body text-secondary small">
        Tatsächlich vom Browser gemeldete Ereignisse, auch ohne individuelle Analytics-Einwilligung.
        Wähle ein Ereignis, um Zeitpunkt, Website und den unkritischen URL-Bereich zu sehen.
        Verschiedene Ereignisse werden nicht ohne zuverlässige Zuordnung derselben Person zugeschrieben.
      </div>
      <div className="list-group list-group-flush" style={{maxHeight: 520, overflowY: "auto"}}>
        {(list.data?.automaticActivity?.anonymousBrowserEvents || []).slice(0, 80).map(event =>
          <button type="button" key={event.id}
            className={"list-group-item list-group-item-action text-start " + (selectedAnonEventId === event.id ? "active" : "")}
            onClick={() => setSelectedAnonEventId(selectedAnonEventId === event.id ? null : event.id)}>
            <div className="d-flex flex-wrap align-items-center justify-content-between gap-2">
              <strong>{event.host}</strong><span className="small">{stamp(event.time)}</span>
            </div>
            <div className="small opacity-75">{
              event.type === "page_view" ? "Seite geöffnet" :
              event.type === "route_change" ? "Seite gewechselt" :
              event.type === "scroll" ? "Gescrollt" :
              event.type === "engagement" ? "Seite sichtbar" : "Browseraktion"
            } · {event.section}</div>
            {selectedAnonEventId === event.id && <div className="mt-2 small">
              <strong>Ereignisdetails</strong>
              <div>Quelle: {event.source} · Zeitpunkt: {stamp(event.time)}</div>
              <div>Website: {event.host} · URL-Bereich: {event.section}</div>
              {event.type === "scroll" && <div>Scrolltiefe: {event.scrollDepth}%</div>}
              {event.type === "engagement" && <div>Sichtbar: {event.visibleSeconds} Sekunden</div>}
              <div className="mt-2">Einzelnes Ereignis; keine bestätigte Identität oder verbundene Sitzung.</div>
            </div>}
          </button>)}
        {list.isSuccess && !(list.data?.automaticActivity?.anonymousBrowserEvents || []).length &&
          <div className="p-3 text-secondary">Keine Browser-Ereignisse im jüngsten VPS-Ausschnitt.</div>}
      </div>
    </div>
    <div className="row g-3">
      <div className="col-lg-5">
        <div className="card">
          <div className="card-header"><h3 className="card-title">Liste der Besucher</h3></div>
          <div className="card-body d-flex flex-column gap-2">
            <input className="form-control" value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Name, Browser oder Website suchen…" aria-label="Besucher suchen"/>
            <label className="form-check">
              <input type="checkbox" className="form-check-input" checked={activeOnly}
                onChange={(e) => setActiveOnly(e.target.checked)}/>
              <span className="form-check-label">Nur kürzlich sichtbare Browser (letzte 2 Minuten)</span>
            </label>
          </div>
          <div className="list-group list-group-flush" style={{ maxHeight: 580, overflowY: "auto" }}>
            {list.isLoading && <div className="p-3 text-secondary">Loading visitors…</div>}
            {list.isError && <div className="p-3 text-danger" role="alert">
              Browser-Liste nicht geladen: {String((list.error as Error)?.message || list.error)}
              <button type="button" className="btn btn-outline-danger ms-2" onClick={() => list.refetch()}>Erneut versuchen</button>
            </div>}
            {list.isSuccess && filtered.length === 0 && <div className="p-3 text-secondary">
              Noch keine passenden Browserbesuche mit Einwilligung. Anonyme HTTP-Anfragen findest du unter Übersicht.
              Browser-Zuordnung wird nicht aus IP-Adressen oder Browser-Fingerprints geraten.
            </div>}
            {filtered.map(visitor => <button type="button" key={visitor.id}
              onClick={() => setSelectedId(visitor.id)}
              className={"list-group-item list-group-item-action " + (selectedId === visitor.id ? "active" : "")}>
                <div className="d-flex justify-content-between align-items-center gap-2">
                  <strong>{visitor.name || "Visitor " + visitor.id.slice(0, 9)}</strong>
                  <span className={"badge " + (visitor.active ? "bg-success-lt text-success" : visitor.interactive ? "bg-blue-lt text-blue" : "bg-secondary-lt")}>
                    {visitor.active ? "Kürzlich sichtbar" : visitor.interactive ? "Interaktion erfasst" : "Seitenbesuch"}
                  </span>
                </div>
                <div className="small opacity-75">{visitor.platforms.join(", ") || "Unknown platform"}
                  {" · "}{visitor.browsers.join(", ") || "Unknown browser"}</div>
                <div className="small opacity-75">{visitor.sites.length} Websites · {visitor.pageViews} Seiten · {visitor.actions} Aktionen</div>
                <div className="small opacity-75">Zuletzt {stamp(visitor.lastSeen)}</div>
                {visitor.lastPage && <div className="small text-break opacity-75">Letzte Seite: {visitor.lastPage.host}{visitor.lastPage.path}</div>}
              </button>)}
          </div>
        </div>
      </div>
      <div className="col-lg-7">
        {!selectedId ? <div className="card"><div className="card-body text-secondary">
          Wähle links einen Browser-Besucher aus, um die besuchten Websites, einzelne Sitzungen und
          die chronologische Ereignisliste zu sehen. Du kannst dem Profil einen Namen geben.
        </div></div> :
          <div className="d-flex flex-column gap-3">
            <div className="card">
              <div className="card-header"><h3 className="card-title">Browser-Profil</h3></div>
              <div className="card-body">
                {detail.isLoading && <p>Loading profile…</p>}
                {detail.error && <p className="text-danger">{String(detail.error)}</p>}
                {selected && <>
                  <div className="row g-2 mb-3">
                    <div className="col-md-6"><label className="form-label">Custom name</label>
                      <input className="form-control" value={name} maxLength={120} onChange={(e)=>setName(e.target.value)}
                        placeholder="e.g. Test device / known visitor"/></div>
                    <div className="col-md-6"><label className="form-label">Notes</label>
                      <input className="form-control" value={notes} maxLength={500} onChange={(e)=>setNotes(e.target.value)}
                        placeholder="Optional internal note"/></div>
                  </div>
                  <div className="d-flex align-items-center gap-2 mb-3">
                    <button type="button" className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>
                      {save.isPending ? "Saving…" : "Save profile"}
                    </button>
                    {save.isSuccess && <span className="text-success">Saved</span>}
                    {save.error && <span className="text-danger">{String(save.error)}</span>}
                  </div>
                  <div className="small text-secondary text-break mb-2">Pseudonymous consent ID: {selected.id}</div>
                  <dl className="row mb-0">
                    <dt className="col-sm-4">First seen</dt><dd className="col-sm-8">{stamp(selected.firstSeen)}</dd>
                    <dt className="col-sm-4">Last seen</dt><dd className="col-sm-8">{stamp(selected.lastSeen)}</dd>
                    <dt className="col-sm-4">Aktivität</dt><dd className="col-sm-8">{selected.active ? "Kürzlich sichtbar" : "Nicht aktuell sichtbar (oder kein frisches Signal)"}</dd>
                    <dt className="col-sm-4">Letzte Interaktion</dt><dd className="col-sm-8">{stamp(selected.lastInteractiveAt)}</dd>
                    <dt className="col-sm-4">Letzte Seite</dt><dd className="col-sm-8 text-break">{selected.lastPage ? selected.lastPage.host + selected.lastPage.path : "—"}</dd>
                    <dt className="col-sm-4">Sichtbarkeitszeit</dt><dd className="col-sm-8">{selected.engagementSeconds} Sekunden</dd>
                    <dt className="col-sm-4">Sitzungen</dt><dd className="col-sm-8">{selected.sessions}</dd>
                    <dt className="col-sm-4">Events / actions</dt><dd className="col-sm-8">{selected.count} / {selected.actions}</dd>
                    <dt className="col-sm-4">Browser</dt><dd className="col-sm-8">{selected.browsers.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Platform</dt><dd className="col-sm-8">{selected.platforms.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Languages</dt><dd className="col-sm-8">{selected.languages.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Timezone</dt><dd className="col-sm-8">{selected.timezones.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Viewport buckets</dt><dd className="col-sm-8">{selected.viewports.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Websites</dt><dd className="col-sm-8">{selected.sites.map(s => s.host + " (" + s.count + ")").join(" · ")}</dd>
                  </dl>
                </>}
              </div>
            </div>
            {selected && selected.sessionDetails.length > 0 && <div className="card">
              <div className="card-header"><h3 className="card-title">Sitzungen nach Website</h3></div>
              <div className="table-responsive">
                <table className="table table-vcenter card-table">
                  <thead><tr><th>Website</th><th>Erster / letzter Besuch</th><th>Seiten</th><th>Aktionen</th></tr></thead>
                  <tbody>{selected.sessionDetails.map((session) => <tr key={session.id}>
                    <td className="text-break">{session.host}</td>
                    <td className="small">{stamp(session.firstSeen)} → {stamp(session.lastSeen)}</td>
                    <td>{session.pageViews}</td><td>{session.actions}</td>
                  </tr>)}</tbody>
                </table>
              </div>
            </div>}
            <div className="card">
              <div className="card-header"><h3 className="card-title">Besuchte Seiten und Aktionen</h3></div>
              <div className="table-responsive" style={{maxHeight: 540, overflowY: "auto"}}>
                <table className="table table-vcenter card-table">
                  <thead><tr><th>Zeitpunkt</th><th>Website</th><th>Ereignis</th></tr></thead>
                  <tbody>{(detail.data?.timeline || []).map(event =>
                    <tr key={event.id}><td className="text-secondary small">{stamp(event.timestamp)}</td>
                      <td className="small text-break">{event.host}</td>
                      <td><span className="badge bg-blue-lt">{
                        event.type === "page_view" ? "Seite geöffnet" :
                        event.type === "route_change" ? "Seitenwechsel" :
                        event.type === "action" ? "Aktion" :
                        event.type === "engagement" ? "Seite sichtbar" :
                        event.type === "scroll" ? "Gescrollt" : event.type
                      }</span>
                        <div className="small text-break mt-1">{
                          event.type === "action" ?
                            (event.action === "link_click" ? "Link angeklickt" :
                              event.action === "button_click" ? "Button angeklickt" : event.action) :
                          event.type === "engagement" ? event.visibleSeconds + " Sekunden · " + event.path :
                          event.type === "scroll" ? event.scrollDepth + "% · " + event.path : event.path
                        }</div>
                      </td></tr>)}
                    {detail.data?.timeline.length === 0 && <tr><td colSpan={3}>Noch keine gespeicherten Ereignisse.</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          </div>}
      </div>
    </div>
    <p className="text-secondary small mt-3">Die Liste beruht ausschließlich auf zugestimmter Browser-Telemetrie und dem jüngsten Pi-HPM-Protokoll.
      „Kürzlich sichtbar“ bedeutet ein frisches Sichtbarkeitssignal, keine garantierte Anwesenheit einer Person.
      Websites am getrennten VPS-HPM erscheinen hier noch nicht.</p>
  </div>;
}
