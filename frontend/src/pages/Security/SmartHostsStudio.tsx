import {useQuery, useMutation, useQueryClient} from "@tanstack/react-query";
import {useEffect, useMemo, useState} from "react";
import {IconPlus, IconRefresh, IconTrash, IconWorld, IconExternalLink} from "@tabler/icons-react";
import {
  getSecurityVisitors, getSecurityVisitor, getSmartHosts, addSmartHost, removeSmartHost,
} from "src/api/backend/securityVisitors";

const format = (time: string) => new Date(time).toLocaleString("de-DE");
const kind: Record<string,string> = {
  page_view:"Seitenaufruf",route_change:"Seitenwechsel",
  action:"Aktion",scroll:"Scrolltiefe",engagement:"Aktivität",
};

export default function SmartHostsStudio() {
  const qc = useQueryClient();
  const [newHost,setNewHost] = useState("");
  const [selected,setSelected] = useState<string|null>(null);
  const [selectedVisitor,setSelectedVisitor] = useState<string|null>(null);
  const config = useQuery({queryKey:["hyrovi-smart-hosts"],queryFn:getSmartHosts,
    staleTime:10000,refetchInterval:30000,retry:false});
  const activity = useQuery({queryKey:["security-visitors"],queryFn:getSecurityVisitors,
    refetchInterval:15000,staleTime:7000,retry:false});
  const details = useQuery({queryKey:["hyrovi-smart-visitor",selectedVisitor],queryFn:()=>getSecurityVisitor(selectedVisitor||""),
    enabled:Boolean(selectedVisitor),staleTime:10000,retry:false});
  const update = useMutation({
    mutationFn:(value:{host:string;enabled:boolean})=>value.enabled?addSmartHost(value.host):removeSmartHost(value.host),
    onSuccess:async()=>{await qc.invalidateQueries({queryKey:["hyrovi-smart-hosts"]});setNewHost("");},
  });
  const hosts=config.data?.hosts||[];
  const available=(config.data?.available||[]).filter(h=>!hosts.includes(h));
  useEffect(()=>{
    if(!config.data)return;
    if(!selected||!hosts.includes(selected))setSelected(hosts[0]||null);
  },[config.data,selected,hosts.join("|")]);
  useEffect(()=>{setSelectedVisitor(null);},[selected]);
  const sites=useMemo(()=>(activity.data?.automaticActivity.websites||[]).filter(x=>x.host===selected),
    [activity.data,selected]);
  const totals=sites.reduce((a,b)=>({
    requests:a.requests+b.requests,views:a.views+b.browserViews,actions:a.actions+b.browserActions,
    scroll:a.scroll+b.browserScroll,errors:a.errors+b.failures,
  }),{requests:0,views:0,actions:0,scroll:0,errors:0});
  const consented=(activity.data?.visitors||[]).filter(v=>v.sites.some(s=>s.host===selected));
  const events=(activity.data?.automaticActivity.anonymousBrowserEvents||[])
    .filter(e=>e.host===selected).slice(0,100);
  const selectedProfile=details.data?.visitor;
  const filteredTimeline=(details.data?.timeline||[]).filter(e=>e.host===selected).slice(0,100);
  return <div>
    <div className="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
      <div>
        <div className="small text-secondary">HYROVI SMART / HOST-VERWALTUNG</div>
        <h2 className="mb-1"><IconWorld className="me-2"/>Hosts & Analytics</h2>
        <p className="mb-0 text-secondary">Websites gezielt zu HYROVI Smart hinzufügen und ihre vorhandenen Analytics auswerten.</p>
      </div>
      <button type="button" className="btn btn-outline-secondary"
        onClick={()=>{void config.refetch();void activity.refetch();}}>
        <IconRefresh size={16}/> Aktualisieren
      </button>
    </div>
    <div className="alert alert-info">
      Diese Auswahl begrenzt die <strong>HYROVI-Smart-Ansicht</strong>. Sie installiert keine neuen Tracker
      und ändert nicht die bestehenden HPM-Proxy-Logs. Browserbasierte Besucherprofile
      entstehen nur bei freigegebener individueller Analyse; reine HTTP-Anfragen werden
      nicht als Personen oder Geräte ausgegeben.
    </div>
    {config.isError&&<div className="alert alert-danger" role="alert">Host-Verwaltung nicht erreichbar: {String(config.error)}</div>}
    {activity.isError&&<div className="alert alert-danger" role="alert">Analytics nicht erreichbar: {String(activity.error)}</div>}
    <div className="card mb-3">
      <div className="card-header"><h3 className="card-title">Ausgewählte Hosts ({hosts.length})</h3></div>
      <div className="card-body">
        {config.isLoading&&<p className="text-secondary">Lade Host-Konfiguration…</p>}
        <div className="d-flex flex-wrap gap-2 mb-3">
          {hosts.map(h=><div className="btn-group" key={h} role="group" aria-label={"Host "+h}>
            <button type="button" className={"btn "+(selected===h?"btn-primary":"btn-outline-primary")}
              onClick={()=>setSelected(h)}>{h}</button>
            <button type="button" className="btn btn-outline-danger"
              aria-label={"Host "+h+" aus Smart entfernen"} disabled={update.isPending}
              onClick={()=>update.mutate({host:h,enabled:false})}><IconTrash size={16}/></button>
          </div>)}
          {!config.isLoading&&!hosts.length&&<span className="text-secondary">Noch kein Host ausgewählt.</span>}
        </div>
        <div className="d-flex flex-wrap gap-2 align-items-center">
          <select className="form-select" style={{maxWidth:420}} aria-label="Weiteren Host auswählen"
            value={newHost} onChange={e=>setNewHost(e.target.value)}>
            <option value="">Weiteren vorhandenen HPM-Host wählen…</option>
            {available.map(h=><option key={h} value={h}>{h}</option>)}
          </select>
          <button type="button" className="btn btn-primary" disabled={!newHost||update.isPending}
            onClick={()=>update.mutate({host:newHost,enabled:true})}>
            <IconPlus size={17}/> Host hinzufügen
          </button>
        </div>
        {update.isError&&<div className="text-danger small mt-2" role="alert">{String(update.error)}</div>}
        {update.isSuccess&&<div className="text-secondary small mt-2">Host-Auswahl gespeichert.</div>}
        <div className="text-secondary small mt-2">
          Auswählbar sind verwaltete HPM-Hosts. tests.hyrovi.com bleibt ein separates Testlabor.
        </div>
      </div>
    </div>
    {selected&&<>
      <div className="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
        <h3 className="mb-0">{selected}</h3>
        <a className="btn btn-outline-secondary btn-sm" href={"https://"+selected}
          target="_blank" rel="noopener noreferrer">Website öffnen <IconExternalLink size={14}/></a>
      </div>
      <div className="row g-2 mb-3">
        {[
          ["Proxy-Anfragen",totals.requests],["Browser-Seitenereignisse",totals.views],
          ["Browser-Aktionen",totals.actions],["Scroll-Ereignisse",totals.scroll],
          ["HTTP-Fehler",totals.errors],["Freigegebene Besucherprofile",consented.length]
        ].map(([label,value])=><div className="col-6 col-lg-4" key={label}>
          <div className="card h-100"><div className="card-body">
            <div className="small text-secondary">{label}</div><h2 className="mb-0">{activity.isLoading?"—":value}</h2>
          </div></div>
        </div>)}
      </div>
      <p className="small text-secondary">
        Pi: begrenzter jüngster Proxy-Log-Ausschnitt · VPS: bis zu 24 Stunden verfügbarer Log-Ausschnitt.
        Zahlen sind keine Anzahl verschiedener Geräte oder Menschen.
      </p>
      <div className="row g-3">
        <div className="col-lg-6"><div className="card">
          <div className="card-header"><h3 className="card-title">Browser-Ereignisse (anonymisiert)</h3></div>
          <div className="table-responsive" style={{maxHeight:540,overflowY:"auto"}}>
            <table className="table table-vcenter card-table">
              <thead><tr><th>Zeit</th><th>Aktion / Bereich</th></tr></thead>
              <tbody>{events.map(e=><tr key={e.id}>
                <td className="small text-secondary" style={{whiteSpace:"nowrap"}}>{format(e.time)}</td>
                <td>{kind[e.type]||e.type} · {e.section}
                  {e.type==="scroll"?" · "+e.scrollDepth+"%":""}</td>
              </tr>)}
              {!events.length&&<tr><td colSpan={2} className="text-secondary">
                Keine anonymisierten Browser-Einzelereignisse im aktuellen Export.
              </td></tr>}
              </tbody>
            </table>
          </div>
        </div></div>
        <div className="col-lg-6"><div className="card">
          <div className="card-header"><h3 className="card-title">Individuell freigegebene Browserprofile</h3></div>
          <div className="list-group list-group-flush" style={{maxHeight:330,overflowY:"auto"}}>
            {consented.map(v=><button type="button" key={v.id}
              className={"list-group-item list-group-item-action text-start "+(selectedVisitor===v.id?"active":"")}
              onClick={()=>setSelectedVisitor(v.id)}>
              <strong>{v.name||v.browsers.join(", ")||"Browserprofil"}</strong>
              <div className="small opacity-75">{v.platforms.join(", ")||"Plattform unbekannt"}
                {" · "}{v.sites.find(s=>s.host===selected)?.count||0} Ereignisse</div>
            </button>)}
            {!consented.length&&<div className="p-3 text-secondary">
              Noch keine freigegebenen Besucherprofile für diesen Host. Anonyme Ereignisse
              lassen sich nicht zuverlässig einem konkreten Gerät zuordnen.
            </div>}
          </div>
          {selectedVisitor&&<div className="card-body border-top">
            {details.isLoading&&<p className="text-secondary">Lade Profil…</p>}
            {details.isError&&<p className="text-danger">Profil derzeit nicht abrufbar.</p>}
            {selectedProfile&&<>
              <strong>{selectedProfile.name||"Freigegebenes Browserprofil"}</strong>
              <p className="small text-secondary mb-2">
                {selectedProfile.browsers.join(", ")} · {selectedProfile.platforms.join(", ")}
                {" · "}{selectedProfile.languages.join(", ")}
              </p>
              <div style={{maxHeight:250,overflowY:"auto"}}>
                {filteredTimeline.map(e=><div className="border-bottom py-1 small" key={e.id}>
                  {format(e.timestamp)} · {kind[e.type]||e.type} · {e.path}
                </div>)}
                {!filteredTimeline.length&&<p className="text-secondary">Keine Ereignisse für diesen Host.</p>}
              </div>
            </>}
          </div>}
        </div></div>
      </div>
    </>}
  </div>;
}
