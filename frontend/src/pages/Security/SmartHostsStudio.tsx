import {useQuery, useMutation, useQueryClient} from "@tanstack/react-query";
import {useEffect, useMemo, useState} from "react";
import {IconPlus, IconRefresh, IconTrash, IconWorld, IconExternalLink, IconFilter} from "@tabler/icons-react";
import {
  getSecurityVisitors, getSecurityVisitor, getSmartHosts, addSmartHost, removeSmartHost,
  type SmartTrafficBreakdown,
} from "src/api/backend/securityVisitors";

// First-party browser enrollment initiated on the authenticated HPM dashboard.
// These names are only consumed by the Stoneapp proxy-injected script.
const STONEAPP_CONSENT="hyrovi_stoneapp_analytics_consent";
const STONEAPP_DEVICE="hyrovi_stoneapp_visitor_id";
const expires=90*86400;
const readCookie=(key:string)=>{
  try {return decodeURIComponent(document.cookie.split(";").map(s=>s.trim())
    .find(s=>s.startsWith(key+"="))?.slice(key.length+1)||"");}
  catch{return "";}
};
const registered=()=>readCookie(STONEAPP_CONSENT)==="1"&&
  /^[a-f0-9-]{16,64}$/.test(readCookie(STONEAPP_DEVICE));
const privacyBlocked=()=>navigator.doNotTrack==="1"||
  (navigator as Navigator & {globalPrivacyControl?:boolean}).globalPrivacyControl===true;
function setEnrollmentCookie(name:string,value:string,age:number){
  document.cookie=name+"="+encodeURIComponent(value)+"; Max-Age="+age+
    "; Domain=.hyrovi.com; Path=/; SameSite=Lax; Secure";
}
const format = (time: string) => new Date(time).toLocaleString("de-DE");
const botLabel:Record<string,string> = {
  bot:"Wahrscheinlich Bot",interactive:"Interaktionssignal",unknown:"Nicht bestimmbar",
};
const summaryKeys = [
  ["devices","botDevices","Geräteklassen"],
  ["browsers","botBrowsers","Browser"],
  ["platforms","botPlatforms","Betriebssysteme"],
  ["languageRegions","botLanguageRegions","Sprachregionen (kein Standort)"],
] as const;
const kind: Record<string,string> = {
  page_view:"Seitenaufruf",route_change:"Seitenwechsel",
  action:"Aktion",scroll:"Scrolltiefe",engagement:"Aktivität",
};

export default function SmartHostsStudio() {
  const qc = useQueryClient();
  const [newHost,setNewHost] = useState("");
  const [selected,setSelected] = useState<string|null>(null);
  const [selectedVisitor,setSelectedVisitor] = useState<string|null>(null);
  const [botFilter,setBotFilter] = useState<"hide"|"all"|"only">("hide");
  const [myDeviceRegistered,setMyDeviceRegistered]=useState(registered);
  const [deviceMessage,setDeviceMessage]=useState("");
  const enroll=()=>{
    if(privacyBlocked()){setDeviceMessage("Dein Browser deaktiviert individuelle Statistiken (DNT/GPC).");return;}
    const existing=readCookie(STONEAPP_DEVICE);
    const id=/^[a-f0-9-]{16,64}$/.test(existing)?existing:crypto.randomUUID();
    setEnrollmentCookie(STONEAPP_DEVICE,id,expires);
    setEnrollmentCookie(STONEAPP_CONSENT,"1",expires);
    const active=registered();setMyDeviceRegistered(active);
    setDeviceMessage(active?"Dieses Browserprofil ist registriert. Öffne Stoneapp im selben Browser, damit es in HPM erscheint.":
      "Browserregistrierung nicht möglich – prüfe, ob Cookies in diesem Browser zugelassen sind.");
  };
  const unenroll=()=>{
    setEnrollmentCookie(STONEAPP_CONSENT,"",0);
    setEnrollmentCookie(STONEAPP_DEVICE,"",0);
    setMyDeviceRegistered(registered());
    setDeviceMessage("Die Registrierung für zukünftige Besuche wurde in diesem Browser deaktiviert. Bereits gespeicherte Protokolle werden dadurch nicht rückwirkend gelöscht.");
  };
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
  const aggregate = sites.reduce((a,site)=>{
    const breakdown=site.smartBreakdown;
    if(!breakdown)return a;
    a.botRequests+=breakdown.botRequests||0;
    a.unknownRequests+=breakdown.unknownRequests||0;
    for(const [map] of summaryKeys){
      const botMap=("bot"+map.charAt(0).toUpperCase()+map.slice(1)) as keyof SmartTrafficBreakdown;
      for(const key of [map,botMap]){
        const target=a[key] as Record<string,number>;
        const data=breakdown[key] as Record<string,number>;
        for(const [label,count] of Object.entries(data||{})) target[label]=(target[label]||0)+count;
      }
    }
    return a;
  },{botRequests:0,unknownRequests:0,devices:{},browsers:{},platforms:{},languageRegions:{},
     botDevices:{},botBrowsers:{},botPlatforms:{},botLanguageRegions:{}} as SmartTrafficBreakdown);
  const breakdownRows = summaryKeys.map(([allKey,botKey,label])=>{
    const all=aggregate[allKey],bots=aggregate[botKey];
    const values=Object.entries(all).map(([name,total])=>({
      name, count:botFilter==="hide"?Math.max(0,total-(bots[name]||0))
        :botFilter==="only"?(bots[name]||0):total,
    })).filter(x=>x.count>0).sort((a,b)=>b.count-a.count).slice(0,8);
    return {label,values};
  });
  const browserEvents=(activity.data?.automaticActivity.anonymousBrowserEvents||[])
    .filter(e=>e.host===selected).map(e=>({...e,origin:"browser" as const,
      classification:e.classification||((e.type==="scroll"||e.type==="action"||
        (e.type==="engagement"&&e.visibleSeconds>0))?"interactive" as const:"unknown" as const)}));
  const httpEvents=sites.flatMap(s=>s.smartRequestEvents||[]);
  const allEvents=[...browserEvents,...httpEvents].sort((a,b)=>Date.parse(b.time)-Date.parse(a.time));
  const events=allEvents.filter(e=>botFilter==="all" ||
    (botFilter==="hide"&&e.classification!=="bot") ||
    (botFilter==="only"&&e.classification==="bot")).slice(0,150);
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
      {selected==="stoneapp.hyrovi.com"&&<div className="card mb-3">
        <div className="card-header"><h3 className="card-title">Eigenen Browser registrieren · Stoneapp</h3></div>
        <div className="card-body">
          <p className="text-secondary mb-2">
            Damit du deine eigenen späteren Seitenaufrufe und allgemeinen Aktionen in HPM
            wiederfindest, kannst du <strong>dieses Browserprofil</strong> einmal hier aktivieren.
            Es erscheint kein Banner auf Stoneapp. Die Registrierung gilt bis zu 90 Tage für Stoneapp;
            Login-Daten, Formulare und Passwörter werden nicht mitprotokolliert.
          </p>
          <div className="d-flex flex-wrap align-items-center gap-2">
            <span className={"badge "+(myDeviceRegistered?"bg-green-lt":"bg-secondary-lt")}>
              {myDeviceRegistered?"Dieser Browser registriert":"Nicht registriert"}
            </span>
            {!myDeviceRegistered?<button type="button" className="btn btn-primary" onClick={enroll}>
              Diesen Browser registrieren
            </button>:<button type="button" className="btn btn-outline-secondary" onClick={unenroll}>
              Registrierung deaktivieren
            </button>}
            <a href="https://stoneapp.hyrovi.com" target="_blank" rel="noopener noreferrer"
              className="btn btn-outline-primary">Stoneapp öffnen</a>
          </div>
          {deviceMessage&&<p className="small mt-2 mb-0" role="status">{deviceMessage}</p>}
          <p className="small text-secondary mt-2 mb-0">
            Nur derselbe Browser auf diesem Gerät wird registriert. Andere Besucher werden
            weiterhin nur anonymisiert ausgewertet. Die Registrierung erfasst keine
            verifizierte persönliche Identität oder den Stoneapp-Accountnamen.
          </p>
        </div>
      </div>}
      <div className="row g-2 mb-3">
        {[
          ["Proxy-Anfragen",totals.requests],["Browser-Seitenereignisse",totals.views],
          ["Browser-Aktionen",totals.actions],["Scroll-Ereignisse",totals.scroll],
          ["HTTP-Fehler",totals.errors],["Erkannte Bot-Anfragen",aggregate.botRequests],
          ["Ohne eindeutiges Bot-Signal",aggregate.unknownRequests],
          ["Freigegebene Browserprofile",consented.length]
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
      <div className="card mb-3">
        <div className="card-header d-flex flex-wrap justify-content-between align-items-center gap-2">
          <h3 className="card-title">Zusammenfassung · {selected}</h3>
          <label className="d-flex align-items-center gap-2 small">
            <IconFilter size={17}/> Bot-Filter
            <select className="form-select form-select-sm" value={botFilter}
              aria-label="Bot-Filter für Zusammenfassung und Ereignisse"
              onChange={e=>setBotFilter(e.target.value as "hide"|"all"|"only")}>
              <option value="hide">Bots ausblenden</option>
              <option value="all">Alle anzeigen</option>
              <option value="only">Nur Bots</option>
            </select>
          </label>
        </div>
        <div className="card-body">
          <div className="row g-3">
            {breakdownRows.map(({label,values})=><div className="col-md-6" key={label}>
              <h4>{label}</h4>
              {values.length? <div className="d-flex flex-column gap-1">
                {values.map(v=><div className="d-flex justify-content-between border-bottom gap-2 py-1"
                  key={v.name}><span className="text-break">{v.name}</span>
                  <strong>{v.count} Anfragen</strong></div>)}
              </div>:<p className="text-secondary small">Keine erkennbaren Angaben.</p>}
            </div>)}
          </div>
          <div className="border-top pt-3 mt-3 small text-secondary">
            <strong>Woher kommen die Anfragen?</strong> Über {sites.map(s=>s.source).join(" und ")||"unbekannten Proxy-Knoten"}.
            Ein echter geografischer Standort oder ein Herkunftsland ist in diesen Logs
            nicht verlässlich erfasst. Sprachregionen beschreiben Browser-Einstellungen,
            nicht den Aufenthaltsort. Die Geräte-/Browser-Verteilung zählt HTTP-Anfragen,
            keine einzigartigen Geräte.
          </div>
          <div className="small text-secondary mt-2">
            Die Bot-Erkennung verwendet eindeutige Automationshinweise im HTTP-User-Agent.
            Anfragen ohne solche Hinweise gelten <strong>nicht</strong> als bewiesene Menschen;
            Bots können Browser imitieren und interaktive Events simulieren.
            Ausblenden filtert nur die Ansicht, nicht die gespeicherten Logs.
          </div>
        </div>
      </div>
      <div className="row g-3">
        <div className="col-lg-6"><div className="card">
          <div className="card-header"><h3 className="card-title">Ereignisse · {botFilter==="hide"?"ohne erkannte Bots":botFilter==="only"?"nur Bots":"alle"} ({events.length})</h3></div>
          <div className="table-responsive" style={{maxHeight:540,overflowY:"auto"}}>
            <table className="table table-vcenter card-table">
              <thead><tr><th>Zeit</th><th>Aktion / Bereich / Bewertung</th></tr></thead>
              <tbody>{events.map((e,index)=><tr key={e.origin+":"+e.time+":"+index}>
                <td className="small text-secondary" style={{whiteSpace:"nowrap"}}>{format(e.time)}</td>
                <td>
                  {e.origin==="proxy"?<><strong>{e.method} · HTTP {e.status}</strong>
                    <div className="small text-secondary">{e.browser} · {e.device} · {e.source}</div></>:
                    <strong>{kind[e.type]||e.type}{e.type==="scroll"?" · "+e.scrollDepth+"%":""}</strong>}
                  <div className="small text-secondary">{e.section}</div>
                  <span className={"badge "+(e.classification==="bot"?"bg-orange-lt":e.classification==="interactive"?"bg-blue-lt":"bg-secondary-lt")}>
                    {botLabel[e.classification]||"Unbekannt"}
                  </span>
                </td>
              </tr>)}
              {!events.length&&<tr><td colSpan={2} className="text-secondary">
                Keine Ereignisse für diesen Filter im verfügbaren Ausschnitt.
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
