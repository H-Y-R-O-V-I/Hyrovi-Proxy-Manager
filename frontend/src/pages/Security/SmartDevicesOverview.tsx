import {useQuery} from "@tanstack/react-query";
import {useMemo, useState} from "react";
import {IconDeviceDesktop, IconSearch, IconShieldCheck, IconWorld} from "@tabler/icons-react";
import {getSecurityVisitor, getOneAuthDevices, type AutomaticSiteActivity, type SecurityVisitor} from "src/api/backend/securityVisitors";
import SmartClientDetails from "./SmartClientDetails";

type Props = {activity?: AutomaticSiteActivity; visitors: SecurityVisitor[]; loading: boolean};
type DeviceRow = {
  id:string; kind:"one"|"consented"|"observation"; at:number;
  name:string; detail:string; domain:string; route:string; usage:string;
  visitorId?:string;
};
const stamp=(sec:number)=>sec>0?new Date(sec*1000).toLocaleString("de-DE"):"Nicht bekannt";
const eventStamp=(ms:number)=>Number.isFinite(ms)&&ms>0?new Date(ms).toLocaleString("de-DE"):"—";
const makeTime=(value:string|null|undefined)=>value?Date.parse(value)||0:0;

export default function SmartDevicesOverview({activity,visitors,loading}:Props) {
  const [search,setSearch]=useState("");
  const [filter,setFilter]=useState<"all"|"one"|"consented"|"observation">("all");
  const [host,setHost]=useState("");
  const [open,setOpen]=useState<string|null>(null);
  const [openOne,setOpenOne]=useState<string|null>(null);
  const authQuery=useQuery({queryKey:["smart-one-auth-devices"],queryFn:getOneAuthDevices,
    staleTime:15000,refetchInterval:30000,retry:false});
  const auth=authQuery.data;
  const sites=activity?.websites||[];
  const rows=useMemo(()=>{
    const out:DeviceRow[]=[];
    for(const d of auth?.devices||[]){
      const valid=d.validSessions>0;
      out.push({
        id:"one:"+d.id,kind:"one",at:d.lastUsed*1000,
        name:d.label||"HYROVI-One-Browser",
        detail:d.account+" · "+(valid?"Gültige One-Sitzung":"Keine gültige One-Sitzung"),
        domain:"one.hyrovi.com",route:"Anmeldung",
        usage:valid?d.validSessions+" gültige Session(s)":"Früher registrierter Login",
      });
    }
    for(const v of visitors){
      out.push({
        id:"consent:"+v.id,kind:"consented",at:makeTime(v.lastSeen),
        name:v.name||v.platforms.join(", ")||"Freigegebenes Browserprofil",
        detail:(v.browsers.join(", ")||"Browser unbekannt")+" · "+(v.platforms.join(", ")||"Plattform unbekannt"),
        domain:v.sites.map(s=>s.host).join(", "),
        route:v.lastPage?.path||"—",
        usage:v.pageViews+" Seiten · "+v.actions+" Aktionen · "+v.engagementSeconds+" s sichtbar",
        visitorId:v.id,
      });
    }
    // A proxy request is evidence of an HTTP client, NOT a unique physical device.
    // Never merge anonymous rows by IP, user agent or fingerprint across domains.
    for(const s of sites){
      for(const [i,e] of (s.smartRequestEvents||[]).entries()){
        out.push({
          id:"http:"+s.source+":"+s.host+":"+i,kind:"observation",at:makeTime(e.time),
          name:e.device||"Unbekannte Geräteklasse",
          detail:(e.browser||"Browser unbekannt")+" · "+(e.platform||"OS unbekannt")+" · "+e.source,
          domain:s.host,route:e.section||"/",
          usage:e.method+" · HTTP "+e.status+(e.classification==="bot"?" · Bot-Signal":""),
        });
      }
    }
    for(const [i,e] of (activity?.anonymousBrowserEvents||[]).entries()){
      out.push({
        id:"event:"+e.host+":"+i,kind:"observation",at:makeTime(e.time),
        name:"Anonymer Browserzugriff",detail:"Ohne sichere Geräte-ID · "+e.source,
        domain:e.host,route:e.section,usage:e.type+" · Browserereignis",
      });
    }
    return out.sort((a,b)=>b.at-a.at);
  },[auth,visitors,sites,activity?.anonymousBrowserEvents]);
  const domains=useMemo(()=>[...new Set(sites.map(s=>s.host))].sort(),[sites]);
  const filtered=rows.filter(r=>{
    if(filter!=="all"&&r.kind!==filter)return false;
    if(host&&!r.domain.split(", ").includes(host))return false;
    return [r.name,r.detail,r.domain,r.route,r.usage].join(" ").toLowerCase().includes(search.toLowerCase());
  });
  const valid=(auth?.devices||[]).filter(d=>d.validSessions>0).length;
  const chosen=visitors.find(v=>v.id===open);
  const detail=useQuery({queryKey:["smart-overview-device",open],queryFn:()=>getSecurityVisitor(open||""),
    enabled:Boolean(open),staleTime:15000,retry:false});
  const one=(auth?.devices||[]).find(d=>"one:"+d.id===openOne);
  return <section aria-label="Gesamte Geräte- und Besucherübersicht" className="mb-4">
    <div className="d-flex flex-wrap justify-content-between align-items-end gap-2 mb-3">
      <div>
        <div className="text-secondary small">HYROVI SMART / GESAMTÜBERSICHT</div>
        <h3 className="mb-1"><IconDeviceDesktop className="me-2"/>Geräte & letzte Aktivität</h3>
        <p className="text-secondary mb-0">Alle beobachteten Zugriffe, freigegebene Browserprofile und echte One-Anmeldungen – klar getrennt.</p>
      </div>
      <span className="badge bg-blue-lt">Live-Daten aus HPM & One</span>
    </div>
    <div className="row g-2 mb-3">
      {[
        ["Verifizierte One-Geräte",auth?.available?String(auth.devices.length):"—","mit registriertem Login"],
        ["Gültige One-Sitzungen",auth?.available?String(valid):"—","keine Aussage über geöffnete Tabs"],
        ["Freigegebene Profile",String(visitors.length),"domainübergreifend nur mit Zustimmung"],
        ["Anonyme Beobachtungen",String(rows.filter(r=>r.kind==="observation").length),"nicht einzigartige Geräte"],
        ["Erfasste Domains",String(domains.length),"im verfügbaren Logfenster"],
      ].map(([name,count,subtitle])=><div key={name} className="col-6 col-lg">
        <div className="card h-100"><div className="card-body p-3">
          <div className="small text-secondary">{name}</div><h2 className="mb-1">{loading?"—":count}</h2>
          <div className="small text-secondary">{subtitle}</div>
        </div></div>
      </div>)}
    </div>
    <div className="card">
      <div className="card-header d-flex flex-wrap align-items-center justify-content-between gap-2">
        <h4 className="card-title mb-0">Zuletzt beobachtet <span className="text-secondary">({filtered.length})</span></h4>
        <div className="d-flex flex-wrap gap-2 align-items-center">
          <label className="d-flex align-items-center gap-2">
            <IconSearch size={16}/><input className="form-control form-control-sm"
              aria-label="Geräte oder Seiten suchen" placeholder="Gerät, Browser, Seite …"
              value={search} onChange={e=>setSearch(e.target.value)}/>
          </label>
          <select className="form-select form-select-sm" style={{width:"auto"}} value={filter}
            aria-label="Gerätetyp filtern" onChange={e=>setFilter(e.target.value as typeof filter)}>
            <option value="all">Alle Einträge</option>
            <option value="one">HYROVI-One-Logins</option>
            <option value="consented">Freigegebene Profile</option>
            <option value="observation">Nicht angemeldete / unbekannte Zugriffe</option>
          </select>
          <select className="form-select form-select-sm" style={{width:"auto",maxWidth:230}} value={host}
            aria-label="Domain filtern" onChange={e=>setHost(e.target.value)}>
            <option value="">Alle Domains</option>
            {domains.map(d=><option key={d} value={d}>{d}</option>)}
          </select>
        </div>
      </div>
      <div className="table-responsive" style={{maxHeight:620,overflowY:"auto"}}>
        <table className="table table-vcenter card-table mb-0">
          <thead className="sticky-top"><tr><th>Erkennung / Gerät</th><th>Zuletzt aktiv</th><th>Domain & Seite</th><th>Aktivität</th><th/></tr></thead>
          <tbody>
            {filtered.slice(0,300).map(r=><tr key={r.id}>
              <td style={{minWidth:205}}>
                <div className="d-flex align-items-center gap-2 mb-1">
                  <span className={"badge "+(r.kind==="one"?"bg-green-lt":r.kind==="consented"?"bg-blue-lt":"bg-secondary-lt")}>
                    {r.kind==="one"?"One-Login":r.kind==="consented"?"Zustimmung":"Nicht zugeordnet"}
                  </span>
                </div>
                <div className="fw-semibold">{r.name}</div><div className="small text-secondary">{r.detail}</div>
              </td>
              <td className="small" style={{whiteSpace:"nowrap"}}>{eventStamp(r.at)}</td>
              <td><div className="text-break">{r.domain}</div><div className="small text-secondary text-break">{r.route}</div></td>
              <td className="small">{r.usage}</td>
              <td>
                {r.kind==="consented"&&<button className="btn btn-outline-primary btn-sm"
                  type="button" onClick={()=>{setOpen(r.visitorId||null);setOpenOne(null);}}>Details</button>}
                {r.kind==="one"&&<button className="btn btn-outline-primary btn-sm"
                  type="button" onClick={()=>{setOpenOne(r.id);setOpen(null);}}>Details</button>}
              </td>
            </tr>)}
            {!filtered.length&&<tr><td colSpan={5} className="text-secondary p-3">
              {loading?"Daten werden geladen…":"Keine Einträge in diesem Filter oder Logfenster."}
            </td></tr>}
          </tbody>
        </table>
      </div>
      {filtered.length>300&&<div className="card-body small text-secondary">Anzeige auf die 300 neuesten Einträge begrenzt. Filtere nach Domain oder Typ.</div>}
    </div>
    {one&&<div className="card mt-3">
      <div className="card-header d-flex justify-content-between align-items-center">
        <h4 className="card-title"><IconShieldCheck size={17} className="me-1"/>Verifizierte One-Anmeldung</h4>
        <button type="button" className="btn btn-outline-secondary btn-sm" onClick={()=>setOpenOne(null)}>Schließen</button>
      </div>
      <div className="card-body">
        <div className="row g-3">
          {[["Gerätebezeichnung",one.label],["One-Konto",one.account],["Erste Anmeldung",stamp(one.firstLogin)],
            ["Zuletzt für Anmeldung verwendet",stamp(one.lastUsed)],["Gültige Sitzungen",String(one.validSessions)],
            ["Vertrauensstatus bis",stamp(one.trustedUntil)]].map(([key,value])=>
            <div key={key} className="col-md-4"><div className="text-secondary small">{key}</div><strong>{value}</strong></div>)}
        </div>
        <p className="small text-secondary mt-3 mb-0">
          HYROVI One bestätigt den gespeicherten Loginstatus. Eine gültige Sitzung bedeutet nicht, dass das Gerät
          gerade online ist. Die Browserbezeichnung ist kein verifiziertes Hardwaremodell; keine Verknüpfung mit anonymen Proxy-Ereignissen.
        </p>
      </div>
    </div>}
    {open&&<div className="card mt-3"><div className="card-body">
      <div className="d-flex justify-content-end mb-2">
        <button type="button" className="btn btn-outline-secondary btn-sm" onClick={()=>setOpen(null)}>Details schließen</button>
      </div>
      {detail.isLoading&&<div className="text-secondary">Lade Gerätedetails…</div>}
      {detail.isError&&<div className="text-danger">Gerätedetails derzeit nicht erreichbar.</div>}
      {detail.data?.visitor&&<SmartClientDetails visitor={detail.data.visitor}
        host={chosen?.lastHost||chosen?.sites[0]?.host||""}
        timeline={detail.data.timeline||[]} loading={detail.isLoading} error={detail.isError}/>}
    </div></div>}
    {!auth?.available&&<p className="small text-warning mt-2">Die One-Gerätequelle ist derzeit nicht verfügbar. HPM-Zugriffe werden unabhängig davon angezeigt.</p>}
    <p className="small text-secondary mt-2">
      <IconWorld size={15} className="me-1"/>Anonyme Einträge sind einzelne beobachtete HTTP- oder Browserereignisse,
      keine nachweislich einzigartigen Geräte. IP- und Header-Fingerprints werden hier nicht zum heimlichen
      domainübergreifenden Wiedererkennen zusammengeführt. Uhrzeiten und Seitenbereiche stammen aus dem begrenzten Logfenster.
    </p>
  </section>;
}
