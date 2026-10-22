import {IconCopy, IconDeviceMobile, IconEye, IconInfoCircle} from "@tabler/icons-react";
import type {SecurityVisitor, SecurityVisitorEvent} from "src/api/backend/securityVisitors";

type Props = {visitor:SecurityVisitor; timeline:SecurityVisitorEvent[]; host:string; loading:boolean; error:boolean};
const pretty=(time:string|null|undefined)=>time&&Number.isFinite(Date.parse(time))?
  new Date(time).toLocaleString("de-DE",{dateStyle:"medium",timeStyle:"medium"}):"Nicht erfasst";
const display=(value:string|number|null|undefined)=>value===null||value===undefined||
  value===""?"Nicht erfasst":String(value);
const explainType:Record<string,string>={
  page_view:"Seitenaufruf",route_change:"Seitenwechsel",scroll:"Scrolltiefe",
  action:"Bedienaktion",engagement:"Sichtbare Aktivität",
};
const explainAction:Record<string,string>={
  button_click:"Schaltfläche betätigt (welche, wird nicht erfasst)",
  link_click:"Link betätigt (Linkziel wird nicht erfasst)",
};
const unavailable=[
  ["Hersteller / genaues Modell","Nicht übermittelt"],
  ["iPhone-, iPad- oder Mac-Modellnummer","Nicht übermittelt"],
  ["Betriebssystemversion","Nicht übermittelt"],
  ["Browserversion","Nicht übermittelt"],
  ["Physische Bildschirmauflösung","Nicht übermittelt – nur Größenklasse"],
  ["Standort / Stadt / Land","Nicht erfasst – Zeitzone ist kein Standort"],
  ["Hardware / Speicher / CPU","Nicht erfasst"],
  ["IP-Adresse im Client-Profil","Nicht gespeichert"],
  ["Inhalt eines Klicks / Formularfeldes","Bewusst nicht erfasst"],
] as const;

export default function SmartClientDetails({visitor,timeline,host,loading,error}:Props){
  const sessions=visitor.sessionDetails;
  const count=visitor.sites.find(s=>s.host===host)?.count||0;
  const latest=timeline.filter(e=>e.host===host);
  const detected=[
    ["Browserfamilie",visitor.browsers.join(", "),"Vom Browserprofil übermittelt; keine Versionsnummer"],
    ["Betriebssystemfamilie",visitor.platforms.join(", "),"Vom Browserprofil übermittelt; keine Systemversion"],
    ["Browsersprache",visitor.languages.join(", "),"Übermittelt, nicht Aufenthaltsort"],
    ["Browser-Zeitzone",visitor.timezones.join(", "),"Browserangabe, nicht GPS-Standort"],
    ["Ansichtsfläche (gerundet)",visitor.viewports.join(", "),"Auf 200 Pixel gerundete Browserfensterklasse; keine physische Auflösung"],
    ["Erste Erfassung",pretty(visitor.firstSeen),"Zeitpunkt des ersten gespeicherten Ereignisses im Log-Ausschnitt"],
    ["Letzte Erfassung",pretty(visitor.lastSeen),"Zeitpunkt des zuletzt gespeicherten Ereignisses"],
    ["Letzter besuchter Host",visitor.lastHost||"","Aus einem gespeicherten Seitenereignis"],
    ["Letzte Seite",visitor.lastPage?visitor.lastPage.host+visitor.lastPage.path:"","Erfasster Seitenpfad; sensible Wege werden maskiert"],
    ["Zeitpunkt der letzten Seite",pretty(visitor.lastPage?.at),"Browser-Seitenaufruf oder Seitenwechsel"],
    ["Aktivitätsstatus",visitor.active?"Kürzlich sichtbare Aktivität":"Derzeit keine aktuelle sichtbare Aktivität","Aus letzten Aktivitätsereignissen abgeleitet, kein Menschennachweis"],
    ["Interaktionssignal",visitor.interactive?"Klick oder Scroll erfasst":"Kein Klick/Scroll im Ausschnitt","Kann auch von automatisierten Browsern ausgelöst werden"],
    ["Letzte sichtbare Aktivität",pretty(visitor.lastVisibleAt),"Browser-Aktivitätsmeldung, kein Nachweis einer anwesenden Person"],
    ["Letzte Bedienaktion",pretty(visitor.lastInteractiveAt),"Beobachtete Klick-/Scroll-Kategorie"],
    ["Aktivitätsdauer (gesamt)",visitor.engagementSeconds+" Sekunden","Summe gemeldeter sichtbarer Intervalle, nicht vollständige Besuchsdauer"],
  ] as const;
  return <div>
    <div className="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-2">
      <h3 className="mb-0"><IconDeviceMobile className="me-2"/>Client-Details</h3>
      <span className="badge bg-green-lt">Zustimmung · Browserprofil</span>
    </div>
    <p className="text-secondary small mb-3">
      Genau die Informationen, die HPM im gespeicherten Einwilligungs-Datensatz hat.
      Eine Browserkennung ist <strong>keine bestätigte Person</strong> und die Anzeige ist auf den verfügbaren Log-Ausschnitt begrenzt.
    </p>
    <div className="card mb-3">
      <div className="card-header"><h4 className="card-title">Zuordnung & Aktivitäten</h4></div>
      <div className="card-body">
        <dl className="row mb-0">
          <dt className="col-5 col-md-4">Profilname</dt>
          <dd className="col-7 col-md-8">{display(visitor.name||"Unbenanntes Browserprofil")}</dd>
          <dt className="col-5 col-md-4">Pseudonyme Profil-ID</dt>
          <dd className="col-7 col-md-8">
            <div className="d-flex gap-2 align-items-start">
              <code className="text-break" style={{fontSize:11}}>{visitor.id}</code>
              <button className="btn btn-outline-secondary btn-sm" type="button"
                aria-label="Pseudonyme Profil-ID kopieren"
                onClick={()=>{void navigator.clipboard?.writeText(visitor.id)}}><IconCopy size={14}/></button>
            </div>
            <span className="small text-secondary">Einwegabgeleitete Browserkennung; keine Klartext-Cookie-ID</span>
          </dd>
          <dt className="col-5 col-md-4">Interne Notizen</dt>
          <dd className="col-7 col-md-8">{display(visitor.notes)}</dd>
          <dt className="col-5 col-md-4">Host-Ereignisse</dt>
          <dd className="col-7 col-md-8">{count}</dd>
          <dt className="col-5 col-md-4">Alle erfassten Hosts</dt>
          <dd className="col-7 col-md-8">{visitor.sites.map(s=>s.host+" ("+s.count+")").join(" · ")||"Keine"}</dd>
          <dt className="col-5 col-md-4">Gesamtereignisse</dt>
          <dd className="col-7 col-md-8">{visitor.count}</dd>
          <dt className="col-5 col-md-4">Seitenaufrufe / Wechsel</dt>
          <dd className="col-7 col-md-8">{visitor.pageViews}</dd>
          <dt className="col-5 col-md-4">Bedienaktionen</dt>
          <dd className="col-7 col-md-8">{visitor.actions}</dd>
          <dt className="col-5 col-md-4">Erkannte Sitzungen</dt>
          <dd className="col-7 col-md-8">{visitor.sessions} insgesamt, davon {sessions.filter(s=>s.host===host).length} auf diesem Host</dd>
        </dl>
      </div>
    </div>
    <div className="card mb-3">
      <div className="card-header"><h4 className="card-title">Alle tatsächlich erfassten technischen Angaben</h4></div>
      <div className="table-responsive">
        <table className="table table-vcenter card-table">
          <thead><tr><th>Merkmal</th><th>Wert</th><th>Einordnung</th></tr></thead>
          <tbody>{detected.map(([label,value,reason])=><tr key={label}>
            <td className="fw-medium">{label}</td>
            <td className="text-break">{display(value)}</td>
            <td className="small text-secondary">{reason}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </div>
    <div className="card mb-3">
      <div className="card-header"><h4 className="card-title">Nicht erkannte oder absichtlich nicht gespeicherte Angaben</h4></div>
      <div className="table-responsive">
        <table className="table table-vcenter card-table">
          <tbody>{unavailable.map(([name,value])=><tr key={name}>
            <td className="fw-medium">{name}</td>
            <td className="text-secondary">{value}</td>
          </tr>)}</tbody>
        </table>
      </div>
      <div className="card-body border-top small text-secondary">
        Ein Browser kann Merkmale verändern oder verschleiern. HPM rät deshalb keine exakte
        Modellnummer, Hardwareausstattung oder geografische Position.
      </div>
    </div>
    <div className="card mb-3">
      <div className="card-header"><h4 className="card-title">Alle erkannten Sitzungen dieses Profils (max. 40)</h4></div>
      <div className="table-responsive">
        <table className="table table-vcenter card-table">
          <thead><tr><th>Beginn / Ende</th><th>Aktivität</th><th>Session</th></tr></thead>
          <tbody>{sessions.map(s=><tr key={s.id}>
            <td><div>{pretty(s.firstSeen)}</div><div className="text-secondary small">{pretty(s.lastSeen)}</div><div className="small text-secondary">{s.host}</div></td>
            <td>{s.pageViews} Seiten · {s.actions} Aktionen · {s.visibleSeconds} s sichtbar</td>
            <td><code className="text-break" title="Abgeleitete Sitzungs-ID, kein Session-Cookie im Klartext" style={{fontSize:10}}>{s.id}</code></td>
          </tr>)}
          {!sessions.length&&<tr><td colSpan={3} className="text-secondary">Keine Sitzung im erfassten Ausschnitt.</td></tr>}</tbody>
        </table>
      </div>
    </div>
    <div className="card">
      <div className="card-header"><h4 className="card-title"><IconEye className="me-2"/>Einzelereignisse auf {host} ({latest.length})</h4></div>
      <p className="small text-secondary px-3 pt-2 mb-0">
        Neueste zuerst. Jede Zeile zeigt die tatsächlich gespeicherten Felder.
        „button_click“ bedeutet nicht, dass HPM den konkreten Button kennt.
      </p>
      <div className="table-responsive" style={{maxHeight:650,overflowY:"auto"}}>
        <table className="table table-vcenter card-table">
          <thead><tr><th>Zeit & Aktion</th><th>Details</th></tr></thead>
          <tbody>{latest.map(e=><tr key={e.id}>
            <td style={{minWidth:175}}>
              <div className="fw-medium">{explainType[e.type]||e.type}</div>
              <div className="small text-secondary">{pretty(e.timestamp)}</div>
            </td>
            <td>
              <div><strong>Pfad:</strong> {display(e.path)}</div>
              {e.action&&<div><strong>Aktion:</strong> {explainAction[e.action]||e.action} <code>{e.action}</code></div>}
              {e.type==="scroll"&&<div><strong>Scrolltiefe:</strong> {e.scrollDepth}%</div>}
              {e.type==="engagement"&&<div><strong>Aktivität:</strong> {e.visibleSeconds} Sekunden</div>}
              {e.referrerHost&&<div><strong>Referrer-Host:</strong> {e.referrerHost}</div>}
              {e.language&&<div><strong>Sprache:</strong> {e.language}</div>}
              {e.viewport&&<div><strong>Ansichtsklasse:</strong> {e.viewport}</div>}
              <div className="small text-secondary text-break">Ereignis-ID: {e.id}</div>
            </td>
          </tr>)}
          {loading&&<tr><td colSpan={2} className="text-secondary">Lade Client-Ereignisse…</td></tr>}
          {error&&<tr><td colSpan={2} className="text-danger">Client-Ereignisse derzeit nicht erreichbar.</td></tr>}
          {!loading&&!error&&!latest.length&&<tr><td colSpan={2} className="text-secondary">Keine erfassten Ereignisse für diesen Host.</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="card-body border-top small text-secondary"><IconInfoCircle size={15} className="me-1"/>
        Maximal 300 der letzten verfügbaren Profil-Ereignisse werden vom Backend geliefert.
        Weder Texteingaben noch Passwörter oder exakte Klickziele sind Teil dieser Daten.
      </div>
    </div>
  </div>;
}
