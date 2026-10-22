# HYROVI Smart — vollständige Client-Detailansicht (2026-10-22)

## Nutzerwunsch
"Ich will jetzt bei einem client sehen was genau wirklich erkannt wird", präzisiert als
"die ganzen erkannten infos und gerät und alles ganz exakt alle infos".
Die Anzeige gehört in den bereits existierenden `HYROVI Sec > HYROVI Smart >
Hosts & Analytics` und ist nicht nur eine zusätzliche aggregierte Statistik.

## Implementiert
- `frontend/src/pages/Security/SmartClientDetails.tsx`: neues detailliertes
  Profilpaneel in voller Breite, wird bei Auswahl eines zuvor
  freigegebenen Browserprofils angezeigt.
- `frontend/src/pages/Security/SmartHostsStudio.tsx`: Integration,
  automatische Auswahl, wenn nur **ein** freigegebenes Profil
  auf dem ausgewählten Host vorliegt.
- Zeigt ALLE aus bestehenden HPM-Consent-Telemetriedaten bereits
  vorhandenen Kategorien/Informationen: Hash-basierte pseudonyme
  Browserprofil-ID, Profilname und Anmerkungen, Seitenaufrufe,
  Interaktionen, sämtliche gespeicherten Hosts und Ereigniszähler,
  erstmalige und letzte Erfassung, Browserfamilien,
  Betriebssystemfamilien, Browsersprache, Zeitzonen,
  gerundete Fenstergrößenklassen, letzte Seite und deren Zeitpunkt,
  letztes Sichtbarkeitssignal/Interaktionssignal, insgesamt
  gemeldete sichtbare Sekunden, erkannte Aktivitäts-/Interaktions-
  Statusflags; bis zu 40 hashed Sessions mit Host, Start-/Endzeit,
  Seitenaufrufen/Aktionen/Sichtbarkeitsdauer und voller Hash-ID.
- Bei Einzelereignissen werden bis zu 300 aktuelle Einträge des
  Backend-Profils verwendet und nach gewähltem Host gefiltert:
  Zeit, Host-Pfad, Kategorie, codierte Action
  (button_click/link_click), Scroll-Prozent,
  Engagementsekunden, ggf. referrerHost, language/viewport und
  das von HPM erzeugte Event-Identifier.
- Copy-Button kopiert die **pseudonyme Hash-ID**, NICHT die
  Klartext-Cookie-ID oder Roh-Netzwerkkennung.
- Zusätzlich absichtlich **nicht** erkannt/gespeichert:
  exakte iPhone-/iPad-/Mac-Modelle, konkrete Hardware,
  CPU/RAM, System- oder Browser-Version, physische
  Bildschirmauflösung, exakte GPS-Lage/Land/Stadt,
  IP im einzelnen pseudonymen Client-Profil,
  konkrete angeklickte Elemente und Formulare.
  Diese bleiben ausdrücklich `Nicht übermittelt`/`Nicht erfasst`.
  Keine falsche Präzision aus iOS/iPadOS/Safari, timezone,
  gerundeter viewport size oder User-Agent-Browserfamilie.
- Keine Änderung an Consent-Text/-Verhalten oder beim Server/Collector;
  keine Ausweitung auf hochentropische Fingerprinting-APIs.
  Andere Websites/Stoneapp-Code nicht bearbeitet.

## Live-Verifizierung vor Deployment
Pi-HPM backend `security_visitors.list()` lieferte:
- 1 consented pseudonymes Browserprofil auf
  `stoneapp.hyrovi.com`, 10 Ereignisse.
- Browser Safari, OS-Familie iOS/iPadOS, Sprache de-DE,
  Zeitzone Europe/Berlin, Größenklasse 400x600.
- Eine Sitzung, 3 Seitenaufrufe, 5 Aktionen,
  2 Engagement-Ereignisse mit 20 s sichtbarer Zeit.
- Letzte Seite `/`, Einträge `button_click`, `link_click`.
Das lässt KEINE verifizierte Aussage zu, welcher reale
Mensch oder welches exakte Hardwaremodell dahintersteht.

## Tests und Produktion
- `NODE_ENV=production npm run build`: PASS (TypeScript + Vite).
- Node tests `security-smart-hosts`, `security-smart-traffic`,
  `security-smart`, `shared-cookie-consent`, `privacy-page`:
  18/18 PASS, vorhandener Python test_smart_analytics PASS.
- Neues Frontend auf Pi unter
  `/opt/hyrovi-hpm/runtime/frontend-client-details-20261022`.
- Pi Compose `/opt/hyrovi-hpm/runtime/docker-compose.yml`
  Frontend-Bind-Mount gewechselt auf
  `frontend-client-details-20261022:/app/frontend:ro`;
  nur HPM Service neu erstellt, alle Backend/Consent/Proxy-
  Bind-Mounts unverändert.
- Compose-Rollback:
  `/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-client-details-20261022.yml`.
  Wiederherstellen und
  `docker compose config -q && docker compose up -d --no-deps --force-recreate hpm`.
- HPM, Stoneapp, HYROVI One öffentliche HTTPS alle HTTP 200,
  `https://hpm.hyrovi.com/assets/Security-CadpHzc9.js`
  HTTP 200, Pi HPM lokale API HTTP 200.
- Authenticated iPad Safari visual tap test not directly performed;
  user should refresh HPM to load new JS.
