# HYROVI Smart: Browser-/Geräteübersicht mit Bot-Filter (22.10.2026)

## Umfang
Live im produktiven Pi-HPM unter `HYROVI Sec > HYROVI Smart > Hosts & Analytics`.
Host-Auswahl bleibt unverändert, nur Stoneapp standardmäßig ausgewählt.

Pro ausgewähltem Host:
- HTTP-Anfrage-Klassifizierung nach User-Agent: wahrscheinliche Automation
  vs. keine eindeutigen Bot-Signale. Diese letzte Gruppe sind ausdrücklich
  KEINE bestätigten echten Menschen.
- Requests nach grober Geräteklasse (Smartphone/Tablet/Desktop-Unbekannt),
  Browserfamilie, Betriebssystem und HTTP Accept-Language-Sprachregion.
- Sprachregion ist kein GeoIP-Nachweis und nicht der physische Standort.
  Der aktuell verfügbare Herkunftshinweis ist lediglich Pi/VPS-Proxy-Knoten.
- In der kombinierten Ereignis-Timeline stehen begrenzte, sanitizierte
  HTTP-Anfragesamples (Minute, erste sichere Routenebene, Status, Methode,
  Geräte-/Browserklasse und Bot-Kennzeichnung) und bereits vorhandene,
  anonymisierte Browser-Ereignisse. Echte Benutzer-/Geräte-IDs werden nicht
  aus Requestmerkmalen abgeleitet.
- Bot-Filter `Bots ausblenden` (Standard), `Alle anzeigen`, `Nur Bots`
  filtert sowohl die Verteilung als auch Einzelereignisse, nicht die Logs.
- Browseraktivität `scroll`, `action`, Engagement wird als
  `Interaktionssignal` bezeichnet: Bots können das imitieren. Keine
  verifizierte Menschenerkennung oder automatische Blocks.

## Datenschutzgrenzen
- Verarbeitet ohnehin vorhandene Proxy- und Browser-Logs.
- An Pi werden KEINE IP-Adressen, vollständigen User-Agents,
  Fingerprints, Cookies, Queryparameter, Request IDs oder präzisen
  einzelnen HTTP-Event-Zeitpunkte exportiert.
- HTTP-Ereignisse werden auf Minuten gerundet; Requestpfade werden
  zu einem allgemeinen ersten Segment abstrahiert / sensible Pfade maskiert.
- Maximal 35 einzelne HTTP-Ereignisse je Host und Node innerhalb des
  ohnehin beschränkten Log-Ausschnitts.
- Host-Auswahl steuert ausschließlich diese Smart-Oberfläche; keine neue
  Erfassung auf weiteren Domains. Das vorhandene Einwilligungssystem bleibt.

## Dateien
- VPS `ops/smart_activity_traffic.py`:
  eigener klassifizierender Sanitizer für Anfragen, benutzerunabhängig.
- VPS `ops/vps_browser_activity_sync.py`: summiert beschreibende Zähler
  und exportiert begrenzte HTTP-Ereignisse per SSH an Pi.
- Pi `backend/internal/security_smart_traffic.js`: dieselbe grobe
  Heuristik für lokale Proxy-Logs, ohne identifizierende Rohfelder.
- Pi `backend/internal/security_visitors.js`: aggregierte PI/VPS-
  Breakdown-Zähler, Safe-Event-Übertragung und harmlose Browseraktion-
  Klassifizierung.
- `frontend/src/api/backend/securityVisitors.ts`: Typen.
- `frontend/src/pages/Security/SmartHostsStudio.tsx`: UI, Filter, Counts,
  Request-/Browser-Eventtimeline und Herkunftshinweis.
- `tests/security-smart-traffic.test.mjs`: 4 automatisierte
  Datenschutz-/Bot-/Browser-Klassifikationstests.

## Live Deployment und Rollback
VPS aktiver Systemd-Exporter:
`/usr/local/libexec/hyrovi-vps-hpm-activity-sync.py` mit lokalem Import
`/usr/local/libexec/smart_activity_traffic.py`.
Backup vor Änderung:
`/usr/local/libexec/hyrovi-vps-hpm-activity-sync.before-smart-classification-20261022.py`.
Rollback auf VPS:
```sh
cp -p /usr/local/libexec/hyrovi-vps-hpm-activity-sync.before-smart-classification-20261022.py /usr/local/libexec/hyrovi-vps-hpm-activity-sync.py
systemctl start hyrovi-vps-hpm-activity-sync.service
```

Pi Live Compose: `/opt/hyrovi-hpm/runtime/docker-compose.yml`
- Frontend: `frontend-smart-insights-20261022`
- Backend: `backend-smart-insights-20261022/security_visitors.js`
  und `security_smart_traffic.js`.
- Alle bestehenden User-, Consent- und Security-Mounts bleiben erhalten.
Pi Backup: `backups-users-20261020/docker-compose.before-smart-insights-20261022.yml`.
Rollback:
```sh
cd /opt/hyrovi-hpm/runtime
cp backups-users-20261020/docker-compose.before-smart-insights-20261022.yml docker-compose.yml
docker compose config -q
docker compose up -d --no-deps --force-recreate hpm
```

## Tests / echter Stand
- 15/15 gezielte Node-Testfälle PASS, Python-Klassifikation PASS.
- TypeScript/Vite Build PASS.
- Dry-run VPS Export: 92.354 Bytes für 16 Hosteinträge und
  15 aktuelle anonyme Browser-Ereignisse, keine Rohkennungen.
- Realer VPS Export und Pi Empfang verifiziert.
- Produktiver Pi HPM Container / API / public HPM / Stoneapp / HYROVI One: HTTP 200.
- Neue Security-Bundle-URL HTTP 200; unauthenticated Host Management API 403.
- Produktive Pi API `security_visitors.list()` antwortete in 465 ms und
  zeigte Stoneapp: VPS 88 HTTP-Anfragen, 32 Bot-User-Agent-Signale,
  56 nicht eindeutig klassifiziert; Anfragegeräteklassen: 27 Smartphone,
  18 Desktop/Unbekannt, 43 Unbekannt; Browser: Safari 42,
  Chrome 3, Unbekannt 43; 57 HTTP-Anfragen mit Browsersprachregion de-DE.
  35 sichere HTTP-Ereignissamples; 15 anonymisierte Browserevents.
  Keine individuell freigegebenen Stoneapp-Browserprofile im Ausschnitt.
- Kein authentifizierter Safari-UI-End-to-End-Test möglich;
  Code, Datenexport, Backend und HTTP-Assets dagegen geprüft.

## Wichtig für Folgearbeiten
Ein präzises Land/Stadt braucht eine verlässliche, lokale GeoIP-Datenquelle
und Prüfung des tatsächlich protokollierten Client-IP-Verhaltens; ohne das
nicht aus Accept-Language ableiten. Automations-Browser können Skripte
ausführen und User Agents fälschen; eine echte Person kann nicht aus
diesen Signalen allein sicher festgestellt werden.
