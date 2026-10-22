# HYROVI Smart · Einzeln verwaltete Hosts (2026-10-22)

## Nutzerwunsch
Unter dem bereits eigenständigen HYROVI-Sec-Tab **HYROVI Smart** einzelne
bestehende HPM-Hosts auswählen, verwalten und ihre Website-Analytics sehen.
Zu Beginn soll **nur stoneapp.hyrovi.com** in der Smart-Hostliste stehen.

## Verhalten
- Erststart ohne gespeicherte Konfig: nur `stoneapp.hyrovi.com`.
- Andere Hosts sind standardmäßig **nicht** in der Smart-Hostansicht.
- Ein HPM-Administrator kann vorhandene konfigurierte Proxy-Hosts per
  Dropdown hinzufügen oder wieder entfernen.
- Änderungen sind persistent in der Pi-HPM-Datenpartition gespeichert:
  `/data/nginx/hyrovi-security/smart-analytics-hosts.json`, Atomic-Rename,
  Modus 0600, max. 25 Hosts; bewusst leere Liste bleibt leer.
- Die Auswahl ändert **nur den HYROVI-Smart-Auswertungsumfang**. Sie
  installiert/deinstalliert keine Tracker und verändert nicht andere HPM
  Proxy-Logs, Sicherheitsregeln, Standard-Analytics-Skripte oder
  Einwilligungseinstellungen. Vorbestehende Scripts auf anderen Proxy Hosts
  werden nicht durch diese Auswahl deaktiviert.
- Getrenntes `tests.hyrovi.com`-Testlabor bleibt vorhanden, wird
  aber nicht als Smart-Host angeboten.
- HPM Sec > HYROVI Smart hat Unteransichten `Hosts & Analytics`
  (Standard), `Testlabor`, `Sicherheitsanalyse`.
- Hostdetails verwenden bestehende HPM-`/security/visitors`-Daten:
  HTTP- und Browserereigniszähler nach Pi/VPS, anonymisierte sichere
  Browser-Ereignisse und für den gewählten Host gefilterte
  Opt-in-Browserprofile sowie host-spezifisch gefilterte Timeline.
  Keine neue Identitätsableitung / Fingerprintverknüpfung.
- Admin API:
  - GET `/api/security/smart/hosts` (Permission `logs:list`)
  - POST `/api/security/smart/hosts` `{host}` (`users:list`)
  - DELETE `/api/security/smart/hosts/:host` (`users:list`)
  - Host-Änderungen nur für bereits als konfiguriert erfasste Proxy
    Hosts; Syntax validiert, geschützte HPM- und Test-Domains ausgeschlossen.

## Code
- `backend/internal/security_smart_hosts.js` – scoped file persistence,
  default, validation and write-queue.
- `backend/routes/security.js` – drei autorisierte API-Routen nach JWT.
- `frontend/src/api/backend/securityVisitors.ts` – typsichere APIs.
- `frontend/src/pages/Security/SmartHostsStudio.tsx` – Hostmanager,
  Dashboard, Ereignisse und freigegebene Besucherprofile.
- `frontend/src/pages/Security/SmartHub.tsx` – neue Defaultansicht.
- `tests/security-smart-hosts.test.mjs` – Regression.

## Produktion
Verfügbar über https://hpm.hyrovi.com/security.
Pi-HPM Compose `/opt/hyrovi-hpm/runtime/docker-compose.yml` bindet:
- Frontend `frontend-smart-hosts-20261022` → `/app/frontend`;
- Backend `backend-smart-hosts-20261022/security.js` → `/app/routes/security.js`;
- Backend `backend-smart-hosts-20261022/security_smart_hosts.js`
  → `/app/internal/security_smart_hosts.js`.
Bestehende Backend-Mounts, Consent Script, Proxy-Regeln und Zertifikate
unverändert. Compose-Rollback-Backup:
`/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-smart-hosts-20261022.yml`.
Rollback:
```sh
cd /opt/hyrovi-hpm/runtime
cp backups-users-20261020/docker-compose.before-smart-hosts-20261022.yml docker-compose.yml
docker compose config -q
docker compose up -d --no-deps --force-recreate hpm
```
Der Rollback ändert die separate Smart-Host-Konfigurationsdatei nicht.

## Verifiziert
- TypeScript/Vite Build erfolgreich.
- Node: 11/11 Tests erfolgreich (5 Host Tests, 5 Smart Security,
  1 Consent/Privacy Test).
- Node Syntax-Checks für Backendmodule und Route erfolgreich.
- Live Pi Docker HPM API HTTP200, öffentliche HPM/Stoneapp/One HTTP200.
- Live in Container `security_smart_hosts.list()`:
  `["stoneapp.hyrovi.com"]` und Stoneapp im HPM-Hostinventar gefunden.
- Live VPS Stoneapp verfügbar, ca. 87 jüngste Proxy-Requests,
  4 Browser-Seitenereignisse und 15 anonymisierte Browser-Ereignisse;
  0 individuell freigegebene Besucherprofile in diesem Ausschnitt.
- Unauthentifizierte GET und POST Smart-Hosts API: 403.
- Mutationen mit echten Admin-Credentials wurden nicht direkt über
  Safari geprüft; persistente Mutation ist mit isolierter Testdatei
  unter Unit-Tests nachgewiesen.
- Echtgerät-iPad-Safari-UI nicht visuell getestet.

## Weiterer Ausbau
Ein vom Administrator ausgewählter Host erhält dadurch keinen
neuen Collector – es werden die bereits bestehenden Security-/Analytics-
Informationen genutzt. Für wirklich detaillierte browserbasierte
Gerätedaten auf Stoneapp ist ein separater, offengelegter Opt-in-Flow
notwendig; ohne ihn nicht vorgeben, einzigartige Geräte zu erkennen.
