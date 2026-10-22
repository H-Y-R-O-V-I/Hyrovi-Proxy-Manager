# HPM-globales Cookie- und Tracking-Banner (22.10.2026)

## Nutzeranforderung
Nicht nur Stoneapp: Ein **gemeinsamer, formaler und neutraler Cookie- und
Tracking-Hinweis für hyrovi.com und dessen Subdomains, gesteuert durch HPM**.
Die Entscheidung soll ein einziges Mal getroffen, domainübergreifend
gespeichert und der Banner danach entfernt werden. Kein Umbau einzelner Apps.

## Umsetzung
In `backend/internal/visitor_consent_script.js` wird ein responsiver,
weiß-grauer, zurückhaltender Hinweis auf unterstützten HTML-Seiten
eingeblendet, sobald der Browser noch keine gültige Auswahl hat.

- Gleichwertige sichtbare Schaltflächen **Ablehnen** und **Akzeptieren**
  (keine vorangekreuzten Optionen).
- Der Banner verschwindet sofort nach einer Entscheidung.
- Ein gemeinsames Cookie `hyrovi_analytics_consent` mit `0` oder `1`
  wird nur auf dem Weg der Auswahl geschrieben, `Secure; SameSite=Lax;
  Domain=.hyrovi.com; Path=/; Max-Age=7776000` (90 Tage).
- Vor dem Akzeptieren werden kein Besucher-Identifier und keine
  Analytics-Sitzung erzeugt und keine Browser-Ereignisse gesendet.
- Nach Akzeptanz wird das zufällige Pseudonym
  `hyrovi_visitor_id` (ebenfalls Secure/SameSite/Lax, max 90 Tage)
  erzeugt und die bestehende Analytics über denselben Host aktiviert.
  HPM zeichnet dann gekürzte Pfade (sensible Login-Pfade maskiert),
  allgemeine Klickkategorien, Seitenwechsel, Scroll- und
  Aktivitätsereignisse und grobe Browser-/Plattforminformationen auf,
  aber keine Formulareingaben, Passwörter oder Klickinhalte.
- Bei Ablehnung wird der Besucher-Identifier gelöscht bzw. nicht erzeugt.
  Die Ablehnung wird gleichermaßen gespeichert, auch über spätere
  Besuche auf anderen verwalteten Subdomains hinweg.
- Das kleine, nicht aufdringliche **Cookie-Einstellungen**-Element
  bleibt nach der Entscheidung sichtbar, erlaubt das erneute
  Öffnen des Banners und das Ändern der Wahl.
- DNT und GPC blockieren die individuelle Übertragung; Akzeptieren
  wird bei aktiven Browser-Datenschutzeinstellungen deaktiviert.
- Der bisherige Sonderfall 'Stoneapp: JS komplett inaktiv' entfällt
  absichtlich nach der neuen Anforderung. Das Stoneapp-Projekt und
  seine Datenbank wurden **nicht** verändert.
- In `backend/internal/security_analytics_tracker.js` wird bei
  neuen Analytics-Ereignissen KEIN zusätzlicher Header-Fingerprint
  oder täglicher IP-Hash als Identifikator mehr erzeugt.
  Bereits vorhandene Security-Proxy-Zugriffslogs bleiben separat.

## Abdeckung und echte Grenzen
Der HPM-Proxyscript-Injektor ist auf den konfigurierten HTML-Hosts
vorhanden: zum Implementierungszeitpunkt **15 VPS-Proxy-Host-Dateien
und 31 Pi-Proxy-Host-Dateien**, mit möglichen Überschneidungen.
Gleicher JS-SHA256 vom VPS Stoneapp/AI und Pi Search/QR bestätigt.
Bei nicht-HTML/API-Antworten wird kein Banner eingeblendet.

Die Domains `hyrovi.com` (Apex), `one.hyrovi.com`,
`hpm.hyrovi.com` und `tests.hyrovi.com` werden aktuell NICHT
über diese HPM-HTML-Injektion bedient. Das gemeinsame Cookie gilt
zwar auch dort als Browser-Cookie, doch dort wird ohne gesondertes
Proxy-Routing kein HPM-Banner eingeblendet. Für wirklich restlose
Abdeckung müssen diese separaten Zugangswege sicher über HPM geführt
oder ein HPM-gesteuerter Einbindungsweg geschaffen werden.
**Nicht** behaupten, dort sei der Banner bereits sichtbar.

`https://hyrovi.com/datenschutz` liefert aktuell HTTP 404.
Ein formaler Banner ersetzt keine zugängliche Datenschutzerklärung;
diese sollte vor einer rechtlichen Compliance-Zusage ergänzt werden.

## Live-Deployment
VPS HPM:
- Compose `/opt/hyrovi-hpm-vps/runtime/docker-compose.yml`
- Neu gemountet aus `/opt/hyrovi-hpm-vps/runtime/browser-cookie-v3/`:
  - `visitor_consent_script_global_20261022.js`
  - `security_analytics_tracker_global_20261022.js`
- Rollback-Backup:
  `/opt/hyrovi-hpm-vps/runtime/docker-compose.before-global-consent-20261022.yml`

Pi HPM:
- Compose `/opt/hyrovi-hpm/runtime/docker-compose.yml`
- Neu gemountet:
  - `/opt/hyrovi-hpm/runtime/backend-global-consent-20261022/visitor_consent_script.js`
  - `/opt/hyrovi-hpm/runtime/backend-global-consent-20261022/security_analytics_tracker.js`
- Rollback-Backup:
  `/opt/hyrovi-hpm/runtime/backups-users-20261020/docker-compose.before-global-consent-20261022.yml`

Rollback jeweils: Compose-Backup wiederherstellen, dann im
jeweiligen Runtime-Verzeichnis
`docker compose config -q` und
`docker compose up -d --no-deps --force-recreate hpm`.
Andere Dienste, Apps, Host-Routen und Datenbanken unverändert.

## Prüfung
- Browser-VM-Tests 15/15 PASS, insbesondere gleichwertige
  accept/decline controls, client privacy opt-outs, 90d shared
  domain cookie, kein Tracker vor Opt-in, kein erneutes Banner nach
  Wahl, Domänenwechsel und erneutes Öffnen über Einstellungen.
- Zusätzlich Python-Test für HPM Smart PASS.
- Beide HPM-Container neu gestartet, lokale HPM APIs HTTP 200.
- VPS Stoneapp/AI und Pi Search/QR liefern dieselben JS-Bytes,
  SHA256 `d88bb5ad33a8056a441e9761f7f4231ef529352fd9b85b2e11a7fa9614166c75`.
- HTML-Skript-Integration bei Stoneapp, AI und Pi Search nachgewiesen.
- HPM Admin HTTP 200, HPM Smart Hosts API unauthenticated HTTP 403.
- Beide HPM Node-Backends:
  `security_analytics_tracker.prepare()` → `ready:true`,
  `sharedIdentityReady:true`.
- Stoneapp/AI HTTPS verfügbar, Search gibt erwartbar HTTP 401
  ohne Login zurück.
- Kein echter angemeldeter iPad Safari UI-Tap-/Screenshot-Test;
  nur JS-Simulation und live HTTPS-/HPM-Backend-Verifikation.
- Cache-Control bisher max-age=300 auf Tracking-JS; Clients können
  bei vorhandener HTTP-Cache-Version vorübergehend das alte Skript
  haben. Neubeladen nach Cacheablauf hilft.
