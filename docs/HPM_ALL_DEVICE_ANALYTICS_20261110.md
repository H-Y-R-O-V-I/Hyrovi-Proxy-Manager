# HYROVI HPM · Geräte & letzte Aktivität (10.11.2026)

## Erkennungsstufen

- **One-Anmeldungen:** Reale registrierte One-Browsergeräte mit Konto, Browserlabel, erster/letzter Verwendung, Ablauf und Anzahl aktuell gültiger Sessions aus der bestehenden One-SQLite-DB. Eine gültige Session belegt nicht, dass ein Gerät gerade online ist.
- **Freigegebene Browserprofile:** Einwilligungsabhängige pseudonyme HPM-Browserkennung, Domains, Seitenaufrufe, Aktionen, Aktivitätszeit und vorhandene Sessions.
- **Anonyme Beobachtungen:** Jeder im begrenzten vorhandenen HPM-Logfenster verfügbare HTTP- oder Browser-Event mit Zeit, Host, sicherem Seitenbereich, HTTP-Status, Browser-/OS-/Geräteklasse soweit erkennbar. Diese Einträge sind keine einzigartigen physischen Geräte; keine verdeckte Fingerprint-Verknüpfung.

## Datenschutz und Zugriff

Der VPS-Exporter liest One-SQLite ausschließlich read-only und exportiert höchstens 200 Metadatensätze über den vorhandenen privaten Pi-Sync. Keine Passwörter, Cookie-/Session-Token-Hashes, CSRF-Werte oder Klartext-Login-IDs. Die neue geschützte API GET /api/security/one-auth-devices verlangt users:list, während normale aggregierte HPM-Logs über logs:list zugänglich bleiben. Kein ungesicherter Zusammenhang zwischen One-Login und anonymen HPM-Events wird behauptet.

Das Cookie-Banner nennt jetzt notwendige Sitzungs-/Sicherheitscookies, optionale Tracking-Kennungen, Domains, Seitenbereiche, Interaktionen und 90-Tage-Speicherung. Ablehnen und DNT/GPC bleiben für optionales individuelles Tracking bestehen (§25 TDDDG); die Datenschutzerklärung bleibt erreichbar.

## Oberfläche

HYROVI Smart > Hosts & Analytics erhält eine zentrale, nach letzter Aktivität sortierte Liste aller drei Erkennungsstufen mit Suche, Domain-/Typfilter und Detailauswahl. One-Geräte zeigen verifizierte Gültigkeit, Browserprofile ihre tatsächliche Timeline, unbekannte Zugriffe ihre verfügbaren technischen Request-Metadaten. Host-Statistiken und Matomo-artige Stundenkurve bleiben erhalten.

## Grenzen

One löscht widerrufene Login-Geräte aus der registrierten Liste; ihre vollständige Historie wird hier nicht erfunden. Exakte Hardwaremodelle und die Zahl physischer Geräte sind aus anonymen HTTP-Headern nicht verlässlich messbar. Gültiger Login ist kein offener Tab oder Online-Heartbeat. Kein zusätzliches anonymes, langfristiges Tracking.
