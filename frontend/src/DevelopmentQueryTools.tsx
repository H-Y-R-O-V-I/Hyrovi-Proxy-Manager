import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { useState } from "react";
import {
	enablePersistentTestVisitor,
	getVisitorCookieTestStatus,
	resetPersistentTestVisitor
} from "./development/visitorCookie";

// Vite development only; App.tsx removes this component from production builds.
export default function DevelopmentQueryTools() {
	const [open, setOpen] = useState(false);
	const [status, setStatus] = useState(() => getVisitorCookieTestStatus());
	const [error, setError] = useState("");

	const run = (action: () => typeof status) => {
		try { setStatus(action()); setError(""); }
		catch (err) { setError(err instanceof Error ? err.message : "Cookie-Test fehlgeschlagen"); }
	};

	return <>
		<ReactQueryDevtools buttonPosition="bottom-right" position="right" />
		<aside style={{
			position: "fixed", bottom: 12, left: 12, zIndex: 1040, maxWidth: 335,
			background: "#fff", color: "#27323f", border: "1px solid #cbd5e1",
			borderRadius: 8, boxShadow: "0 3px 16px #0002", padding: 9,
			fontSize: 12
		}}>
			<button type="button" className="btn btn-outline-secondary btn-sm"
				onClick={() => { setStatus(getVisitorCookieTestStatus()); setOpen(!open); }}>
				Development · Besucher-Cookie {open ? "▴" : "▾"}
			</button>
			{open && <div style={{ marginTop: 8 }}>
				<div>Cookie-Bereich: <strong>{status.scope}</strong></div>
				<div>90-Tage-Cookie: <strong>{status.persistentIdPresent ? "vorhanden (…" + status.idEnding + ")" : "nicht vorhanden"}</strong></div>
				<div>Tracking für diesen Testbrowser: <strong>{status.optedIn ? "aktiv" : "inaktiv"}</strong></div>
				<p style={{ margin: "7px 0" }}>
					Nach Neustart des Browsers auf „Prüfen“ klicken:
					die Besucher-ID bleibt gleich, eine neue Session-ID wird erzeugt.
					Nur für den eigenen Testbrowser aktivieren.
				</p>
				{status.privacyBlocked && <div role="alert">DNT/GPC aktiv: individuelle Statistik gesperrt.</div>}
				{error && <div role="alert" style={{ color: "#a00" }}>{error}</div>}
				<div className="d-flex flex-wrap gap-1">
					<button type="button" className="btn btn-primary btn-sm"
						disabled={!status.supported || status.privacyBlocked}
						onClick={() => run(enablePersistentTestVisitor)}>
						90-Tage-Test-Cookie aktivieren
					</button>
					<button type="button" className="btn btn-outline-secondary btn-sm"
						onClick={() => run(getVisitorCookieTestStatus)}>Prüfen</button>
					<button type="button" className="btn btn-outline-danger btn-sm"
						disabled={!status.supported}
						onClick={() => run(resetPersistentTestVisitor)}>Test-Cookie zurücksetzen</button>
				</div>
			</div>}
		</aside>
	</>;
}
