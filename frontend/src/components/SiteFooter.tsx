import { useHealth } from "src/hooks";

const REPOSITORY_URL = "https://github.com/H-Y-R-O-V-I/Hyrovi-Proxy-Manager";

export function SiteFooter() {
	const health = useHealth();

	const version = health.data
		? `v${health.data.version.major}.${health.data.version.minor}.${health.data.version.revision}`
		: null;

	return (
		<footer className="footer d-print-none py-3">
			<div className="container-xl">
				<div className="d-flex flex-column flex-lg-row align-items-center justify-content-between gap-2 text-center text-lg-start">
					<div className="text-secondary small">
						© 2026 HYROVI · HYROVI Proxy Manager{version ? ` · ${version}` : ""}
					</div>
					<div className="d-flex align-items-center gap-3 small">
						<span className="text-secondary">HYROVI Sec integrated</span>
						<a href={REPOSITORY_URL} target="_blank" rel="noopener noreferrer" className="link-secondary">
							Source repository
						</a>
					</div>
				</div>
			</div>
		</footer>
	);
}
