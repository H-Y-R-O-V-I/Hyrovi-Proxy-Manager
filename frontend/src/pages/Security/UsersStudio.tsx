import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { IconActivity, IconDeviceDesktop, IconRefresh, IconUser } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import { getSecurityVisitor, getSecurityVisitors, saveSecurityVisitor } from "src/api/backend/securityVisitors";

const stamp = (value: string | null) => value ? new Date(value).toLocaleString() : "—";

export default function UsersStudio() {
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const list = useQuery({
    queryKey: ["security-visitors"], queryFn: getSecurityVisitors,
    refetchInterval: 60_000, staleTime: 20_000
  });
  const detail = useQuery({
    queryKey: ["security-visitor", selectedId],
    queryFn: () => getSecurityVisitor(selectedId || ""),
    enabled: Boolean(selectedId), staleTime: 20_000
  });
  const selected = detail.data?.visitor;
  useEffect(() => {
    if (selected) { setName(selected.name); setNotes(selected.notes); }
  }, [selected?.id, selected?.name, selected?.notes]);
  const save = useMutation({
    mutationFn: () => saveSecurityVisitor(selectedId || "", { name, notes }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["security-visitors"] });
      client.invalidateQueries({ queryKey: ["security-visitor", selectedId] });
    }
  });
  const filtered = useMemo(() => (list.data?.visitors || []).filter((visitor) => {
    const q = search.trim().toLowerCase();
    return !q || [visitor.name, visitor.id, visitor.browsers.join(" "),
      visitor.platforms.join(" "), ...visitor.sites.map((site) => site.host)]
      .join(" ").toLowerCase().includes(q);
  }), [list.data, search]);

  return <div>
    <div className="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-3">
      <div>
        <h2 className="mb-1">Users <span className="text-secondary">/ Fingerprint Studio</span></h2>
        <p className="text-secondary mb-0">Consented visitor IDs · Websites · Sessions · Actions</p>
      </div>
      <button type="button" className="btn btn-outline-secondary"
        onClick={() => { list.refetch(); if (selectedId) detail.refetch(); }}>
        <IconRefresh size={16} className="me-1" /> Refresh
      </button>
    </div>
    <div className="alert alert-info py-2" role="status">
      Only visitors who opted into first-party HYROVI analytics appear here. IDs can be shared across participating HYROVI subdomains.
      Browser properties are coarse diagnostics, not proof of a person's identity.
      Only app-declared action names are recorded; form contents, passwords and raw clicks are not.
    </div>
    <div className="row g-3 mb-3">
      <div className="col-sm-4"><div className="card"><div className="card-body d-flex align-items-center gap-3">
        <IconUser size={26} /><div><div className="text-secondary small">Opted-in visitors</div>
          <h3 className="mb-0">{list.data?.visitors.length ?? "—"}</h3></div>
      </div></div></div>
      <div className="col-sm-4"><div className="card"><div className="card-body d-flex align-items-center gap-3">
        <IconActivity size={26} /><div><div className="text-secondary small">Recorded events (recent)</div>
          <h3 className="mb-0">{list.data?.totalEvents ?? "—"}</h3></div>
      </div></div></div>
      <div className="col-sm-4"><div className="card"><div className="card-body d-flex align-items-center gap-3">
        <IconDeviceDesktop size={26} /><div><div className="text-secondary small">Covered websites</div>
          <h3 className="mb-0">{new Set((list.data?.visitors ?? []).flatMap(v => v.sites.map(s => s.host))).size}</h3></div>
      </div></div></div>
    </div>
    <div className="row g-3">
      <div className="col-lg-5">
        <div className="card">
          <div className="card-header"><h3 className="card-title">Visitors</h3></div>
          <div className="card-body">
            <input className="form-control" value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search visitor name, platform, website…" aria-label="Search visitors"/>
          </div>
          <div className="list-group list-group-flush" style={{ maxHeight: 580, overflowY: "auto" }}>
            {list.isLoading && <div className="p-3 text-secondary">Loading visitors…</div>}
            {list.error && <div className="p-3 text-danger">Visitor API unavailable: {String(list.error)}</div>}
            {!list.isLoading && filtered.length === 0 && <div className="p-3 text-secondary">
              No matching consented visitors. Existing anonymous proxy requests cannot be assigned to a person.
            </div>}
            {filtered.map(visitor => <button type="button" key={visitor.id}
              onClick={() => setSelectedId(visitor.id)}
              className={"list-group-item list-group-item-action " + (selectedId === visitor.id ? "active" : "")}>
                <div className="d-flex justify-content-between align-items-center gap-2">
                  <strong>{visitor.name || "Visitor " + visitor.id.slice(0, 9)}</strong>
                  <small>{visitor.pageViews} views</small>
                </div>
                <div className="small opacity-75">{visitor.platforms.join(", ") || "Unknown platform"}
                  {" · "}{visitor.browsers.join(", ") || "Unknown browser"}</div>
                <div className="small opacity-75">{visitor.sites.length} sites · Last {stamp(visitor.lastSeen)}</div>
              </button>)}
          </div>
        </div>
      </div>
      <div className="col-lg-7">
        {!selectedId ? <div className="card"><div className="card-body text-secondary">
          Select a visitor to see their website and action timeline and assign a name.
        </div></div> :
          <div className="d-flex flex-column gap-3">
            <div className="card">
              <div className="card-header"><h3 className="card-title">Visitor profile</h3></div>
              <div className="card-body">
                {detail.isLoading && <p>Loading profile…</p>}
                {detail.error && <p className="text-danger">{String(detail.error)}</p>}
                {selected && <>
                  <div className="row g-2 mb-3">
                    <div className="col-md-6"><label className="form-label">Custom name</label>
                      <input className="form-control" value={name} maxLength={120} onChange={(e)=>setName(e.target.value)}
                        placeholder="e.g. Test device / known visitor"/></div>
                    <div className="col-md-6"><label className="form-label">Notes</label>
                      <input className="form-control" value={notes} maxLength={500} onChange={(e)=>setNotes(e.target.value)}
                        placeholder="Optional internal note"/></div>
                  </div>
                  <div className="d-flex align-items-center gap-2 mb-3">
                    <button type="button" className="btn btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>
                      {save.isPending ? "Saving…" : "Save profile"}
                    </button>
                    {save.isSuccess && <span className="text-success">Saved</span>}
                    {save.error && <span className="text-danger">{String(save.error)}</span>}
                  </div>
                  <div className="small text-secondary text-break mb-2">Pseudonymous consent ID: {selected.id}</div>
                  <dl className="row mb-0">
                    <dt className="col-sm-4">First seen</dt><dd className="col-sm-8">{stamp(selected.firstSeen)}</dd>
                    <dt className="col-sm-4">Last seen</dt><dd className="col-sm-8">{stamp(selected.lastSeen)}</dd>
                    <dt className="col-sm-4">Sessions</dt><dd className="col-sm-8">{selected.sessions}</dd>
                    <dt className="col-sm-4">Events / actions</dt><dd className="col-sm-8">{selected.count} / {selected.actions}</dd>
                    <dt className="col-sm-4">Browser</dt><dd className="col-sm-8">{selected.browsers.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Platform</dt><dd className="col-sm-8">{selected.platforms.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Languages</dt><dd className="col-sm-8">{selected.languages.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Timezone</dt><dd className="col-sm-8">{selected.timezones.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Viewport buckets</dt><dd className="col-sm-8">{selected.viewports.join(", ") || "Not reported"}</dd>
                    <dt className="col-sm-4">Websites</dt><dd className="col-sm-8">{selected.sites.map(s => s.host + " (" + s.count + ")").join(" · ")}</dd>
                  </dl>
                </>}
              </div>
            </div>
            <div className="card">
              <div className="card-header"><h3 className="card-title">Activity timeline</h3></div>
              <div className="table-responsive" style={{maxHeight: 540, overflowY: "auto"}}>
                <table className="table table-vcenter card-table">
                  <thead><tr><th>When</th><th>Website</th><th>Activity</th></tr></thead>
                  <tbody>{(detail.data?.timeline || []).map(event =>
                    <tr key={event.id}><td className="text-secondary small">{stamp(event.timestamp)}</td>
                      <td className="small text-break">{event.host}</td>
                      <td><span className="badge bg-blue-lt">{event.type.replace(/_/g, " ")}</span>
                        <div className="small text-break mt-1">{event.action || event.path}</div>
                      </td></tr>)}
                    {detail.data?.timeline.length === 0 && <tr><td colSpan={3}>No retained events.</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          </div>}
      </div>
    </div>
    <p className="text-secondary small mt-3">Profiles cover only the retained recent analytics log, not complete lifetime history.
      Cross-site IDs are shared only among participating HYROVI subdomains after consent. This view currently lists analytics received by the Raspberry Pi HPM node.</p>
  </div>;
}
