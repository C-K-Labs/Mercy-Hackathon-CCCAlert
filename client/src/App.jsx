import { useEffect, useMemo, useState } from "react";

const POLL_INTERVAL_MS = 5000;

const severityClasses = {
  Low: "bg-emerald-500/15 text-emerald-100 ring-1 ring-inset ring-emerald-400/30",
  Moderate: "bg-amber-500/15 text-amber-100 ring-1 ring-inset ring-amber-400/30",
  High: "bg-orange-500/15 text-orange-100 ring-1 ring-inset ring-orange-400/30",
  Critical: "bg-rose-500/20 text-rose-100 ring-1 ring-inset ring-rose-400/40"
};

const statusClasses = {
  New: "bg-sky-500/15 text-sky-100 ring-1 ring-inset ring-sky-400/30",
  Reviewing: "bg-violet-500/15 text-violet-100 ring-1 ring-inset ring-violet-400/30",
  Escalated: "bg-fuchsia-500/15 text-fuchsia-100 ring-1 ring-inset ring-fuchsia-400/30",
  Closed: "bg-emerald-500/15 text-emerald-100 ring-1 ring-inset ring-emerald-400/30",
  "False Positive": "bg-slate-500/25 text-slate-100 ring-1 ring-inset ring-slate-400/30"
};

const priorityClasses = {
  Low: "bg-emerald-500/15 text-emerald-100 ring-1 ring-inset ring-emerald-400/30",
  Medium: "bg-amber-500/15 text-amber-100 ring-1 ring-inset ring-amber-400/30",
  High: "bg-rose-500/20 text-rose-100 ring-1 ring-inset ring-rose-400/40"
};

const actionClasses = {
  Log: "bg-slate-500/25 text-slate-100 ring-1 ring-inset ring-slate-400/30",
  "Contact Security": "bg-cyan-500/15 text-cyan-100 ring-1 ring-inset ring-cyan-400/30",
  "Contact Police": "bg-rose-500/20 text-rose-100 ring-1 ring-inset ring-rose-400/40"
};

const priorityToSeverity = {
  High: "High",
  Medium: "Moderate",
  Low: "Low"
};

function formatTimestamp(timestamp) {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? "Invalid timestamp" : date.toLocaleString();
}

function requestDateValue(timestamp) {
  if (!timestamp) return "";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}

function getSnapshotSource(incident) {
  try {
    const snapshot = incident?.metadata?.snapshotBase64;
    if (!snapshot || snapshot === "..." || snapshot.length === 0) return "";
    if (snapshot.startsWith("data:")) return snapshot;
    return `data:image/jpeg;base64,${snapshot}`;
  } catch (_) {
    return "";
  }
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    ...options
  });
  if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
  return response.json();
}

function matchesDateFilter(timestamp, filterDate) {
  if (!filterDate) return true;
  return requestDateValue(timestamp) === filterDate;
}

function App() {
  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");
  const [saving, setSaving] = useState("");
  const [draftNote, setDraftNote] = useState("");

  const [selectedArchivedIncident, setSelectedArchivedIncident] = useState(null);

  // Archived incidents section
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [archivedIncidents, setArchivedIncidents] = useState([]);
  const [archiveLoading, setArchiveLoading] = useState(false);
  const [archiveSearch, setArchiveSearch] = useState("");
  const [archiveReasonFilter, setArchiveReasonFilter] = useState("All");
  const [archivePriorityFilter, setArchivePriorityFilter] = useState("All");
  const [archiveSourceFilter, setArchiveSourceFilter] = useState("All");
  const [archiveDateFilter, setArchiveDateFilter] = useState("");
  const [testFiring, setTestFiring] = useState(false);
  const [testMessage, setTestMessage] = useState("");

  useEffect(() => {
    let active = true;

    async function loadIncidents() {
      try {
        const data = await requestJson("/incidents");
        if (!active) return;
        const nextIncidents = Array.isArray(data) ? data : [];
        setIncidents(nextIncidents);
        setError("");
        setLastUpdated(new Date().toLocaleTimeString());
        if (!selectedId && nextIncidents[0]) {
          setSelectedId(nextIncidents[0].id);
        }
      } catch (loadError) {
        if (!active) return;
        setError(loadError.message || "Unable to load incidents.");
      } finally {
        if (active) setLoading(false);
      }
    }

    loadIncidents();
    const intervalId = window.setInterval(loadIncidents, POLL_INTERVAL_MS);
    return () => { active = false; window.clearInterval(intervalId); };
  }, []);

  async function loadArchivedIncidents() {
    setArchiveLoading(true);
    try {
      const data = await requestJson("/archived-incidents");
      setArchivedIncidents(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || "Unable to load archived incidents.");
    } finally {
      setArchiveLoading(false);
    }
  }

  async function fireTestIncident() {
    setTestFiring(true);
    setTestMessage("");
    try {
      await requestJson("/webhooks/camera-incidents", {
        method: "POST",
        body: JSON.stringify({
          alert_type: "INCIDENT",
          severity: "HIGH",
          camera_id: "CAM-DEMO",
          description: "Individual with a weapon spotted near main entrance. Immediate threat detected.",
          timestamp: new Date().toISOString(),
          people: [{ person_id: 1, description: "Suspect in black jacket", is_new: true, is_return: false, times_seen: 1 }],
          cross_camera: true,
          cross_camera_note: "Same individual seen on CAM-2 thirty seconds ago.",
          snapshot_base64: ""
        })
      });
      setTestMessage("Test incident fired.");
    } catch (err) {
      setTestMessage("Failed: " + err.message);
    } finally {
      setTimeout(() => {
        setTestFiring(false);
        setTestMessage("");
      }, 3000);
    }
  }

  function toggleArchive() {
    const next = !archiveOpen;
    setArchiveOpen(next);
    if (next && archivedIncidents.length === 0) {
      loadArchivedIncidents();
    }
  }

  // Sort by timestamp descending (newest first)
  const sortedIncidents = useMemo(() => {
    return [...incidents].sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }, [incidents]);

  const selectedIncident = useMemo(() => {
    return incidents.find((incident) => incident.id === selectedId) || null;
  }, [incidents, selectedId]);

  useEffect(() => {
    if (selectedIncident) {
      setDraftNote(selectedIncident.notes || "");
      return;
    }
    if (sortedIncidents[0]) {
      setSelectedId(sortedIncidents[0].id);
      return;
    }
    setSelectedId("");
  }, [sortedIncidents, selectedIncident]);

  const stats = useMemo(() => {
    const highPriority = incidents.filter((i) => i.priority === "High").length;
    const escalated = incidents.filter((i) => i.status === "Escalated").length;
    const falsePositives = incidents.filter((i) => i.status === "False Positive").length;
    return { total: incidents.length, highPriority, escalated, falsePositives };
  }, [incidents]);

  async function updateIncident(url, payload) {
    setSaving(url);
    try {
      const updated = await requestJson(url, { method: "PATCH", body: JSON.stringify(payload) });
      setIncidents((current) =>
        current.map((incident) => (incident.id === updated.id ? updated : incident))
      );
      setError("");
    } catch (actionError) {
      setError(actionError.message || "Unable to update incident.");
    } finally {
      setSaving("");
    }
  }

  async function archiveIncident(id, reason) {
    setSaving(id);
    try {
      await requestJson(`/incidents/${id}/archive`, {
        method: "POST",
        body: JSON.stringify({ reason })
      });
      setIncidents((current) => current.filter((i) => i.id !== id));
      if (selectedId === id) setSelectedId("");
      setError("");
    } catch (actionError) {
      setError(actionError.message || "Unable to archive incident.");
    } finally {
      setSaving("");
    }
  }

  async function saveNote() {
    if (!selectedIncident) return;
    await updateIncident(`/incidents/${selectedIncident.id}/notes`, { notes: draftNote });
  }

  const displayIncident = selectedArchivedIncident || selectedIncident;
  const snapshotSource = getSnapshotSource(displayIncident);
  const systemTimeline = displayIncident?.timeline.filter((e) => e.type !== "note" && e.type !== "status") || [];
  const operatorTimeline = displayIncident?.timeline.filter((e) => e.type === "note" || e.type === "status") || [];

  const filteredArchived = useMemo(() => {
    const query = archiveSearch.trim().toLowerCase();
    return archivedIncidents.filter((a) => {
      const matchesSearch =
        !query ||
        [a.label, a.notes, a.source, a.priority, a.location]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(query));
      const matchesReason = archiveReasonFilter === "All" || a.archiveReason === archiveReasonFilter;
      const matchesPriority = archivePriorityFilter === "All" || a.priority === archivePriorityFilter;
      const matchesSource = archiveSourceFilter === "All" || (a.source || "").toUpperCase() === archiveSourceFilter;
      const matchesDate = matchesDateFilter(a.archivedAt, archiveDateFilter);
      return matchesSearch && matchesReason && matchesPriority && matchesSource && matchesDate;
    });
  }, [archivedIncidents, archiveSearch, archiveReasonFilter, archivePriorityFilter, archiveSourceFilter, archiveDateFilter]);

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,#18314f_0%,#08101b_45%,#030712_100%)] text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-[92rem] flex-col px-4 py-8 sm:px-6 lg:px-8">
        <header className="overflow-hidden rounded-[2rem] border border-cyan-400/20 bg-slate-950/70 shadow-2xl shadow-cyan-950/20 backdrop-blur">
          <div className="border-b border-white/10 px-6 py-6">
            <p className="text-sm font-semibold uppercase tracking-[0.35em] text-cyan-300">
              Campus Security Audit Console
            </p>
            <div className="mt-4 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
                  Incident dashboard and review trail
                </h1>
                <p className="mt-2 max-w-3xl text-sm text-slate-300 sm:text-base">
                  Security personnel can manually audit inbound incidents, review attached evidence,
                  track decisions, and verify routing actions from one interface.
                </p>
              </div>
              <div className="flex flex-col items-end gap-2">
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-300">
                  Feed refreshes every 5 seconds. Last updated:{" "}
                  <span className="font-semibold text-white">{lastUpdated || "Pending"}</span>
                </div>
                <div className="flex items-center gap-3">
                  {testMessage && (
                    <span className="text-sm font-semibold text-orange-300">{testMessage}</span>
                  )}
                  <button
                    type="button"
                    onClick={fireTestIncident}
                    disabled={testFiring}
                    className="rounded-2xl border border-orange-500/60 bg-orange-500/20 px-4 py-2 text-sm font-semibold text-orange-300 transition hover:bg-orange-500/30 hover:text-orange-200 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {testFiring ? "Firing..." : "Fire Test Incident"}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="grid gap-3 px-6 py-5 grid-cols-2 lg:grid-cols-4">
            <StatCard label="Total Incidents" value={stats.total} accent="text-cyan-300" />
            <StatCard label="High Priority" value={stats.highPriority} accent="text-rose-300" />
            <StatCard label="Escalated" value={stats.escalated} accent="text-fuchsia-300" />
            <StatCard label="False Positives" value={stats.falsePositives} accent="text-slate-200" />
          </div>
        </header>

        {error ? (
          <div className="mt-4 rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
            {error}
          </div>
        ) : null}

        <section className="mt-6 flex flex-col gap-6 lg:grid lg:grid-cols-[1.2fr,1.35fr]">
          {/* Left column: Incident Queue + Archived */}
          <div className="space-y-6">
            <div className="rounded-[2rem] border border-white/10 bg-slate-950/75 p-4 shadow-xl shadow-slate-950/40">
              <div className="mb-4 flex items-center justify-between px-2">
                <div>
                  <h2 className="text-lg font-semibold text-white">Incident Queue</h2>
                  <p className="text-sm text-slate-400">
                    Review-ready list ordered by recency.
                  </p>
                </div>
              </div>

              {loading ? (
                <StateMessage title="Loading incidents" description="Fetching the review queue." />
              ) : sortedIncidents.length === 0 ? (
                <StateMessage title="No active incidents" description="All clear." />
              ) : (
                <div className="overflow-hidden rounded-3xl border border-white/10">
                  <div className="hidden grid-cols-[1.7fr,0.8fr,0.8fr,1fr,1fr,1fr] gap-4 bg-slate-900/90 px-5 py-4 text-xs font-semibold uppercase tracking-[0.2em] text-slate-400 lg:grid">
                    <span>Incident</span>
                    <span>Priority</span>
                    <span>Status</span>
                    <span>Direction</span>
                    <span>Camera</span>
                    <span>Timestamp</span>
                  </div>

                  <div className="divide-y divide-white/10">
                    {sortedIncidents.map((incident) => {
                      const baseStyle = selectedId === incident.id
                        ? "bg-slate-900"
                        : "bg-slate-950/35 hover:bg-slate-900/80";
                      return (
                        <button
                          key={incident.id}
                          type="button"
                          onClick={() => { setSelectedId(incident.id); setSelectedArchivedIncident(null); }}
                          className={`grid w-full gap-3 px-5 py-4 text-left transition lg:grid-cols-[1.7fr,0.8fr,0.8fr,1fr,1fr,1fr] lg:items-start lg:gap-4 ${baseStyle}`}
                        >
                          <div className="min-w-0">
                            <p className="text-sm font-semibold text-white">{incident.label}</p>
                            <p className="mt-1 text-sm text-slate-300">{incident.summary}</p>
                          </div>
                          <QueueCell label="Priority">
                            <Badge value={`${incident.priority} Priority`} className={priorityClasses[incident.priority]} />
                          </QueueCell>
                          <QueueCell label="Status">
                            <Badge value={incident.status} className={statusClasses[incident.status]} />
                          </QueueCell>
                          <QueueCell label="Direction">
                            <Badge value={incident.recommendedAction} className={actionClasses[incident.recommendedAction]} />
                          </QueueCell>
                          <QueueCell label="Camera">
                            <span className="text-sm text-slate-200">{incident.location}</span>
                          </QueueCell>
                          <QueueCell label="Timestamp">
                            <span className="text-sm text-slate-200">{formatTimestamp(incident.timestamp)}</span>
                          </QueueCell>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* Archived Incidents collapsible */}
            <div className="rounded-[2rem] border border-white/10 bg-slate-950/75 shadow-xl shadow-slate-950/40">
              <button
                type="button"
                onClick={toggleArchive}
                className="flex w-full items-center justify-between px-6 py-5 text-left"
              >
                <div>
                  <h2 className="text-lg font-semibold text-white">Archived Incidents</h2>
                  <p className="text-sm text-slate-400">Closed and dismissed incidents.</p>
                </div>
                <span className="text-slate-400 text-xl">{archiveOpen ? "▲" : "▼"}</span>
              </button>

              {archiveOpen && (
                <div className="border-t border-white/10 p-5 space-y-4">
                  <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    <FilterInput
                      label="Search"
                      value={archiveSearch}
                      onChange={setArchiveSearch}
                      placeholder="Label, note, source..."
                    />
                    <FilterSelect
                      label="Archive Reason"
                      value={archiveReasonFilter}
                      onChange={setArchiveReasonFilter}
                      options={["All", "closed", "false_positive"]}
                    />
                    <FilterSelect
                      label="Priority"
                      value={archivePriorityFilter}
                      onChange={setArchivePriorityFilter}
                      options={["All", "High", "Medium", "Low"]}
                    />
                    <FilterSelect
                      label="Source"
                      value={archiveSourceFilter}
                      onChange={setArchiveSourceFilter}
                      options={["All", "EMERGENCY", "CHATBOT"]}
                    />
                    <FilterDate label="Date Archived" value={archiveDateFilter} onChange={setArchiveDateFilter} />
                  </div>

                  {archiveLoading ? (
                    <StateMessage title="Loading archives" description="Fetching archived records." />
                  ) : filteredArchived.length === 0 ? (
                    <StateMessage title="No archived incidents" description="Nothing matches the current filters." />
                  ) : (
                    <div className="overflow-x-auto rounded-2xl border border-white/10">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="bg-slate-900/90 text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                            <th className="px-4 py-3 text-left">Label</th>
                            <th className="px-4 py-3 text-left">Source</th>
                            <th className="px-4 py-3 text-left">Priority</th>
                            <th className="px-4 py-3 text-left">Reason</th>
                            <th className="px-4 py-3 text-left">Archived At</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-white/10">
                          {filteredArchived.map((a) => (
                            <tr
                              key={a.id}
                              onClick={() => { setSelectedArchivedIncident(a); setSelectedId(""); }}
                              className={`cursor-pointer transition ${selectedArchivedIncident?.id === a.id ? "bg-slate-800" : "bg-slate-950/40 hover:bg-slate-900/60"}`}
                            >
                              <td className="px-4 py-3 text-white">{a.label}</td>
                              <td className="px-4 py-3 text-slate-300">{a.source}</td>
                              <td className="px-4 py-3">
                                <Badge value={a.priority} className={priorityClasses[a.priority] || ""} />
                              </td>
                              <td className="px-4 py-3 text-slate-300">{a.archiveReason}</td>
                              <td className="px-4 py-3 text-slate-400">{formatTimestamp(a.archivedAt)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right column: Detail panel */}
          <aside className="rounded-[2rem] border border-white/10 bg-slate-950/80 p-5 shadow-xl shadow-slate-950/40">
            {!displayIncident ? (
              <StateMessage
                title="Select an incident"
                description="Choose a queue item to inspect evidence, routing, and action history."
              />
            ) : (
              <div className="space-y-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.25em] text-cyan-300">
                      Audit Detail{selectedArchivedIncident ? " — Archived" : ""}
                    </p>
                    <h2 className="mt-2 text-2xl font-semibold text-white">
                      {displayIncident.label}
                    </h2>
                    <p className="mt-2 text-sm text-slate-400">
                      Source: {displayIncident.source} | ID: {displayIncident.id}
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge value={`${displayIncident.priority} Priority`} className={priorityClasses[displayIncident.priority]} />
                    <Badge value={displayIncident.recommendedAction} className={actionClasses[displayIncident.recommendedAction]} />
                    <Badge value={displayIncident.status} className={statusClasses[displayIncident.status]} />
                    <Badge
                      value={priorityToSeverity[displayIncident.priority] || displayIncident.severity}
                      className={severityClasses[priorityToSeverity[displayIncident.priority]] || severityClasses[displayIncident.severity]}
                    />
                  </div>
                </div>

                <div className="grid gap-5 lg:grid-cols-[1.1fr,0.9fr]">
                  <section className="rounded-3xl border border-white/10 bg-white/5 p-4">
                    <div className="mb-3 flex items-center justify-between">
                      <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">
                        Evidence
                      </h3>
                      <span className="text-xs uppercase tracking-[0.18em] text-slate-500">
                        Report + photo pair
                      </span>
                    </div>
                    {snapshotSource ? (
                      <img
                        src={snapshotSource}
                        alt="Incident evidence"
                        style={{ width: "100%", maxHeight: "320px", objectFit: "contain", borderRadius: "8px" }}
                      />
                    ) : (
                      <div className="flex h-64 items-center justify-center rounded-2xl border border-dashed border-cyan-300/30 bg-slate-950/40 text-center text-sm text-slate-300">
                        Photo placeholder
                        <br />
                        Attached response image will appear here
                      </div>
                    )}
                    <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/70 p-4">
                      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                        Report Text
                      </p>
                      <p className="mt-2 text-sm leading-6 text-slate-200">
                        {displayIncident.metadata?.description || displayIncident.summary}
                      </p>
                    </div>
                  </section>

                  <section className="space-y-4">
                    <div className="rounded-3xl border border-white/10 bg-white/5 p-4">
                      <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">
                        Routing Snapshot
                      </h3>
                      <div className="mt-4 grid gap-3 sm:grid-cols-2">
                        <InfoCard label="Priority" value={displayIncident.priority} />
                        <InfoCard label="Direction" value={displayIncident.recommendedAction} />
                        <InfoCard label="Camera" value={displayIncident.location} />
                        <InfoCard label="Timestamp" value={formatTimestamp(displayIncident.timestamp)} />
                        <InfoCard label="Confidence" value={`${Math.round(displayIncident.confidence * 100)}%`} />
                        <InfoCard label="Urgency Score" value={String(displayIncident.urgencyScore)} />
                      </div>
                    </div>

                    <div className="rounded-3xl border border-white/10 bg-white/5 p-4">
                      <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">
                        Summary
                      </h3>
                      <p className="mt-3 text-sm leading-6 text-slate-200">{displayIncident.summary}</p>
                    </div>
                  </section>
                </div>

                {!selectedArchivedIncident && (
                <div className="rounded-3xl border border-white/10 bg-white/5 p-4">
                  <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">
                    Operator Actions
                  </h3>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <ActionButton
                      label="Mark Reviewing"
                      onClick={() => updateIncident(`/incidents/${displayIncident.id}/status`, { status: "Reviewing" })}
                      disabled={Boolean(saving)}
                    />
                    <ActionButton
                      label="Escalate"
                      onClick={() => updateIncident(`/incidents/${displayIncident.id}/status`, { status: "Escalated" })}
                      disabled={Boolean(saving)}
                    />
                    <ActionButton
                      label="Dismiss as False Positive"
                      onClick={() => archiveIncident(displayIncident.id, "false_positive")}
                      disabled={Boolean(saving)}
                    />
                    <ActionButton
                      label="Close Incident"
                      onClick={() => archiveIncident(displayIncident.id, "closed")}
                      disabled={Boolean(saving)}
                    />
                  </div>
                </div>
                )}

                <div className="rounded-3xl border border-white/10 bg-white/5 p-4">
                  <div className="flex items-center justify-between gap-4">
                    <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">
                      Operator Notes
                    </h3>
                    {!selectedArchivedIncident && (
                    <button
                      type="button"
                      onClick={saveNote}
                      disabled={Boolean(saving)}
                      className="rounded-full bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-300"
                    >
                      Save Note
                    </button>
                    )}
                  </div>
                  <textarea
                    value={draftNote}
                    onChange={(event) => setDraftNote(event.target.value)}
                    rows={7}
                    className="mt-4 w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-300/40"
                  />
                </div>

                <div className="grid gap-5 lg:grid-cols-2">
                  <TimelinePanel title="System Event History" events={systemTimeline} emptyLabel="No system events yet." />
                  <TimelinePanel title="Operator Audit Trail" events={operatorTimeline} emptyLabel="No operator actions yet." />
                </div>
              </div>
            )}
          </aside>
        </section>
      </div>
    </main>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/5 px-5 py-4">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">{label}</p>
      <p className={`mt-3 text-3xl font-semibold ${accent}`}>{value}</p>
    </div>
  );
}

function FilterInput({ label, value, onChange, placeholder }) {
  return (
    <label className="block">
      <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
        {label}
      </span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-300/40"
      />
    </label>
  );
}

function FilterSelect({ label, value, onChange, options }) {
  return (
    <label className="block">
      <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
        {label}
      </span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-300/40"
      >
        {options.map((option) => (
          <option key={option} value={option}>{option}</option>
        ))}
      </select>
    </label>
  );
}

function FilterDate({ label, value, onChange }) {
  return (
    <label className="block">
      <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
        {label}
      </span>
      <input
        type="date"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-300/40"
      />
    </label>
  );
}

function QueueCell({ label, children }) {
  return (
    <div className="min-w-0">
      <p className="mb-1 text-[0.65rem] font-semibold uppercase tracking-[0.18em] text-slate-500 lg:hidden">
        {label}
      </p>
      {children}
    </div>
  );
}

function InfoCard({ label, value }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">{label}</p>
      <p className="mt-2 text-sm text-white">{value}</p>
    </div>
  );
}

function Badge({ value, className }) {
  return (
    <span className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${className}`}>
      {value}
    </span>
  );
}

function ActionButton({ label, onClick, disabled }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-2xl border border-white/10 bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:border-cyan-300/40 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {label}
    </button>
  );
}

function TimelinePanel({ title, events, emptyLabel }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/5 p-4">
      <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-400">
        {title}
      </h3>
      <div className="mt-4 space-y-3">
        {events.length === 0 ? (
          <p className="text-sm text-slate-400">{emptyLabel}</p>
        ) : (
          events.map((event) => (
            <div key={event.id} className="flex gap-3">
              <div className="mt-1 h-2.5 w-2.5 rounded-full bg-cyan-300" />
              <div>
                <p className="text-sm font-medium text-white">{event.message}</p>
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                  {event.type} | {formatTimestamp(event.timestamp)}
                </p>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function StateMessage({ title, description }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/60 px-6 py-10 text-center">
      <h3 className="text-lg font-semibold text-white">{title}</h3>
      <p className="mt-2 text-sm text-slate-400">{description}</p>
    </div>
  );
}

export default App;
