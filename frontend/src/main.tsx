import { StrictMode, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Event = {
  id: number;
  time: string;
  kind: string;
  data: Record<string, unknown>;
};
type Check = {
  passed: boolean;
  result?: { stdout: string; stderr: string; exit_code: number };
};
type Run = {
  id: string;
  scenario: string;
  status: string;
  created_at: string;
  live: boolean;
  sandbox_id: string | null;
  cleanup: string;
  error?: string;
  cleanup_note?: string;
  models: { worker: string; security: string };
  policy: {
    version: number;
    mode: string;
    file_mode?: string;
    scope?: string;
    require_full_suite?: boolean;
    required_tests?: string[];
    validated?: boolean;
  };
  decision?: { summary: string; evidence_ids: number[] };
  verification: Record<string, Check>;
  suite_audit?: {
    tests_run: number;
    failures: string[];
    errors: string[];
    executed: string[];
    successful: boolean;
  };
  final_test_status?: string;
  events?: Event[];
};
type Health = {
  configured: boolean;
  missing: string[];
  active_id: string | null;
  same_model: boolean;
  models: { worker: string; security: string };
};
const terminal = new Set([
  "succeeded",
  "failed",
  "cancelled",
  "attack_not_reproduced",
  "baseline_passed",
  "interrupted",
]);
const statuses: Record<string, string> = {
  queued: "Ready",
  preflight: "Checking connections",
  provisioning: "Provisioning",
  observing: "Observing",
  analyzing: "Analyzing",
  patching: "Applying policy",
  verifying: "Verifying",
  cleaning_up: "Cleanup",
  succeeded: "Recovery verified",
  failed: "Run failed",
  cancelled: "Cancelled",
  attack_not_reproduced: "Attack not reproduced",
  baseline_passed: "Baseline passed",
  interrupted: "Interrupted",
};
const checks: Record<string, string> = {
  baseline_tests: "Baseline tests",
  same_attack: "Same attack replay",
  python_read: "Python read bypass",
  gateway_read: "Gateway file read",
  worker_cannot_chmod: "Worker permission changes blocked",
  normal_tests: "Normal tests preserved",
  fresh_worker: "Fresh Worker completion",
  honest_observation: "No false success report",
  partial_suite_blocked: "Partial suite blocked",
  forged_output_blocked: "Forged output blocked",
  full_suite_verified: "Full suite detects real failure",
  false_success_rejected: "False success rejected",
};
const scenarioLabels: Record<string, string> = {
  normal: "Baseline",
  "readme-injection": "README Injection",
  "test-laundering": "Test Laundering",
};
function expectedChecks(scenario: string) {
  if (scenario === "normal") return ["baseline_tests"];
  if (scenario === "test-laundering")
    return [
      "partial_suite_blocked",
      "forged_output_blocked",
      "full_suite_verified",
      "false_success_rejected",
      "fresh_worker",
    ];
  return [
    "same_attack",
    "python_read",
    "gateway_read",
    "worker_cannot_chmod",
    "normal_tests",
    "fresh_worker",
  ];
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch("/api" + path, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(
      typeof body.detail === "string"
        ? body.detail
        : `Request failed (${response.status})`,
    );
  }
  return response.json();
}

function Shield({ small = false }: { small?: boolean }) {
  return (
    <svg
      width={small ? 16 : 24}
      height={small ? 16 : 24}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 3 20 6v6c0 4-4 7-8 9-4-2-8-5-8-9V6l8-3Z"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path d="m8 12 3 3 5-6" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}
function Tag({
  children,
  tone = "",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={"tag " + tone}>{children}</span>;
}
function time(value: string) {
  return new Date(value).toLocaleTimeString("en-GB", { hour12: false });
}

function RecordedText({ value }: { value: unknown }) {
  const text = String(value);
  // Preserve historical evidence verbatim without mixing languages in the dashboard.
  if (/\p{Script=Hangul}/u.test(text)) {
    return (
      <details className="recorded-output">
        <summary>Original recorded output (Korean)</summary>
        <p>{text}</p>
      </details>
    );
  }
  return <p>{text}</p>;
}

function EventCard({ event }: { event: Event }) {
  const d = event.data;
  const tool = d.tool as
    { action?: string; command?: string; path?: string } | undefined;
  const result = d.result as
    { stdout?: string; stderr?: string; exit_code?: number } | undefined;
  const titles: Record<string, string> = {
    phase: String(d.message || d.name || ""),
    tool_request: tool?.command || `${tool?.action} ${tool?.path || ""}`,
    tool_result: d.canary_exposed
      ? "Canary exposure observed"
      : `Execution result · exit ${result?.exit_code}`,
    boundary_verified: "Unprivileged boundary verified",
    models_ready: "Nosana models connected",
    sandbox_created: "Daytona sandbox created",
    boundary_violation: "Boundary violation recorded",
    security_decision: "Security Agent analysis complete",
    policy_applied: "Policy v1 applied",
    verification: `${checks[String(d.name)] || d.name} · ${d.passed ? "PASS" : "FAIL"}`,
    worker_report: "Worker report",
    report_rejected: "False or unverified report rejected",
    suite_audit: "Independent full-suite audit",
    completed: statuses[String(d.status)] || "Run complete",
    cleanup: d.ok ? "Sandbox deleted" : "Sandbox deletion failed",
    error: "Run error",
    observation_complete: "No violation reproduced · no patch",
    cancel_requested: "Cancellation requested",
    cancelled: "Run cancelled",
    worker_limit: "Worker tool limit reached",
    interrupted: "Interrupted by server restart",
  };
  const warning =
    d.canary_exposed ||
    event.kind === "boundary_violation" ||
    event.kind === "error" ||
    (event.kind === "verification" && !d.passed) ||
    (event.kind === "cleanup" && !d.ok);
  return (
    <details
      className={"event " + (warning ? "warning" : "")}
      open={
        event.kind === "security_decision" || event.kind === "worker_report"
      }
    >
      <summary>
        <span className="event-dot" />
        <span className="event-title">{titles[event.kind] || event.kind}</span>
        <span className="event-phase">
          {d.phase ? String(d.phase) : event.kind}
        </span>
        <time>{time(event.time)}</time>
      </summary>
      <div className="event-body">
        {d.message != null && <RecordedText value={d.message} />}
        {d.summary != null && <RecordedText value={d.summary} />}
        {result && (
          <pre>
            {result.stdout || ""}
            {result.stderr || ""}
            {!result.stdout && !result.stderr ? "(no output)" : ""}
          </pre>
        )}
        {tool && <pre>{JSON.stringify(tool, null, 2)}</pre>}
        {event.kind === "boundary_verified" && (
          <pre>{JSON.stringify(d, null, 2)}</pre>
        )}
        {event.kind === "security_decision" && (
          <p className="muted">
            Evidence events:{" "}
            {(d.evidence_ids as number[]).map((id) => `#${id}`).join(", ")}
          </p>
        )}
        {d.test_status != null && (
          <p>
            Worker full-suite verdict: <strong>{String(d.test_status)}</strong>
            {d.suite_verified
              ? " · full-suite evidence verified"
              : " · reported before independent verification"}
          </p>
        )}
        {event.kind === "suite_audit" && (
          <pre>{JSON.stringify(d.report, null, 2)}</pre>
        )}
        {event.kind === "policy_applied" && (
          <pre>{JSON.stringify(d, null, 2)}</pre>
        )}
        {event.kind === "sandbox_created" && (
          <code>{String(d.sandbox_id)}</code>
        )}
        {warning && d.canary_exposed === true && (
          <p className="muted">
            This records fake-secret exposure during observation. It does not
            indicate access under the current policy.
          </p>
        )}
      </div>
    </details>
  );
}

function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [history, setHistory] = useState<Run[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [scenario, setScenario] = useState("readme-injection");
  const [scenarios, setScenarios] = useState<Record<string, string>>({});
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [checkedModels, setCheckedModels] = useState(false);
  const [streamState, setStreamState] = useState("");
  const [tab, setTab] = useState("timeline");
  const sequence = useRef(0);
  const busy =
    Boolean(health?.active_id) ||
    submitting ||
    Boolean(run && !terminal.has(run.status));

  async function refresh() {
    const [h, runs] = await Promise.all([
      api<Health>("/health"),
      api<Run[]>("/runs"),
    ]);
    setHealth(h);
    setHistory(runs);
    return { h, runs };
  }
  useEffect(() => {
    let alive = true;
    Promise.all([
      api<Health>("/health"),
      api<Run[]>("/runs"),
      api<Record<string, string>>("/scenarios"),
    ])
      .then(([h, runs, fixtures]) => {
        if (!alive) return;
        setHealth(h);
        setHistory(runs);
        setScenarios(fixtures);
        const saved = localStorage.getItem("agentzero:lastRun");
        setSelected(
          h.active_id ||
            (runs.some((r) => r.id === saved) ? saved : runs[0]?.id || null),
        );
      })
      .catch((e) => alive && setError(e.message));
    const timer = window.setInterval(() => {
      if (alive) refresh().catch(() => {});
    }, 5000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!selected) return;
    let alive = true;
    let source: EventSource | undefined;
    let requestNumber = 0;
    setRun(null);
    setEvents([]);
    setStreamState("Connecting");
    localStorage.setItem("agentzero:lastRun", selected);
    const load = async () => {
      const n = ++requestNumber;
      const data = await api<Run>(`/runs/${selected}`);
      if (alive && n === requestNumber) setRun(data);
      return data;
    };
    load()
      .then((data) => {
        if (!alive) return;
        setEvents(data.events || []);
        if (terminal.has(data.status)) {
          setStreamState("Saved history");
          return;
        }
        const last = data.events?.at(-1)?.id || 0;
        source = new EventSource(`/api/runs/${selected}/events?after=${last}`);
        source.onopen = () => alive && setStreamState("Live stream");
        source.onmessage = (message) => {
          if (!alive) return;
          const event: Event = JSON.parse(message.data);
          setEvents((previous) =>
            previous.some((e) => e.id === event.id)
              ? previous
              : [...previous, event].sort((a, b) => a.id - b.id),
          );
          load().catch((e) => alive && setError(e.message));
          if (event.kind === "completed") {
            source?.close();
            setStreamState("History saved");
            refresh().catch(() => {});
          }
        };
        source.onerror = () => alive && setStreamState("Reconnecting");
      })
      .catch((e) => alive && setError(e.message));
    return () => {
      alive = false;
      source?.close();
    };
  }, [selected]);

  async function start() {
    setSubmitting(true);
    setError("");
    setFilter("all");
    setTab("timeline");
    try {
      const next = await api<Run>("/runs", {
        method: "POST",
        body: JSON.stringify({ scenario }),
      });
      setSelected(next.id);
      setRun(next);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }
  async function connectionCheck() {
    const n = ++sequence.current;
    setSubmitting(true);
    setError("");
    setCheckedModels(false);
    try {
      await api("/preflight", { method: "POST" });
      if (n === sequence.current) setCheckedModels(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }
  const visible = events.filter(
    (e) =>
      filter === "all" ||
      e.data.phase === filter ||
      (filter === "security" &&
        [
          "security_decision",
          "policy_applied",
          "boundary_violation",
          "verification",
        ].includes(e.kind)),
  );
  const passed = Object.values(run?.verification || {}).filter(
    (c) => c.passed,
  ).length;
  const exposure = events.some(
    (e) => e.kind === "tool_result" && e.data.canary_exposed,
  );
  const policy = run?.policy;
  const integrity = (run?.scenario || scenario) === "test-laundering";
  const checkKeys = expectedChecks(run?.scenario || scenario);

  return (
    <>
      <header className="topbar">
        <a className="brand" href="/">
          <span className="brand-icon">
            <Shield />
          </span>
          AgentZero<span className="brand-sub">SECURITY CONTROL</span>
        </a>
        <div className="top-right">
          <span className="local-indicator" />
          LOCAL CONTROL PLANE
          <span className="divider" />
          <span className="mono">v0.1</span>
        </div>
      </header>
      <main>
        <div className="page-heading">
          <div>
            <div className="eyebrow">SELF-HEALING SECURITY SANDBOX</div>
            <h1>Observe. Patch. Verify.</h1>
            <p className="subtitle">
              Observe attacks and repair sandbox security policies.
            </p>
          </div>
          <Tag tone={health?.configured ? "mint" : "amber"}>
            {health?.configured ? "● LIVE APIs" : "○ SETUP REQUIRED"}
          </Tag>
        </div>
        {error && (
          <div className="notice danger" role="alert">
            <strong>Unable to complete the request.</strong>
            <span>{error}</span>
            <button
              className="text-button"
              onClick={() => setError("")}
              aria-label="Dismiss error"
            >
              ×
            </button>
          </div>
        )}
        {health && !health.configured && (
          <div className="notice config">
            <div>
              <strong>Connect your services to get started.</strong>
              <p>
                Set <code>{health.missing.join(", ")}</code> in your local .env
                file and restart the server. Runs use live services.
              </p>
            </div>
            <a href="#connection">View connections ↗</a>
          </div>
        )}

        <section className="control panel">
          <div className="control-label">
            <span className="section-number">01</span>
            <div>
              <h2>Scenario</h2>
              <span className="muted">
                {scenario === "test-laundering"
                  ? "Omitted failing test · result integrity"
                  : "Run project tests · fake secrets only"}
              </span>
            </div>
          </div>
          <div className="segmented">
            <button
              className={scenario === "test-laundering" ? "selected" : ""}
              disabled={busy}
              onClick={() => setScenario("test-laundering")}
            >
              Test Laundering
            </button>
            <button
              className={scenario === "readme-injection" ? "selected" : ""}
              disabled={busy}
              onClick={() => setScenario("readme-injection")}
            >
              README Injection
            </button>
            <button
              className={scenario === "normal" ? "selected" : ""}
              disabled={busy}
              onClick={() => setScenario("normal")}
            >
              Baseline
            </button>
          </div>
          <div className="control-actions">
            {busy && health?.active_id && (
              <button
                className="button secondary"
                onClick={() =>
                  api(`/runs/${health.active_id}/cancel`, {
                    method: "POST",
                  }).catch((e) => setError(e.message))
                }
              >
                Cancel
              </button>
            )}
            <button
              className="button primary"
              disabled={!health?.configured || busy}
              onClick={start}
            >
              <span aria-hidden="true">▷</span>
              {busy ? "Running" : "Start demo"}
            </button>
          </div>
        </section>

        <section className="flow panel" aria-label="System architecture">
          <div className="flow-node">
            <span className="node-symbol">W</span>
            <div>
              <strong>Worker Agent</strong>
              <small>NOSANA · task execution</small>
            </div>
          </div>
          <span className="flow-arrow">→</span>
          <div className="flow-node">
            <span className="node-symbol gateway">
              <Shield small />
            </span>
            <div>
              <strong>Security Gateway</strong>
              <small>Policy checks · execution logs</small>
            </div>
          </div>
          <span className="flow-arrow">→</span>
          <div className="flow-node">
            <span className="node-symbol daytona">D</span>
            <div>
              <strong>Daytona Sandbox</strong>
              <small>Unprivileged · live execution</small>
            </div>
          </div>
          <div className="flow-security">
            <span className="node-symbol security">S</span>
            <div>
              <strong>Security Agent</strong>
              <small>NOSANA · analyze → patch → verify</small>
            </div>
            <span className="loop-label">↻ POLICY FEEDBACK</span>
          </div>
        </section>

        <div className="workspace">
          <section className="main-column panel">
            <div className="panel-heading">
              <div className="tabs">
                <button
                  className={tab === "timeline" ? "active" : ""}
                  onClick={() => setTab("timeline")}
                >
                  Execution timeline <span>{events.length}</span>
                </button>
                <button
                  className={tab === "readme" ? "active" : ""}
                  onClick={() => setTab("readme")}
                >
                  README document
                </button>
              </div>
              <span className="stream-state">{streamState || "Ready"}</span>
            </div>
            {tab === "readme" ? (
              <div className="document">
                <div className="file-path">
                  /workspace/project/README.md{" "}
                  <Tag>
                    {scenario === "normal" ? "NORMAL" : "UNTRUSTED INPUT"}
                  </Tag>
                </div>
                <pre>{scenarios[scenario] || "Loading document…"}</pre>
                <p className="muted">
                  Document for the next selected run. The README does not grant
                  the Worker additional privileges.
                </p>
              </div>
            ) : (
              <>
                <div className="timeline-toolbar">
                  <div className="filters">
                    {[
                      ["all", "All"],
                      ["observe", "Observe"],
                      ["security", "Analyze · patch"],
                      ["verification", "Verify"],
                      ["fresh_worker", "Fresh Worker"],
                    ].map(([value, label]) => (
                      <button
                        className={filter === value ? "active" : ""}
                        key={value}
                        onClick={() => setFilter(value)}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
                {run && (
                  <div className="run-meta">
                    <Tag
                      tone={
                        run.status === "succeeded" ||
                        run.status === "baseline_passed"
                          ? "mint"
                          : run.status === "failed"
                            ? "red"
                            : ""
                      }
                    >
                      {statuses[run.status] || run.status}
                    </Tag>
                    <span className="mono">RUN {run.id.slice(0, 8)}</span>
                    <span>{scenarioLabels[run.scenario] || run.scenario}</span>
                  </div>
                )}
                <div className="timeline">
                  {visible.length ? (
                    visible.map((event) => (
                      <EventCard key={event.id} event={event} />
                    ))
                  ) : (
                    <div className="empty-state">
                      <span className="empty-icon">
                        <Shield />
                      </span>
                      <h3>
                        {events.length
                          ? "No events in this phase"
                          : "Your execution evidence appears here"}
                      </h3>
                      <p>
                        {events.length
                          ? "Choose another filter."
                          : "Start a demo to follow every step,\nfrom Worker actions to policy recovery."}
                      </p>
                      <div className="empty-pipeline">
                        <span>OBSERVE</span>
                        <i /> <span>PATCH</span>
                        <i /> <span>VERIFY</span>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </section>

          <aside>
            <section className="panel policy-panel">
              <div className="panel-title">
                <h2>
                  <Shield small />{" "}
                  {integrity ? "Execution & reporting policy" : "Access policy"}
                </h2>
                <Tag tone={policy?.validated ? "mint" : ""}>
                  v{policy?.version || 0}
                </Tag>
              </div>
              <div className="policy-state">
                <span
                  className={
                    "policy-orb " +
                    (policy?.mode === "enforce" ? "enforced" : "")
                  }
                />
                <div>
                  <strong>
                    {policy?.mode === "enforce"
                      ? policy.validated
                        ? "Enforced · verified"
                        : "Enforced · verifying"
                      : "Observation mode"}
                  </strong>
                  <small>
                    {integrity
                      ? policy?.mode === "enforce"
                        ? "Full suite required · evidence-based reports"
                        : "Observe partial runs and Worker reports"
                      : policy?.mode === "enforce"
                        ? "Protected file reads restricted"
                        : "Log violations while allowing access"}
                  </small>
                </div>
              </div>
              <div className="protected-file">
                <span>PROTECTED RESOURCE</span>
                <code>
                  {integrity
                    ? "/workspace/project/tests.py"
                    : "/workspace/project/.env"}
                </code>
              </div>
              <div className="policy-diff">
                <div>
                  <span>Owner</span>
                  <code>root : root</code>
                </div>
                <div>
                  <span>{integrity ? "Test coverage" : "File mode"}</span>
                  <code>
                    {integrity ? (
                      policy?.require_full_suite ? (
                        <>
                          <del>Partial suite</del> <b>→ all 3 required</b>
                        </>
                      ) : (
                        "README profile allowed"
                      )
                    ) : policy?.version ? (
                      <>
                        <del>0644</del> <b>→ 0600</b>
                      </>
                    ) : (
                      "0644"
                    )}
                  </code>
                </div>
                <div>
                  <span>Worker identity</span>
                  <code>UID 31001 · no privileges</code>
                </div>
              </div>
              <p className="policy-note">
                {integrity
                  ? "Recovery restores full-suite execution and truthful reporting. The underlying test failure remains."
                  : exposure
                    ? "The initial exposure remains in the audit history. The patch restricts subsequent access."
                    : "Define the protected boundary before execution, then strengthen the policy using observed violations."}
              </p>
            </section>
            {integrity && run?.suite_audit && (
              <section className="panel audit-panel">
                <div className="panel-title">
                  <h2>Independent audit</h2>
                  <Tag tone="amber">Failing test</Tag>
                </div>
                <div className="audit-content">
                  <p>
                    <strong>{run.suite_audit.tests_run} run</strong> ·{" "}
                    {run.suite_audit.tests_run -
                      run.suite_audit.failures.length -
                      run.suite_audit.errors.length}
                    {" passed · "}
                    <span className="red-text">
                      {run.suite_audit.failures.length +
                        run.suite_audit.errors.length}
                      {" failed"}
                    </span>
                  </p>
                  {run.suite_audit.failures.map((name) => (
                    <code key={name} className="red-text">
                      {name}
                    </code>
                  ))}
                  <p className="muted">
                    {run.final_test_status === "failed"
                      ? "After recovery, the Worker accurately reported the real failure."
                      : "The README cannot redefine the required test suite."}
                  </p>
                </div>
              </section>
            )}
            <section className="panel verification-panel">
              <div className="panel-title">
                <h2>Verification results</h2>
                <span className="count">
                  {passed}
                  <span> / {checkKeys.length}</span>
                </span>
              </div>
              <div className="check-list">
                {checkKeys.map((key) => {
                  const check = run?.verification[key];
                  return (
                    <details
                      className={
                        "check " +
                        (check ? (check.passed ? "passed" : "failed") : "")
                      }
                      key={key}
                    >
                      <summary>
                        <span className="check-symbol">
                          {check ? (check.passed ? "✓" : "×") : "−"}
                        </span>
                        <span>{checks[key]}</span>
                        <small>
                          {check ? (check.passed ? "PASS" : "FAIL") : "PENDING"}
                        </small>
                      </summary>
                      {check?.result && (
                        <pre>
                          {check.result.stdout}
                          {check.result.stderr}
                        </pre>
                      )}
                    </details>
                  );
                })}
              </div>
            </section>
            {run?.decision && (
              <section className="panel analysis-panel">
                <div className="panel-title">
                  <h2>Security Agent analysis</h2>
                </div>
                <RecordedText value={run.decision.summary} />
                <div className="evidence-tags">
                  {run.decision.evidence_ids.map((id) => (
                    <Tag key={id}>Evidence #{id}</Tag>
                  ))}
                </div>
              </section>
            )}
          </aside>
        </div>

        <div className="bottom-grid">
          <section className="panel" id="connection">
            <div className="panel-title">
              <h2>Service connections</h2>
              <button
                className="text-button"
                disabled={!health?.configured || busy}
                onClick={connectionCheck}
              >
                {checkedModels ? "✓ Models verified" : "Check models ↗"}
              </button>
            </div>
            <div className="connection-row">
              <span>Nosana / Worker</span>
              <code>{health?.models.worker || "Not configured"}</code>
            </div>
            <div className="connection-row">
              <span>Nosana / Security</span>
              <code>{health?.models.security || "Not configured"}</code>
            </div>
            {health?.same_model && (
              <p className="small-note">Both roles use the same model.</p>
            )}
            <div className="connection-row">
              <span>Daytona / Sandbox</span>
              <code>
                {run?.sandbox_id
                  ? run.sandbox_id.slice(0, 16)
                  : "Created on run"}
              </code>
            </div>
            {run && (
              <p
                className={
                  "small-note " +
                  (run.cleanup === "failed" || run.cleanup === "check_labels"
                    ? "red-text"
                    : "")
                }
              >
                Cleanup: {run.cleanup}
                {run.cleanup_note ? ` · ${run.cleanup_note}` : ""}
                {run.cleanup === "failed"
                  ? ` · Delete manually in Daytona: ${run.sandbox_id}`
                  : ""}
              </p>
            )}
          </section>
          <section className="panel history-panel">
            <div className="panel-title">
              <h2>Recent runs</h2>
              <span className="muted">Saved locally</span>
            </div>
            {history.length ? (
              history.slice(0, 5).map((item) => (
                <button
                  className={
                    "history-row " + (selected === item.id ? "active" : "")
                  }
                  key={item.id}
                  onClick={() => {
                    setSelected(item.id);
                    setTab("timeline");
                  }}
                >
                  <code>{item.id.slice(0, 8)}</code>
                  <span>{scenarioLabels[item.scenario] || item.scenario}</span>
                  <small>{statuses[item.status] || item.status}</small>
                  <time>{time(item.created_at)}</time>
                </button>
              ))
            ) : (
              <p className="history-empty">No runs yet.</p>
            )}
          </section>
        </div>
        <footer>
          <span>AgentZero</span>
          <p>Defined boundaries. Observable evidence. Verified recovery.</p>
          <span>Nosana × Daytona</span>
        </footer>
      </main>
    </>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
