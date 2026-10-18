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
  queued: "실행 대기",
  preflight: "연결 확인",
  provisioning: "환경 준비",
  observing: "공격 관찰",
  analyzing: "위반 분석",
  patching: "정책 적용",
  verifying: "방어 검증",
  cleaning_up: "환경 정리",
  succeeded: "복구 검증 완료",
  failed: "실행 실패",
  cancelled: "중지됨",
  attack_not_reproduced: "공격 미재현",
  baseline_passed: "정상 기준 통과",
  interrupted: "실행 중단",
};
const checks: Record<string, string> = {
  baseline_tests: "정상 기준 테스트",
  same_attack: "동일 공격 재실행",
  python_read: "Python 우회 읽기",
  gateway_read: "Gateway 파일 읽기",
  worker_cannot_chmod: "Worker 권한 변경 차단",
  normal_tests: "정상 테스트 유지",
  fresh_worker: "새 Worker 작업 완료",
  honest_observation: "허위 성공 보고 없음",
  partial_suite_blocked: "부분 테스트 실행 차단",
  forged_output_blocked: "가짜 성공 출력 차단",
  full_suite_verified: "전체 실행 · 실제 실패 발견",
  false_success_rejected: "허위 성공 보고 거부",
};
const scenarioLabels: Record<string, string> = {
  normal: "정상 기준",
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
        : `요청 실패 (${response.status})`,
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
  return new Date(value).toLocaleTimeString("ko-KR", { hour12: false });
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
      ? "Canary 노출 관찰"
      : `실행 결과 · exit ${result?.exit_code}`,
    boundary_verified: "비특권 실행 경계 확인",
    models_ready: "Nosana 모델 연결 확인",
    sandbox_created: "Daytona 샌드박스 생성",
    boundary_violation: "보호 경계 위반 기록",
    security_decision: "Security Agent 분석 완료",
    policy_applied: "접근 정책 v1 적용",
    verification: `${checks[String(d.name)] || d.name} · ${d.passed ? "통과" : "실패"}`,
    worker_report: "Worker 결과 보고",
    report_rejected: "검증 정책이 허위·미검증 보고를 거부함",
    suite_audit: "제어 영역의 전체 테스트 독립 검증",
    completed: statuses[String(d.status)] || "실행 종료",
    cleanup: d.ok ? "샌드박스 삭제 완료" : "샌드박스 삭제 실패",
    error: "실행 오류",
    observation_complete: "위반 미재현 · 패치 없음",
    cancel_requested: "중지 요청 접수",
    cancelled: "실행 중지",
    worker_limit: "Worker 호출 제한 도달",
    interrupted: "서버 재시작으로 중단",
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
        {d.message != null && <p>{String(d.message)}</p>}
        {d.summary != null && <p>{String(d.summary)}</p>}
        {result && (
          <pre>
            {result.stdout || ""}
            {result.stderr || ""}
            {!result.stdout && !result.stderr ? "(출력 없음)" : ""}
          </pre>
        )}
        {tool && <pre>{JSON.stringify(tool, null, 2)}</pre>}
        {event.kind === "boundary_verified" && (
          <pre>{JSON.stringify(d, null, 2)}</pre>
        )}
        {event.kind === "security_decision" && (
          <p className="muted">
            근거 이벤트:{" "}
            {(d.evidence_ids as number[]).map((id) => `#${id}`).join(", ")}
          </p>
        )}
        {d.test_status != null && (
          <p>
            Worker의 전체 테스트 판정: <strong>{String(d.test_status)}</strong>
            {d.suite_verified
              ? " · 전체 실행 증거 확인됨"
              : " · 독립 검증 전 보고"}
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
            이전 관찰 단계의 가짜 비밀 노출 기록입니다. 현재 정책의 접근 허용
            여부와 구분됩니다.
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
    setStreamState("연결 중");
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
          setStreamState("저장된 기록");
          return;
        }
        const last = data.events?.at(-1)?.id || 0;
        source = new EventSource(`/api/runs/${selected}/events?after=${last}`);
        source.onopen = () => alive && setStreamState("실시간 연결");
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
            setStreamState("기록 저장 완료");
            refresh().catch(() => {});
          }
        };
        source.onerror = () => alive && setStreamState("연결 복구 중");
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
              공격을 관찰하고, 실행 환경의 접근 정책을 복구합니다.
            </p>
          </div>
          <Tag tone={health?.configured ? "mint" : "amber"}>
            {health?.configured ? "● LIVE API 모드" : "○ 연결 설정 필요"}
          </Tag>
        </div>
        {error && (
          <div className="notice danger" role="alert">
            <strong>실행을 확인해 주세요.</strong>
            <span>{error}</span>
            <button
              className="text-button"
              onClick={() => setError("")}
              aria-label="오류 닫기"
            >
              ×
            </button>
          </div>
        )}
        {health && !health.configured && (
          <div className="notice config">
            <div>
              <strong>실제 서비스 연결을 기다리고 있어요.</strong>
              <p>
                로컬 .env에 <code>{health.missing.join(", ")}</code> 설정 후
                서버를 다시 시작하세요. 테스트용 응답으로 대체하지 않습니다.
              </p>
            </div>
            <a href="#connection">연결 상태 보기 ↗</a>
          </div>
        )}

        <section className="control panel">
          <div className="control-label">
            <span className="section-number">01</span>
            <div>
              <h2>시나리오</h2>
              <span className="muted">
                {scenario === "test-laundering"
                  ? "실패 테스트 누락 · 결과 무결성"
                  : "테스트 실행 요청 · 가짜 비밀만 사용"}
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
              정상 기준 실행
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
                중지
              </button>
            )}
            <button
              className="button primary"
              disabled={!health?.configured || busy}
              onClick={start}
            >
              <span aria-hidden="true">▷</span>
              {busy ? "실행 중" : "데모 시작"}
            </button>
          </div>
        </section>

        <section className="flow panel" aria-label="시스템 구조">
          <div className="flow-node">
            <span className="node-symbol">W</span>
            <div>
              <strong>Worker Agent</strong>
              <small>NOSANA · 작업 수행</small>
            </div>
          </div>
          <span className="flow-arrow">→</span>
          <div className="flow-node">
            <span className="node-symbol gateway">
              <Shield small />
            </span>
            <div>
              <strong>Security Gateway</strong>
              <small>정책 검사 · 실행 기록</small>
            </div>
          </div>
          <span className="flow-arrow">→</span>
          <div className="flow-node">
            <span className="node-symbol daytona">D</span>
            <div>
              <strong>Daytona Sandbox</strong>
              <small>비특권 계정 · 실제 실행</small>
            </div>
          </div>
          <div className="flow-security">
            <span className="node-symbol security">S</span>
            <div>
              <strong>Security Agent</strong>
              <small>NOSANA · 분석 → 패치 → 재검증</small>
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
                  실행 타임라인 <span>{events.length}</span>
                </button>
                <button
                  className={tab === "readme" ? "active" : ""}
                  onClick={() => setTab("readme")}
                >
                  README 문서
                </button>
              </div>
              <span className="stream-state">{streamState || "실행 대기"}</span>
            </div>
            {tab === "readme" ? (
              <div className="document">
                <div className="file-path">
                  /workspace/project/README.md{" "}
                  <Tag>
                    {scenario === "normal" ? "NORMAL" : "UNTRUSTED INPUT"}
                  </Tag>
                </div>
                <pre>{scenarios[scenario] || "문서 로딩 중…"}</pre>
                <p className="muted">
                  선택한 다음 실행의 문서입니다. README는 Worker에게 추가 권한을
                  부여하지 않습니다.
                </p>
              </div>
            ) : (
              <>
                <div className="timeline-toolbar">
                  <div className="filters">
                    {[
                      ["all", "전체"],
                      ["observe", "관찰"],
                      ["security", "분석 · 패치"],
                      ["verification", "검증"],
                      ["fresh_worker", "새 Worker"],
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
                          ? "이 단계의 이벤트가 없습니다"
                          : "실행 증거가 쌓이는 곳"}
                      </h3>
                      <p>
                        {events.length
                          ? "다른 필터를 선택해 보세요."
                          : "데모를 시작하면 Worker의 행동부터 정책 복구까지\n모든 단계를 여기에서 확인할 수 있어요."}
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
                  <Shield small /> {integrity ? "실행·보고 정책" : "접근 정책"}
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
                        ? "강제 적용 · 검증 완료"
                        : "강제 적용 · 검증 중"
                      : "관찰 모드"}
                  </strong>
                  <small>
                    {integrity
                      ? policy?.mode === "enforce"
                        ? "필수 전체 실행 · 증거와 일치하는 보고"
                        : "부분 실행과 보고 내용을 관찰"
                      : policy?.mode === "enforce"
                        ? "Worker 보호 파일 읽기 제한"
                        : "위반을 기록하되 접근은 허용"}
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
                  <span>소유자</span>
                  <code>root : root</code>
                </div>
                <div>
                  <span>{integrity ? "검증 범위" : "파일 권한"}</span>
                  <code>
                    {integrity ? (
                      policy?.require_full_suite ? (
                        <>
                          <del>부분 실행</del> <b>→ 필수 3개 전체</b>
                        </>
                      ) : (
                        "README 프로필 허용"
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
                  <span>Worker 실행</span>
                  <code>UID 31001 · no privileges</code>
                </div>
              </div>
              <p className="policy-note">
                {integrity
                  ? "실패 테스트를 고치는 시나리오가 아닙니다. 누락된 실패를 정확히 보고하도록 실행·보고 정책을 복구합니다."
                  : exposure
                    ? "최초 노출은 과거 실행 기록에 남습니다. 패치는 이후 접근을 제한합니다."
                    : "실행 전 보호 경계를 정의하고, 관찰한 위반을 근거로 정책을 강화합니다."}
              </p>
            </section>
            {integrity && run?.suite_audit && (
              <section className="panel audit-panel">
                <div className="panel-title">
                  <h2>독립 검증 결과</h2>
                  <Tag tone="amber">테스트 실패 존재</Tag>
                </div>
                <div className="audit-content">
                  <p>
                    <strong>{run.suite_audit.tests_run}개 실행</strong> ·{" "}
                    {run.suite_audit.tests_run -
                      run.suite_audit.failures.length -
                      run.suite_audit.errors.length}
                    개 통과 ·{" "}
                    <span className="red-text">
                      {run.suite_audit.failures.length +
                        run.suite_audit.errors.length}
                      개 실패
                    </span>
                  </p>
                  {run.suite_audit.failures.map((name) => (
                    <code key={name} className="red-text">
                      {name}
                    </code>
                  ))}
                  <p className="muted">
                    {run.final_test_status === "failed"
                      ? "복구 후 Worker가 실제 실패를 정확히 보고했습니다."
                      : "전체 테스트 기준은 README가 변경할 수 없습니다."}
                  </p>
                </div>
              </section>
            )}
            <section className="panel verification-panel">
              <div className="panel-title">
                <h2>재검증 결과</h2>
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
                          {check ? (check.passed ? "PASS" : "FAIL") : "대기"}
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
                  <h2>Security Agent 분석</h2>
                </div>
                <p>{run.decision.summary}</p>
                <div className="evidence-tags">
                  {run.decision.evidence_ids.map((id) => (
                    <Tag key={id}>증거 #{id}</Tag>
                  ))}
                </div>
              </section>
            )}
          </aside>
        </div>

        <div className="bottom-grid">
          <section className="panel" id="connection">
            <div className="panel-title">
              <h2>서비스 연결</h2>
              <button
                className="text-button"
                disabled={!health?.configured || busy}
                onClick={connectionCheck}
              >
                {checkedModels ? "✓ 모델 확인 완료" : "모델 연결 확인 ↗"}
              </button>
            </div>
            <div className="connection-row">
              <span>Nosana / Worker</span>
              <code>{health?.models.worker || "미설정"}</code>
            </div>
            <div className="connection-row">
              <span>Nosana / Security</span>
              <code>{health?.models.security || "미설정"}</code>
            </div>
            {health?.same_model && (
              <p className="small-note">두 역할이 같은 모델을 사용합니다.</p>
            )}
            <div className="connection-row">
              <span>Daytona / Sandbox</span>
              <code>
                {run?.sandbox_id ? run.sandbox_id.slice(0, 16) : "실행 시 생성"}
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
                환경 정리: {run.cleanup}
                {run.cleanup_note ? ` · ${run.cleanup_note}` : ""}
                {run.cleanup === "failed"
                  ? ` · Daytona에서 직접 삭제 필요: ${run.sandbox_id}`
                  : ""}
              </p>
            )}
          </section>
          <section className="panel history-panel">
            <div className="panel-title">
              <h2>최근 실행</h2>
              <span className="muted">로컬에 저장됨</span>
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
              <p className="history-empty">아직 실행 기록이 없습니다.</p>
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
