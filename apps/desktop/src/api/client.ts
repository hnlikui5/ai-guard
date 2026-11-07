/**
 * AI卫士（AI Guard）桌面端标准 API 客户端
 *
 * 严格遵守 AGENTS.md §2.1 分层隔离红线：
 * - apps/desktop 仅负责界面展示与用户交互，必须通过 apps/local-service 提供的标准本地回路接口访问业务能力。
 * - 严禁 UI 层直接读写 Agent 原始内部文件（如 ~/.codex）或直接访问底层 SQLite 数据库文件。
 */

export const LOCAL_SERVICE_BASE_URL = "http://127.0.0.1:17900";

export type ProtectionState =
  | "protected_verified"
  | "partially_protected"
  | "unprotected"
  | "unknown";

export interface SelfTestRunRecord {
  run_id: string;
  target_id: string;
  host_kind: string;
  passed: boolean;
  allow_verified: boolean;
  deny_verified: boolean;
  policy_revision: string;
  detail: string;
  executed_at_ms: number;
}

export interface TargetStatusReport {
  target_id: string;
  codex_home: string;
  codex_home_exists: boolean;
  config_toml_exists: boolean;
  hook_configured_in_toml: boolean;
  hook_trusted_in_toml: boolean;
  protection_state: ProtectionState;
  real_interception_verified: boolean;
  last_self_test: SelfTestRunRecord | null;
  limitations: string[];
}

export interface DoctorReport {
  schema_version: number;
  ai_guard_version: string;
  overall_status: string;
  targets: TargetStatusReport[];
}

export interface AuditEventRow {
  event_id: string;
  created_at_ms: number;
  target_id: string;
  host_kind: string;
  tool_name: string;
  action_kind: string;
  cwd: string;
  redacted_summary: string;
  enforcement: "allow" | "deny" | "observe" | "unsupported";
  matched_rule_ids: string[];
  reason_code: string;
  display_message: string;
  policy_revision: string;
}

export interface SessionSummary {
  session_id: string;
  target_id: string;
  title: string;
  cwd: string;
  updated_at: string;
  model: string | null;
  rollout_file_exists: boolean;
}

export interface RuleTestResponse {
  ok: boolean;
  policy_revision: string;
  duration_us: number;
  decision: {
    target_id: string;
    enforcement: "allow" | "deny" | "observe" | "unsupported";
    matched_rule_ids: string[];
    reason_code: string;
    display_message: string;
  };
}

export async function fetchDualEnvStatus(target = "all"): Promise<DoctorReport> {
  const res = await fetch(`${LOCAL_SERVICE_BASE_URL}/api/status?target=${encodeURIComponent(target)}`);
  if (!res.ok) {
    throw new Error(`获取双环境状态失败: HTTP ${res.status}`);
  }
  return res.json();
}

export async function runIsolatedSelfTest(target = "all"): Promise<{
  overall_passed: boolean;
  runs: SelfTestRunRecord[];
}> {
  const res = await fetch(`${LOCAL_SERVICE_BASE_URL}/api/self-test`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  if (!res.ok) {
    throw new Error(`执行隔离自检失败: HTTP ${res.status}`);
  }
  return res.json();
}

export async function testRuleInSandbox(
  tool: string,
  input: string,
  cwd: string
): Promise<RuleTestResponse> {
  const res = await fetch(`${LOCAL_SERVICE_BASE_URL}/api/rule/test`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool, input, cwd }),
  });
  if (!res.ok) {
    throw new Error(`规则沙盒测试失败: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchAuditEvents(target = "all", limit = 50): Promise<AuditEventRow[]> {
  const res = await fetch(
    `${LOCAL_SERVICE_BASE_URL}/api/events?target=${encodeURIComponent(target)}&limit=${limit}`
  );
  if (!res.ok) {
    throw new Error(`查询风险事件失败: HTTP ${res.status}`);
  }
  const data = await res.json();
  return data.events ?? [];
}

export async function fetchReadonlySessions(target = "all", limit = 50): Promise<SessionSummary[]> {
  const res = await fetch(
    `${LOCAL_SERVICE_BASE_URL}/api/sessions?target=${encodeURIComponent(target)}&limit=${limit}`
  );
  if (!res.ok) {
    throw new Error(`查询只读会话列表失败: HTTP ${res.status}`);
  }
  const data = await res.json();
  return data.sessions ?? [];
}
