import React, { useEffect, useState } from "react";
import {
  AuditEventRow,
  DoctorReport,
  fetchAuditEvents,
  fetchDualEnvStatus,
  fetchReadonlySessions,
  runIsolatedSelfTest,
  SessionSummary,
  testRuleInSandbox,
} from "./api/client";

type TabKey = "overview" | "agents" | "policies" | "events" | "diagnostics" | "settings";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [statusReport, setStatusReport] = useState<DoctorReport | null>(null);
  const [events, setEvents] = useState<AuditEventRow[]>([]);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [sandboxTool, setSandboxTool] = useState("Bash");
  const [sandboxCwd, setSandboxCwd] = useState("/home/ai-li/workspace");
  const [sandboxInput, setSandboxInput] = useState("rm -fr ~/Documents");
  const [sandboxResult, setSandboxResult] = useState<string>("");

  useEffect(() => {
    void refreshAll();
  }, []);

  async function refreshAll() {
    try {
      const [st, evs, sess] = await Promise.all([
        fetchDualEnvStatus("all"),
        fetchAuditEvents("all", 50),
        fetchReadonlySessions("all", 20),
      ]);
      setStatusReport(st);
      setEvents(evs);
      setSessions(sess);
    } catch {
      // 本地回路未启动或 WSL2 离线时保持诚实未知状态展示
    }
  }

  async function handleSelfTest() {
    await runIsolatedSelfTest("all");
    await refreshAll();
  }

  async function handleSandboxRun() {
    const res = await testRuleInSandbox(sandboxTool, sandboxInput, sandboxCwd);
    setSandboxResult(
      `${res.decision.enforcement.toUpperCase()} | 规则: ${res.decision.matched_rule_ids.join(",") || "无"} | 耗时: ${res.duration_us}us | ${res.decision.display_message}`
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <header className="px-6 py-3 border-b flex items-center justify-between">
        <div className="font-bold text-base">
          AI卫士（AI Guard）v{statusReport?.ai_guard_version ?? "0.1.0"} · Windows 宿主机主控端
        </div>
        <button onClick={handleSelfTest} className="px-3 py-1.5 rounded bg-emerald-600 text-white text-xs">
          一键双环境隔离自检 (self-test)
        </button>
      </header>
      <div className="flex flex-1">
        <nav className="w-60 border-r p-3 space-y-1">
          {([
            ["overview", "1. 安全概览"],
            ["agents", "2. Agent 与环境管理"],
            ["policies", "3. 安全策略与沙盒"],
            ["events", "4. 风险事件审计"],
            ["diagnostics", "5. 安装恢复与会话"],
            ["settings", "6. 设置与隐私边界"],
          ] as [TabKey, string][]).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`w-full text-left px-3 py-2 rounded text-sm ${
                activeTab === key ? "font-semibold bg-emerald-600 text-white" : ""
              }`}
            >
              {label}
            </button>
          ))}
        </nav>
        <main className="flex-1 p-6">
          {activeTab === "overview" && (
            <div>
              <h2 className="text-lg font-bold mb-4">宿主机与 WSL2 双环境四态防护概览</h2>
              <div className="grid grid-cols-2 gap-4">
                {(statusReport?.targets ?? []).map((t) => (
                  <div key={t.target_id} className="p-4 border rounded-xl">
                    <div className="font-semibold">{t.target_id}</div>
                    <div className="text-xs mt-1">路径: {t.codex_home}</div>
                    <div className="text-xs mt-1">四态防护状态: {t.protection_state}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {activeTab === "policies" && (
            <div className="space-y-4">
              <h2 className="text-lg font-bold">跨平台规则沙盒测试器</h2>
              <div className="flex gap-2">
                <input value={sandboxCwd} onChange={(e) => setSandboxCwd(e.target.value)} className="border px-2 py-1 text-xs" />
                <input value={sandboxTool} onChange={(e) => setSandboxTool(e.target.value)} className="border px-2 py-1 text-xs" />
                <input value={sandboxInput} onChange={(e) => setSandboxInput(e.target.value)} className="border px-2 py-1 text-xs flex-1" />
                <button onClick={handleSandboxRun} className="px-3 py-1 bg-emerald-600 text-white text-xs rounded">
                  测试裁决
                </button>
              </div>
              {sandboxResult && <div className="p-3 border rounded text-xs">{sandboxResult}</div>}
            </div>
          )}
          {activeTab === "events" && (
            <div>
              <h2 className="text-lg font-bold mb-3">二次脱敏风险事件时间线 ({events.length})</h2>
              {events.map((ev) => (
                <div key={ev.event_id} className="p-3 border rounded mb-2 text-xs">
                  [{ev.target_id}] {ev.enforcement.toUpperCase()} · {ev.reason_code} · {ev.redacted_summary}
                </div>
              ))}
            </div>
          )}
          {activeTab === "diagnostics" && (
            <div>
              <h2 className="text-lg font-bold mb-3">双环境 Codex 会话只读索引 ({sessions.length})</h2>
              {sessions.map((s) => (
                <div key={`${s.target_id}-${s.session_id}`} className="p-3 border rounded mb-2 text-xs">
                  [{s.target_id}] {s.session_id} · {s.title} · {s.cwd}
                </div>
              ))}
            </div>
          )}
          {(activeTab === "agents" || activeTab === "settings") && (
            <div className="text-xs">
              个人版 V0.1 严格通过本地回路 <code>127.0.0.1:17900</code> 访问业务能力，源会话目录 100% 只读。
            </div>
          )}
        </main>
      </div>
    </div>
  );
};
