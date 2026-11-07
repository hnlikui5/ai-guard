#!/usr/bin/env python3
"""
AI卫士（AI Guard）Phase 1 (M2) 真实 Codex 执行前拦截端到端验证脚本。

安全约束（AGENTS.md 第 5.4 / 5.5 条）：
- 全程在隔离临时目录（/tmp/ai-guard-m2-e2e）运行真实 `codex-cli 0.160.1` 与编译产出的 Rust 二进制 `ai-guard`。
- 严禁修改用户真实 `/home/ai-li/.codex` 与 `/mnt/c/Users/kui.li/.codex`。
- 同时验证：
  1. E2E-DENY-SHELL（带 `trusted_hash`，不传 `--dangerously-bypass-hook-trust`，阻断含 `AI_GUARD_BLOCK_ME` 的命令，验证 `sentinel_blocked.txt` 未生成）
  2. E2E-ALLOW-SHELL（带 `trusted_hash`，正常放行 `pwd` / `echo` 命令，验证 `sentinel_allowed.txt` 正常生成）
  3. E2E-DENY-PATCH（带 `trusted_hash`，阻断含 `AI_GUARD_BLOCK_ME` 的 `apply_patch` 文件修改，验证 `patched_blocked.txt` 未生成）
"""

import http.server
import json
import os
import shutil
import subprocess
import sys
import threading

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
AI_GUARD_BIN = os.path.join(REPO_ROOT, "target/debug/ai-guard")
CODEX_BIN = "/home/ai-li/.local/npm/bin/codex"
E2E_ROOT = "/tmp/ai-guard-m2-e2e"
PORT = 18995

current_scenario = {}
recorded_tool_outputs = []


class MockOpenAIResponsesHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        global recorded_tool_outputs
        length = int(self.headers.get("Content-Length", 0))
        req_json = json.loads(self.rfile.read(length).decode("utf-8"))
        input_items = req_json.get("input", [])
        tool_outputs = [
            i
            for i in input_items
            if isinstance(i, dict)
            and i.get("type") in ("function_call_output", "custom_tool_call_output")
        ]
        if not tool_outputs:
            item_obj = current_scenario["item"]
            events = [
                {
                    "type": "response.created",
                    "response": {"id": "resp_1", "status": "in_progress", "output": []},
                },
                {
                    "type": "response.output_item.added",
                    "output_index": 0,
                    "item": item_obj,
                },
                {
                    "type": "response.output_item.done",
                    "output_index": 0,
                    "item": item_obj,
                },
                {
                    "type": "response.completed",
                    "response": {
                        "id": "resp_1",
                        "status": "completed",
                        "output": [item_obj],
                        "usage": {
                            "input_tokens": 10,
                            "output_tokens": 10,
                            "total_tokens": 20,
                        },
                    },
                },
            ]
        else:
            recorded_tool_outputs = tool_outputs
            events = [
                {
                    "type": "response.created",
                    "response": {"id": "resp_2", "status": "in_progress", "output": []},
                },
                {
                    "type": "response.output_item.done",
                    "output_index": 0,
                    "item": {
                        "type": "message",
                        "id": "msg_1",
                        "role": "assistant",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": "E2E turn complete."}],
                    },
                },
                {
                    "type": "response.completed",
                    "response": {
                        "id": "resp_2",
                        "status": "completed",
                        "output": [
                            {
                                "type": "message",
                                "id": "msg_1",
                                "role": "assistant",
                                "status": "completed",
                                "content": [
                                    {"type": "output_text", "text": "E2E turn complete."}
                                ],
                            }
                        ],
                        "usage": {
                            "input_tokens": 20,
                            "output_tokens": 5,
                            "total_tokens": 25,
                        },
                    },
                },
            ]

        payload = "".join(
            f"event: {ev['type']}\ndata: {json.dumps(ev)}\n\n" for ev in events
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    def log_message(self, format, *args):
        pass


def configure_trusted_codex_home(codex_home: str, workspace: str) -> dict:
    """
    在隔离 CODEX_HOME 写入指向真实 Rust `ai-guard` 二进制的 PreToolUse Hook 配置，
    并通过 `codex app-server --listen stdio://` 的 `hooks/list` 获取精确 `currentHash`，
    写入 `[hooks.state."<key>"].trusted_hash`，验证 `trustStatus == "trusted"`。
    """
    os.makedirs(codex_home, exist_ok=True)
    os.makedirs(workspace, exist_ok=True)

    config_path = os.path.join(codex_home, "config.toml")
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(
            f"""model_provider = "mock"
model = "gpt-5.6-sol"

[model_providers.mock]
name = "MockOpenAI"
base_url = "http://127.0.0.1:{PORT}/v1"
wire_api = "responses"

[features]
hooks = true
enable_request_compression = false
code_mode_only = false

[[hooks.PreToolUse]]
matcher = "*"
hooks = [
  {{ type = "command", command = "{AI_GUARD_BIN} hook codex pre-tool-use", timeout = 5, statusMessage = "AI卫士安全检查中..." }}
]
"""
        )

    env = os.environ.copy()
    env["CODEX_HOME"] = codex_home

    def query_hook_info() -> dict:
        proc = subprocess.Popen(
            [CODEX_BIN, "app-server", "--listen", "stdio://"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        for req in [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "ai-guard-e2e", "version": "0.1.0"},
                    "capabilities": {"experimentalApi": True},
                },
            },
            {"jsonrpc": "2.0", "method": "initialized", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "hooks/list",
                "params": {"cwds": [workspace]},
            },
        ]:
            proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()

        info = None
        for _ in range(12):
            line = proc.stdout.readline()
            if not line:
                break
            msg = json.loads(line)
            if msg.get("id") == 2:
                info = msg["result"]["data"][0]["hooks"][0]
                break
        proc.terminate()
        proc.wait(timeout=5)
        assert info is not None, "Failed to query hooks/list from codex app-server"
        return info

    initial_info = query_hook_info()
    with open(config_path, "a", encoding="utf-8") as f:
        f.write(
            f'\n[hooks.state."{initial_info["key"]}"]\n'
            f"enabled = true\n"
            f'trusted_hash = "{initial_info["currentHash"]}"\n'
        )

    verified_info = query_hook_info()
    assert (
        verified_info["trustStatus"] == "trusted"
    ), f"Expected trustStatus='trusted', got {verified_info['trustStatus']}"
    return verified_info


def run_codex_turn(codex_home: str, workspace: str, prompt: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["CODEX_HOME"] = codex_home
    env["OPENAI_API_KEY"] = "sk-mock-local-e2e-key"
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"

    # 注意：此处不传 --dangerously-bypass-hook-trust，完全依靠真实 [hooks.state] trusted_hash 生效！
    return subprocess.run(
        [
            CODEX_BIN,
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            "-C",
            workspace,
            "--json",
            prompt,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=25,
    )


def main() -> int:
    if not os.path.isfile(AI_GUARD_BIN):
        print(f"ERROR: Rust binary not found at {AI_GUARD_BIN}", file=sys.stderr)
        return 1

    shutil.rmtree(E2E_ROOT, ignore_errors=True)
    codex_home = os.path.join(E2E_ROOT, "codex_home")
    workspace = os.path.join(E2E_ROOT, "workspace")

    server = http.server.HTTPServer(("127.0.0.1", PORT), MockOpenAIResponsesHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    hook_meta = configure_trusted_codex_home(codex_home, workspace)
    print(f"[PASS] Hook configured and trusted: key={hook_meta['key']} trustStatus={hook_meta['trustStatus']}")

    # 1. E2E-DENY-SHELL: Attempt to create sentinel_blocked.txt with AI_GUARD_BLOCK_ME
    global current_scenario, recorded_tool_outputs
    recorded_tool_outputs = []
    sentinel_blocked = os.path.join(workspace, "sentinel_blocked.txt")
    current_scenario = {
        "item": {
            "type": "function_call",
            "id": "fc_deny_1",
            "call_id": "call_e2e_deny_001",
            "name": "exec_command",
            "arguments": json.dumps(
                {"cmd": f"echo AI_GUARD_BLOCK_ME && touch {sentinel_blocked}"}
            ),
            "status": "completed",
        }
    }
    proc_deny = run_codex_turn(codex_home, workspace, "Run blocked command")
    assert not os.path.exists(sentinel_blocked), "FATAL: sentinel_blocked.txt MUST NOT exist!"
    deny_output_str = json.dumps(recorded_tool_outputs, ensure_ascii=False)
    assert "Command blocked by PreToolUse hook" in deny_output_str, f"Unexpected output: {deny_output_str}"
    assert "TEST-DENY-001" in deny_output_str, f"Expected TEST-DENY-001 in output: {deny_output_str}"
    print(f"[PASS] E2E-DENY-SHELL: sentinel_blocked.txt exists={os.path.exists(sentinel_blocked)} | output={deny_output_str}")

    # 2. E2E-ALLOW-SHELL: Normal command creating sentinel_allowed.txt
    recorded_tool_outputs = []
    sentinel_allowed = os.path.join(workspace, "sentinel_allowed.txt")
    current_scenario = {
        "item": {
            "type": "function_call",
            "id": "fc_allow_2",
            "call_id": "call_e2e_allow_002",
            "name": "exec_command",
            "arguments": json.dumps(
                {"cmd": f"pwd && echo ALLOW_VERIFIED > {sentinel_allowed}"}
            ),
            "status": "completed",
        }
    }
    proc_allow = run_codex_turn(codex_home, workspace, "Run allowed command")
    assert os.path.exists(sentinel_allowed), "FATAL: sentinel_allowed.txt MUST exist after Allow!"
    allow_output_str = json.dumps(recorded_tool_outputs, ensure_ascii=False)
    print(f"[PASS] E2E-ALLOW-SHELL: sentinel_allowed.txt exists={os.path.exists(sentinel_allowed)} | content={open(sentinel_allowed).read().strip()}")

    # 3. E2E-DENY-PATCH: apply_patch containing AI_GUARD_BLOCK_ME
    recorded_tool_outputs = []
    patched_blocked = os.path.join(workspace, "patched_blocked.txt")
    current_scenario = {
        "item": {
            "type": "custom_tool_call",
            "id": "ctc_patch_3",
            "call_id": "call_e2e_patch_003",
            "name": "apply_patch",
            "input": "*** Begin Patch\n*** Add File: patched_blocked.txt\n+AI_GUARD_BLOCK_ME\n*** End Patch\n",
            "status": "completed",
        }
    }
    proc_patch = run_codex_turn(codex_home, workspace, "Run blocked apply_patch")
    assert not os.path.exists(patched_blocked), "FATAL: patched_blocked.txt MUST NOT exist!"
    patch_output_str = json.dumps(recorded_tool_outputs, ensure_ascii=False)
    assert "Command blocked by PreToolUse hook" in patch_output_str
    print(f"[PASS] E2E-DENY-PATCH: patched_blocked.txt exists={os.path.exists(patched_blocked)} | output={patch_output_str}")

    shutil.rmtree(E2E_ROOT, ignore_errors=True)
    print("ALL M2 REAL CODEX E2E TESTS PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
