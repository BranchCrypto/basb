# Basb

**启发式 Agent 行为审计沙箱**

给用户一张可信的账本：沙盒里的 Agent 读了什么、写了什么、连了哪里、跑了什么命令。

> 产品定位：**透明监控型 Agent Sandbox**  
> Agent 在接近原生的环境中正常运行；Basb 旁路观察、启发式标注风险、落盘事件并生成审计报告。默认只观察，不阻断、不改写行为。

- 产品说明：[docs/agent_sandbox_transparent_monitoring.md](docs/agent_sandbox_transparent_monitoring.md)
- 开发规格：[docs/agent_sandbox_codex_spec_observe_first.md](docs/agent_sandbox_codex_spec_observe_first.md)

---

## 原则

| 原则 | 含义 |
|------|------|
| 默认 `observe` | 只观察、记录、关联、报告；`decision` 恒为 `ALLOW` |
| Protect 可选 | `mode` 已预留，Policy / Controller 在 Phase 4 再接 |
| Probe 旁路 | Windows Job Object + 轮询 / 差分，不进入 Agent 同步执行路径 |
| 风险 ≠ 阻断 | `risk_level` 是分析输出，Observe 模式下不触发拦截 |

---

## 能审计什么

Basb 用 **Job Object 隔离 + 启发式探针**（轮询与差分，非 ETW 全量）记录 Agent 行为：

| 维度 | 做法 |
|------|------|
| 进程 / Shell | Job 内 PID 轮询；识别 `cmd` / `powershell` / `wsl` 等 |
| 提权 | 提升令牌、`runas` / `sudo` 等 → `HIGH` |
| 文件 | 工作区前后 diff：创建 / 写入 / 删除；可选 SHA256 |
| 网络 | TCP/UDP 表轮询；`:53` → DNS；80/443/8080/8443 → HTTP 启发式；`:22` / `ssh` → SSH |
| 敏感路径 | `id_rsa`、`.env`、Cookies、Windows 凭据等规则命中 |
| 下载 / 外传 | `curl` / `wget` / `certutil`、归档工具与新文件启发式标注 |
| 模块 | 基线后新增的非 System32 DLL |
| 持久化（完整模式） | 启动项、用户、防火墙、计划任务、服务、Defender 快照差分 |
| 报告 | 进程树、计数、敏感时间线、`report.json`、审计 zip |

隔离边界是 **Windows Job Object**（`KillOnJobClose`），不是完整 VM / 容器。

---

## 事件模型（schema 1.0）

每条事件对齐规格 §9：

```text
schema_version, event_id, timestamp
sandbox_id, session_id, agent_id
actor { pid, ppid, user, executable, command_line }
action { category, type }   // e.g. process.create / file.write / network.connect
target / network
decision { mode: observe, result: ALLOW }
correlation { trace_id }
risk_level (分析输出，≠ 阻断)
```

会话落盘：

```text
data/sessions/<session-id>/
  meta.json
  events.jsonl
```

导出 zip 含：`meta.json`、`events.jsonl`、`report.json`、`summary.json`。

---

## 能力现状

| 能力 | 状态 |
|------|------|
| Sandbox / Agent 生命周期事件 | ✓ |
| Process / Shell / File / Network 遥测 | ✓（轮询 + 工作区 / 系统 diff） |
| DNS / HTTP / SSH 启发式 | ✓ |
| 敏感路径 / 凭据风险标记 | ✓（Observe 下仍 ALLOW） |
| 进程树 + Dashboard 计数 | ✓ |
| 任务报告与审计包导出 | ✓ |
| CLI + Wails 桌面 UI | ✓ |
| Protect / Policy / Controller | ✗（后置） |
| 真 VM/容器隔离与干净 Snapshot | ✗（当前为 Job Object） |

---

## 环境要求

- **Windows**（MVP 与采集器以 Windows 为准）
- Go（见 `go.mod`）
- 桌面 UI：需 [Wails CLI](https://wails.io) 与 Node/npm（`frontend/`）

---

## 构建

```bash
# CLI
go build -o basb.exe ./cmd/basb

# 桌面 GUI（产出 Basb.exe）
wails build

# 测试
go test ./...
```

---

## CLI 用法

持久参数：`--data`（默认 `data`）为会话根目录。

```bash
# 完整审计（含防火墙 / 任务 / 服务 / Defender 快照）
basb run --agent ./my-agent.exe --workdir ./sandbox-data --session my-run-1

# 轻量模式（跳过慢速系统快照）
basb run --agent ./my-agent.exe --workdir ./sandbox-data --light

# 传参给 Agent
basb run --agent ./my-agent.exe --workdir ./sandbox-data --arg "--foo" --arg "bar"

basb list
basb show --session my-run-1
basb show --session my-run-1 --type network,credential,file
basb export --session my-run-1 --out ./my-run-1-audit.zip
```

| 命令 | 作用 |
|------|------|
| `run` | 在 Job Object 中启动 Agent 并记录事件 |
| `list` | 列出已有会话 |
| `show` | 查看时间线 / 摘要（可按类型过滤） |
| `export` | 导出审计 zip |

---

## 桌面 UI

`wails build` / `wails dev` 启动 **Basb** 窗口：

- 选择 Agent 可执行文件与工作目录，开始监控（Observe，UI 侧为 Light）
- 会话列表、时间线过滤（file / network / shell / process / risk）
- 进程树、计数看板、导出审计包
- 运行中可实时刷新事件

---

## 仓库结构

```text
cmd/basb/              CLI（cobra）
main.go / app.go        Wails 桌面入口与绑定
internal/
  api/                  运行 / 查询 / 导出 / 报告编排
  analysis/             计数、进程树、report.json
  session/              会话生命周期（created → … → finished）
  event/                统一事件模型 schema 1.0
  store/                JSONL 追加落盘
  summary/              摘要与 zip 导出
  sandbox/windows/      Job Object + 进程元数据 enrichment
  collect/
    process/            进程 / Shell / 提权启发式
    fs/                 工作区前后 diff
    net/                TCP/UDP + DNS/HTTP/SSH 启发式
    module/             新增非系统 DLL
    marker/             敏感 / 凭据路径规则
    snapshot/           启动项 / 用户 / 防火墙 / 任务 / 服务 / Defender
frontend/               Vite + 原生 JS（Dashboard / Timeline / Process Tree）
docs/                   产品说明与 Observe-first 规格
testdata/               MVP 用 fake-agent
data/sessions/          运行时会话目录（本地）
```

Go 模块名与产品名均为 **Basb**。

---

## 架构一览

```text
CLI (basb) / Wails UI (Basb)
        │
        ▼
   api.Run
        ├─ session.Create  → meta.json + events.jsonl
        ├─ Job Object Start (agent)
        ├─ collect watchers（process / net / module）运行中轮询
        ├─ 退出后 fs.Diff + snapshot.Diff（完整模式）
        └─ analysis.Build → summary / report / export
```

---

## 许可

暂未指定开源许可证。
