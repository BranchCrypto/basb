# Basb

[设计文档](docs/agent_sandbox_transparent_monitoring.md) · [开发规格](docs/agent_sandbox_codex_spec_observe_first.md)

---

## What is Basb

Basb是一个启发式行为判断沙盒，用来监控Agent运行

---

## 核心亮点

- **观察优先**：不改写命令、不注入、不拦截正常行为，保障Agent正常运行。
- **原生沙盒**：基于 Windows Job Object，Agent 尽量按原生方式运行。
- **旁路探针**：探针采集进程树、网络、文件变更与敏感事件。
- **桌面控制台**：Wails 桌面端一键启动监测、实时查看会话、导出审计包。

---

## 极速上手

### 桌面端（推荐）

```bash
# 安装依赖并开发运行（需 Go、Node、Wails CLI）
cd frontend && npm install && cd ..
wails dev

# 或打包 Windows 可执行文件
wails build
```

### 命令行

```bash
# 编译 CLI
go build -o basb.exe ./cmd/basb

# 在沙盒中跑一次 Agent 并记录事件
./basb.exe run --agent C:\path\to\agent.exe --workdir C:\path\to\workdir

# 查看会话时间线 / 导出审计包
./basb.exe list
./basb.exe show --session <session_id>
./basb.exe export --session <session_id>
```

---

## 项目结构

```text
basb/
├── cmd/basb/          # CLI 入口
├── frontend/          # Wails 前端（会话 / 报告 / 导出）
├── internal/
│   ├── api/           # 运行、查询、导出 API
│   ├── collect/       # 进程 / 网络 / 文件 / 快照探针
│   ├── sandbox/       # Windows Job Object 沙盒
│   ├── session/       # 会话与事件落盘
│   └── analysis/      # 报告与进程树
└── docs/              # 产品与开发规格
```

