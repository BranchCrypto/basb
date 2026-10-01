# 桌面防火墙 UI 浅色主题设计规范

## 1. 设计目标

本方案用于桌面防火墙 / 网络安全管理软件的浅色主题 UI。

核心设计目标：

- 专业、可靠、克制
- 高信息密度下保持清晰
- 用颜色明确表达防火墙安全状态
- 降低大面积高饱和色造成的视觉疲劳
- 适合桌面端管理面板、规则管理、流量监控、连接管理、告警中心和设置页面
- 设计 Token 可直接供 Codex 用于前端实现

---

## 2. 整体视觉方向

### 关键词

`Professional` · `Security` · `Clean` · `Technical` · `Lightweight`

### 核心原则

1. 页面大面积使用冷灰白，避免纯白造成刺眼效果。
2. 内容区域使用白色 Surface，与页面背景形成轻微层级。
3. 蓝色作为品牌色和主要交互色。
4. 绿色仅用于允许、正常、已保护等正向状态。
5. 红色仅用于阻止、危险、严重告警等安全状态。
6. 黄色 / 琥珀色用于警告、风险提示。
7. 紫色用于网络、流量、协议等辅助信息。
8. 边框和阴影保持低对比度，避免传统后台 UI 的厚重感。
9. 不使用大面积渐变。
10. 不依赖颜色单独表达状态，应结合图标、文字和标签。

---

## 3. Color Tokens

### 3.1 Brand / Primary

| Token | Hex | 用途 |
|---|---|---|
| `--color-primary` | `#2563EB` | 主按钮、链接、选中状态 |
| `--color-primary-hover` | `#1D4ED8` | Hover |
| `--color-primary-active` | `#1E40AF` | Active / Pressed |
| `--color-primary-light` | `#EFF6FF` | 浅色背景、选中行 |

### 3.2 Background

| Token | Hex | 用途 |
|---|---|---|
| `--color-bg` | `#F5F7FA` | 应用主背景 |
| `--color-bg-secondary` | `#FFFFFF` | 内容背景 |
| `--color-bg-tertiary` | `#F8FAFC` | 次级背景 |
| `--color-bg-sidebar` | `#F1F5F9` | Sidebar |

### 3.3 Surface

| Token | Hex | 用途 |
|---|---|---|
| `--color-surface` | `#FFFFFF` | 卡片、表格、Panel |
| `--color-surface-hover` | `#F8FAFC` | Hover |
| `--color-surface-selected` | `#EFF6FF` | Selected |
| `--color-surface-disabled` | `#F1F5F9` | Disabled |

### 3.4 Border

| Token | Hex | 用途 |
|---|---|---|
| `--color-border` | `#E2E8F0` | 默认边框 |
| `--color-border-light` | `#EDF2F7` | 分割线 |
| `--color-border-strong` | `#CBD5E1` | 强边框 |
| `--color-border-focus` | `#93C5FD` | Focus |

### 3.5 Text

| Token | Hex | 用途 |
|---|---|---|
| `--color-text-primary` | `#0F172A` | 主标题、核心数据 |
| `--color-text-secondary` | `#475569` | 正文、表格文字 |
| `--color-text-tertiary` | `#64748B` | 辅助说明 |
| `--color-text-muted` | `#94A3B8` | Placeholder |
| `--color-text-disabled` | `#CBD5E1` | Disabled |
| `--color-text-inverse` | `#FFFFFF` | 深色背景上的文字 |

---

## 4. Security Status Colors

### 4.1 Success / Protected

```text
Primary: #16A34A
Background: #F0FDF4
Border: #BBF7D0
```

用于：

- Firewall Active
- Protected
- Allowed
- Connection Established
- Rule Enabled
- Security Check Passed

Token：

```css
--color-success: #16A34A;
--color-success-bg: #F0FDF4;
--color-success-border: #BBF7D0;
```

### 4.2 Warning

```text
Primary: #D97706
Background: #FFFBEB
Border: #FDE68A
```

用于：

- Warning
- Suspicious Activity
- Configuration Warning
- Pending Action

Token：

```css
--color-warning: #D97706;
--color-warning-bg: #FFFBEB;
--color-warning-border: #FDE68A;
```

### 4.3 Danger / Blocked

```text
Primary: #DC2626
Background: #FEF2F2
Border: #FECACA
```

用于：

- Blocked
- Threat
- Critical Alert
- Dangerous Connection
- Rule Denied

Token：

```css
--color-danger: #DC2626;
--color-danger-bg: #FEF2F2;
--color-danger-border: #FECACA;
```

### 4.4 Info

```text
Primary: #0284C7
Background: #F0F9FF
Border: #BAE6FD
```

用于：

- Information
- System Message
- Update Notice
- Network Information

Token：

```css
--color-info: #0284C7;
--color-info-bg: #F0F9FF;
--color-info-border: #BAE6FD;
```

---

## 5. Network / Traffic Colors

网络相关信息可以使用紫色、青色和蓝色与安全状态颜色区分。

### Network

```css
--color-network: #7C3AED;
--color-network-bg: #F5F3FF;
```

用途：

- Network
- Protocol
- DNS
- VPN
- Network Topology

### Inbound

```css
--color-inbound: #0891B2;
--color-inbound-bg: #ECFEFF;
```

用途：

- Incoming Traffic
- Download
- Inbound Connection

### Outbound

```css
--color-outbound: #2563EB;
--color-outbound-bg: #EFF6FF;
```

用途：

- Outgoing Traffic
- Upload
- Outbound Connection

---

## 6. Firewall Rule Colors

防火墙规则需要快速区分 Action。

### Allow

```css
--color-rule-allow: #16A34A;
--color-rule-allow-bg: #F0FDF4;
```

### Deny

```css
--color-rule-deny: #DC2626;
--color-rule-deny-bg: #FEF2F2;
```

### Reject

```css
--color-rule-reject: #EA580C;
--color-rule-reject-bg: #FFF7ED;
```

推荐使用：

```text
ALLOW   → Green
DENY    → Red
REJECT  → Orange
```

不要使用不同颜色表示规则优先级；优先级应该通过数字、位置或标签表达。

---

## 7. Overlay / Shadow

```css
--color-overlay: rgba(15, 23, 42, 0.35);

--shadow-sm:
  0 1px 2px rgba(15, 23, 42, 0.05);

--shadow-md:
  0 4px 12px rgba(15, 23, 42, 0.08);

--shadow-lg:
  0 12px 32px rgba(15, 23, 42, 0.12);
```

### 使用建议

- 普通卡片：`shadow-sm`
- Dropdown / Popover：`shadow-md`
- Modal / Dialog：`shadow-lg`
- 不建议给所有 UI 元素同时添加阴影。
- 优先通过背景色和边框建立层级。

---

## 8. 完整 CSS Variables

```css
:root {
  /* Brand / Primary */
  --color-primary: #2563EB;
  --color-primary-hover: #1D4ED8;
  --color-primary-active: #1E40AF;
  --color-primary-light: #EFF6FF;

  /* Background */
  --color-bg: #F5F7FA;
  --color-bg-secondary: #FFFFFF;
  --color-bg-tertiary: #F8FAFC;
  --color-bg-sidebar: #F1F5F9;

  /* Surface */
  --color-surface: #FFFFFF;
  --color-surface-hover: #F8FAFC;
  --color-surface-selected: #EFF6FF;
  --color-surface-disabled: #F1F5F9;

  /* Border */
  --color-border: #E2E8F0;
  --color-border-light: #EDF2F7;
  --color-border-strong: #CBD5E1;
  --color-border-focus: #93C5FD;

  /* Text */
  --color-text-primary: #0F172A;
  --color-text-secondary: #475569;
  --color-text-tertiary: #64748B;
  --color-text-muted: #94A3B8;
  --color-text-disabled: #CBD5E1;
  --color-text-inverse: #FFFFFF;

  /* Security Status */
  --color-success: #16A34A;
  --color-success-bg: #F0FDF4;
  --color-success-border: #BBF7D0;

  --color-warning: #D97706;
  --color-warning-bg: #FFFBEB;
  --color-warning-border: #FDE68A;

  --color-danger: #DC2626;
  --color-danger-bg: #FEF2F2;
  --color-danger-border: #FECACA;

  --color-info: #0284C7;
  --color-info-bg: #F0F9FF;
  --color-info-border: #BAE6FD;

  /* Network / Traffic */
  --color-network: #7C3AED;
  --color-network-bg: #F5F3FF;

  --color-inbound: #0891B2;
  --color-inbound-bg: #ECFEFF;

  --color-outbound: #2563EB;
  --color-outbound-bg: #EFF6FF;

  /* Firewall Rule */
  --color-rule-allow: #16A34A;
  --color-rule-allow-bg: #F0FDF4;

  --color-rule-deny: #DC2626;
  --color-rule-deny-bg: #FEF2F2;

  --color-rule-reject: #EA580C;
  --color-rule-reject-bg: #FFF7ED;

  /* Overlay / Shadow */
  --color-overlay: rgba(15, 23, 42, 0.35);
  --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.05);
  --shadow-md: 0 4px 12px rgba(15, 23, 42, 0.08);
  --shadow-lg: 0 12px 32px rgba(15, 23, 42, 0.12);
}
```

---

## 9. 页面结构建议

```text
┌──────────────────────────────────────────────────────────────┐
│  🛡 Firewall                              ● Protected         │
├────────────────┬─────────────────────────────────────────────┤
│                │                                             │
│  Dashboard     │  Firewall Status                            │
│                │                                             │
│  Rules         │  ┌───────────────────────────────────────┐  │
│  Traffic       │  │  ● Firewall is active                │  │
│  Connections   │  │    Last scan · 2 min ago              │  │
│  Alerts        │  └───────────────────────────────────────┘  │
│                │                                             │
│  Settings      │  Allowed       Blocked       Alerts         │
│                │  12,483        326           8              │
│                │  🟢            🔴            🟠             │
│                │                                             │
└────────────────┴─────────────────────────────────────────────┘
```

### Sidebar

- 背景：`#F1F5F9`
- 普通文字：`#475569`
- Hover：`#F8FAFC`
- Selected Background：`#EFF6FF`
- Selected Text / Icon：`#2563EB`

### Main Content

- 页面背景：`#F5F7FA`
- Card：`#FFFFFF`
- Card Border：`#E2E8F0`
- Card Shadow：`shadow-sm`

### Header

- 背景：`#FFFFFF`
- 底部 Border：`#E2E8F0`
- 标题：`#0F172A`
- 状态 Badge：使用 Security Status Colors

---

## 10. Component Guidelines

### Button

#### Primary

```text
Background: #2563EB
Text: #FFFFFF
Hover: #1D4ED8
Active: #1E40AF
```

#### Secondary

```text
Background: #FFFFFF
Text: #334155
Border: #CBD5E1
Hover: #F8FAFC
```

#### Danger

```text
Background: #DC2626
Text: #FFFFFF
Hover: #B91C1C
```

---

### Status Badge

推荐结构：

```text
● Protected
● Allowed
● Blocked
● Warning
```

不要只使用红 / 绿圆点而没有文字。

推荐：

```text
[ ● Protected ]
[ ● Allowed   ]
[ ● Blocked   ]
[ ● Warning   ]
```

---

### Table

表格建议：

```text
Header Background: #F8FAFC
Header Text: #64748B
Row Background: #FFFFFF
Row Border: #EDF2F7
Row Hover: #F8FAFC
Selected Row: #EFF6FF
```

规则 Action：

```text
ALLOW  → Green
DENY   → Red
REJECT → Orange
```

---

### Alert

#### Success

```text
Background: #F0FDF4
Border: #BBF7D0
Icon/Text: #16A34A
```

#### Warning

```text
Background: #FFFBEB
Border: #FDE68A
Icon/Text: #D97706
```

#### Danger

```text
Background: #FEF2F2
Border: #FECACA
Icon/Text: #DC2626
```

---

## 11. Accessibility

实现时不要仅依靠颜色传递信息。

例如：

```text
❌ 绿色 = Allow
```

应改成：

```text
✓ Allowed
```

或者：

```text
[✓ ALLOW]
```

红色：

```text
[× BLOCKED]
```

黄色：

```text
[! WARNING]
```

建议：

- 主要正文文字保持高对比度。
- Disabled 状态不要仅降低透明度。
- Focus 状态必须有明显视觉反馈。
- Icon、Text、Color 三者结合表达安全状态。
- 状态颜色尽量只用于状态，不要随意用于装饰。

---

## 12. Codex Implementation Rules

实现此 UI 时遵循以下规则：

1. 优先使用 CSS Variables / Design Tokens，不要在组件中大量硬编码 Hex。
2. 所有页面默认使用 `--color-bg`。
3. 所有 Card / Panel 默认使用 `--color-surface`。
4. 主操作统一使用 `--color-primary`。
5. 安全状态严格使用 Success / Warning / Danger / Info Token。
6. Allow / Deny / Reject 使用对应 Firewall Rule Token。
7. 不要自行增加新的高饱和颜色，除非确有新的语义需求。
8. 不要使用大面积纯黑背景。
9. 不要使用霓虹色、赛博朋克风格或高饱和渐变。
10. 不要让阴影成为主要层级表达方式。
11. Hover、Active、Selected、Focus、Disabled 状态必须明确区分。
12. 表格、规则列表、连接列表应优先保证数据可读性。
13. 图表可以使用 Network / Traffic Colors，但应保持视觉克制。
14. 红色只用于真正的风险、阻止或危险状态。
15. 绿色只用于正常、允许、保护等正向安全状态。

---

## 13. Recommended Design Language

整体风格可以概括为：

> **Lightweight Enterprise Security UI**

视觉上应该接近现代网络安全 / 系统管理软件，而不是传统 CMS 后台。

关键词：

```text
Clean
Technical
Professional
Secure
Calm
High Information Density
Low Visual Noise
```

最终目标是让用户在第一眼能够快速回答三个问题：

1. **Firewall 当前是否正常？**
2. **现在发生了什么网络活动？**
3. **哪些连接 / 规则需要我处理？**
