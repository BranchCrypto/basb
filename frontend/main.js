import {
  EventsOn,
  Quit,
  WindowIsMaximised,
  WindowMinimise,
  WindowToggleMaximise,
} from './wailsjs/runtime/runtime.js'

const go = window.go

/** @type {string|null} */
let selectedId = null
/** @type {any[]} */
let cachedEvents = []
/** @type {string} */
let activeFilter = 'all'
/** @type {ReturnType<typeof setTimeout>|null} */
let toastTimer = null
/** @type {string|null} */
let lastExportPath = null
/** @type {boolean} */
let isObserving = false
/** @type {string|null} */
let observingId = null
/** @type {string} */
let observingName = ''
/** @type {ReturnType<typeof setInterval>|null} */
let pollTimer = null
/** @type {boolean} */
let loadingSession = false

const FILTERS = [
  { id: 'all', label: '全部' },
  { id: 'sensitive', label: '风险' },
]

const TYPE_LABELS = {
  'process.create': '进程创建',
  'process.exit': '进程退出',
  'shell.execute': '命令执行',
  'file.read': '文件读取',
  'file.write': '文件写入',
  'file.create': '文件创建',
  'file.delete': '文件删除',
  'file.rename': '文件重命名',
  'network.connect': '网络连接',
  'network.close': '连接关闭',
  'network.dns': 'DNS 查询',
  'download.download': '下载',
  'upload.upload': '上传',
  'credential.hit': '凭据访问',
  'sensitive.hit': '风险命中',
  'agent.start': 'Agent 启动',
  'agent.stop': 'Agent 结束',
  'sandbox.create': '沙盒就绪',
  'sandbox.destroy': '沙盒销毁',
}

const RISK_LABELS = {
  INFO: '',
  LOW: '低',
  MEDIUM: '中',
  HIGH: '高',
  CRITICAL: '严重',
}

const STATUS_LABELS = {
  created: '已创建',
  starting: '启动中',
  running: '监测中',
  finished: '已结束',
  collecting: '汇总中',
  destroyed: '已结束',
  paused: '已暂停',
  terminated: '已终止',
  failed: '失败',
}

function api() {
  if (go?.main?.App) return go.main.App
  return null
}

function $(id) {
  return document.getElementById(id)
}

function escapeHtml(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function basename(p) {
  if (!p) return ''
  const parts = String(p).replace(/\\/g, '/').split('/')
  return parts[parts.length - 1] || p
}

function humanType(type) {
  if (!type) return '?'
  if (TYPE_LABELS[type]) return TYPE_LABELS[type]
  const [cat, act] = String(type).split('.')
  const cats = {
    process: '进程',
    shell: '命令',
    file: '文件',
    fs: '文件',
    network: '网络',
    net: '网络',
    dns: '域名',
    download: '下载',
    upload: '上传',
    credential: '凭据',
    sensitive: '敏感',
    agent: 'Agent',
    sandbox: '沙盒',
  }
  const acts = {
    create: '创建',
    write: '写入',
    read: '读取',
    delete: '删除',
    connect: '连接',
    execute: '执行',
    hit: '命中',
    start: '启动',
    stop: '结束',
    dns: '查询',
  }
  if (act) return `${cats[cat] || cat}${acts[act] || act}`
  return cats[cat] || type
}

function humanRisk(risk) {
  if (!risk) return ''
  return RISK_LABELS[risk] || risk
}

function humanStatus(status) {
  if (!status) return ''
  return STATUS_LABELS[status] || status
}

function friendlyWhen(raw) {
  if (!raw) return ''
  const d = parseUTCDate(raw)
  if (!d) return String(raw)
  const now = new Date()
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  if (sameDay) return `今天 ${hh}:${mm}`
  return `${d.getMonth() + 1}月${d.getDate()}日 ${hh}:${mm}`
}

/** Parse backend timestamps (RFC3339 or legacy "YYYY-MM-DD HH:MM:SS" UTC). */
function parseUTCDate(raw) {
  const s = String(raw).trim()
  if (!s) return null
  // Already has timezone (Z or ±HH:MM)
  if (/[zZ]|[+-]\d{2}:\d{2}$/.test(s)) {
    const d = new Date(s)
    return Number.isNaN(d.getTime()) ? null : d
  }
  // Legacy wall-clock UTC without zone — treat as UTC
  const normalized = s.includes('T') ? s : s.replace(' ', 'T')
  const d = new Date(normalized + 'Z')
  return Number.isNaN(d.getTime()) ? null : d
}

function clock(ts) {
  if (!ts) return ''
  const d = parseUTCDate(ts)
  if (!d) {
    const m = String(ts).match(/(\d{2}:\d{2}:\d{2})/)
    return m ? m[1] : String(ts)
  }
  const now = new Date()
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  const ss = String(d.getSeconds()).padStart(2, '0')
  const time = `${hh}:${mm}:${ss}`
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  if (sameDay) return time
  return `${d.getMonth() + 1}/${d.getDate()} ${time}`
}

function showToast(msg, actionLabel) {
  const el = $('toast')
  $('toast-msg').textContent = msg
  const action = $('toast-action')
  if (actionLabel) {
    action.hidden = false
    action.textContent = actionLabel
  } else {
    action.hidden = true
  }
  el.hidden = false
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    el.hidden = true
  }, 4000)
}

function setObservingUI(on, name) {
  isObserving = on
  if (!on) observingId = null
  observingName = name || observingName
  const cta = $('btn-new')
  cta.disabled = on
  cta.textContent = on ? '监测进行中…' : '启动监测'
  $('btn-run').disabled = on
  document.body.classList.toggle('is-observing', on)
}

function startLiveTimers() {
  stopLiveTimers()
  pollTimer = setInterval(() => {
    if (observingId && selectedId === observingId) {
      refreshSession(observingId, { quiet: true })
    } else if (observingId) {
      listSessions({ quiet: true })
    }
  }, 1200)
}

function stopLiveTimers() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

async function pingHealth() {
  const a = api()
  if (!a) return false
  try {
    await a.Health()
    return true
  } catch {
    return false
  }
}

async function listSessions({ quiet = false } = {}) {
  const a = api()
  const el = $('session-list')
  if (!a) {
    if (!quiet) el.innerHTML = `<div class="muted pad">请用 Basb 启动本应用</div>`
    return []
  }
  try {
    const sessions = await a.ListSessions()
    el.innerHTML = ''
    if (!sessions || sessions.length === 0) {
      el.innerHTML = `<div class="muted pad">暂无进程</div>`
      return []
    }
    for (const s of sessions) {
      const btn = document.createElement('button')
      btn.type = 'button'
      const live = isObserving && observingId && s.id === observingId
      btn.className =
        'session-item' +
        (s.id === selectedId ? ' active' : '') +
        (live ? ' live' : '')
      const name = basename(s.agent) || s.id
      const when = friendlyWhen(s.started_at)
      const st = live ? '监测中' : humanStatus(s.status)
      btn.innerHTML = `<div class="id">${escapeHtml(name)}${live ? '<span class="dot"></span>' : ''}</div><div class="meta">${escapeHtml(st)}${when ? ' · ' + escapeHtml(when) : ''}</div>`
      btn.addEventListener('click', () => selectSession(s.id))
      el.appendChild(btn)
    }
    return sessions
  } catch (e) {
    if (!quiet) el.innerHTML = `<div class="err muted pad">${escapeHtml(String(e))}</div>`
    return []
  }
}

function renderTree(nodes) {
  if (!nodes || nodes.length === 0) return isObserving ? '等待进程数据…' : '无'
  let out = ''
  const walk = (list, prefix, isRoot) => {
    list.forEach((n, i) => {
      const isLast = i === list.length - 1
      let branch = isLast ? '└── ' : '├── '
      let next = prefix + (isLast ? '    ' : '│   ')
      if (isRoot) {
        branch = ''
        next = ''
      }
      const name = basename(n.executable) || n.command_line || '?'
      out += `${prefix}${branch}${name}\n`
      if (n.children && n.children.length) walk(n.children, next, false)
    })
  }
  walk(nodes, '', true)
  return out
}

function renderSensitive(items) {
  const wrap = $('highlight')
  const el = $('sensitive')
  if (!items || items.length === 0) {
    wrap.hidden = true
    el.innerHTML = ''
    return
  }
  wrap.hidden = false
  el.innerHTML = items
    .map((it, idx) => {
      const risk = humanRisk(it.risk) || '—'
      const riskClass = it.risk ? `risk-${escapeHtml(it.risk)}` : ''
      return `
    <div class="row sens" data-risk-idx="${idx}" role="button" tabindex="0">
      <span class="risk-badge ${riskClass}">${escapeHtml(risk)}</span>
      <span class="what">${escapeHtml(humanType(it.type))}</span>
      <span class="target">${escapeHtml(it.target || '—')}</span>
    </div>`
    })
    .join('')
  el.querySelectorAll('.row.sens').forEach((row) => {
    const jumpToTimeline = () => {
      const i = Number(row.dataset.riskIdx)
      if (!items[i]) return
      activeFilter = 'sensitive'
      renderFilters()
      renderTimeline(cachedEvents)
      $('summary-section')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }
    row.addEventListener('click', jumpToTimeline)
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        jumpToTimeline()
      }
    })
  })
}

function eventMatchesFilter(ev, filter) {
  if (filter === 'all') return true
  const cat = (ev.category || '').toLowerCase()
  const type = (ev.type || '').toLowerCase()
  const risk = (ev.risk || '').toUpperCase()
  return (
    risk === 'HIGH' ||
    risk === 'CRITICAL' ||
    cat === 'sensitive' ||
    cat === 'credential' ||
    type.startsWith('sensitive.') ||
    type.startsWith('credential.')
  )
}

function renderFilters() {
  const el = $('filters')
  el.innerHTML = ''
  for (const f of FILTERS) {
    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'btn filter' + (activeFilter === f.id ? ' active' : '')
    btn.textContent = f.label
    btn.addEventListener('click', () => {
      activeFilter = f.id
      renderFilters()
      renderTimeline(cachedEvents)
    })
    el.appendChild(btn)
  }
}

function renderTimeline(events) {
  const timeline = $('timeline')
  const meta = $('timeline-meta')
  const filtered = (events || []).filter((ev) => eventMatchesFilter(ev, activeFilter))
  if (meta) {
    meta.textContent = events?.length ? `（${filtered.length}/${events.length}）` : ''
  }
  if (!filtered.length) {
    const tip = isObserving
      ? '等待 Agent 行为事件…'
      : events?.length
        ? '无匹配事件'
        : '暂无事件'
    timeline.innerHTML = `<div class="muted small pad">${tip}</div>`
    return
  }
  const nearBottom =
    timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 80
  timeline.innerHTML = filtered
    .map((ev) => {
      const risk = humanRisk(ev.risk)
      return `
    <div class="row">
      <span class="ts">${escapeHtml(clock(ev.ts))}</span>
      <span class="what">${escapeHtml(humanType(ev.type))}</span>
      ${risk ? `<span class="risk-${escapeHtml(ev.risk || '')}">${escapeHtml(risk)}</span>` : '<span></span>'}
      <span class="target">${escapeHtml(ev.target || '')}</span>
    </div>`
    })
    .join('')
  if (isObserving && nearBottom) {
    timeline.scrollTop = timeline.scrollHeight
  }
}

function showReportShell(timeLabel, subtitle) {
  $('empty').hidden = true
  $('report').hidden = false
  $('btn-export').disabled = !!(isObserving && selectedId === observingId)
  $('title').textContent = timeLabel || '—'
  $('subtitle').textContent = subtitle || ''
}

function hideReport() {
  $('report').hidden = true
  $('empty').hidden = false
  $('btn-export').disabled = true
  selectedId = null
}

async function refreshSession(id, { quiet = false } = {}) {
  if (loadingSession && quiet) return
  const a = api()
  if (!a) return
  loadingSession = true
  try {
    const [meta, report, events] = await Promise.all([
      a.GetSession(id),
      a.GetReport(id),
      a.GetEvents(id),
    ])

    if (selectedId !== id) return

    const name = basename(meta.agent) || meta.id
    const live = isObserving && id === observingId
    const when = friendlyWhen(meta.started_at)
    const statusLabel = live ? '监测中' : humanStatus(meta.status)
    showReportShell(when || '—', `${name}${statusLabel ? ' · ' + statusLabel : ''}`)

    $('tree').textContent = renderTree(report?.process_tree || [])
    renderSensitive(report?.sensitive_events || [])

    cachedEvents = events || []
    renderTimeline(cachedEvents)
  } catch (e) {
    if (quiet) return
    cachedEvents = []
    $('timeline').innerHTML = `<div class="muted pad err">${escapeHtml(String(e))}</div>`
    $('tree').textContent = '加载失败'
    renderSensitive([])
  } finally {
    loadingSession = false
  }
}

async function selectSession(id) {
  selectedId = id
  activeFilter = 'all'
  renderFilters()
  await listSessions()
  await refreshSession(id)
}

async function onRunReady(info) {
  if (!info?.id) return
  observingId = info.id
  observingName = basename(info.agent) || observingName || 'Agent'
  setObservingUI(true, observingName)
  selectedId = info.id
  activeFilter = 'all'
  renderFilters()
  showReportShell(friendlyWhen(new Date().toISOString()) || '刚刚', `${observingName} · 监测中`)
  $('tree').textContent = '等待进程数据…'
  cachedEvents = []
  renderTimeline([])
  await listSessions()
  startLiveTimers()
  await refreshSession(info.id, { quiet: true })
}

async function pickInto(inputId, kind) {
  const a = api()
  if (!a) {
    showToast('无法打开文件对话框')
    return
  }
  try {
    const path = kind === 'dir' ? await a.PickFolder() : await a.PickExecutable()
    if (path) $(inputId).value = path
  } catch (e) {
    showToast(String(e))
  }
}

function openRunDialog() {
  if (isObserving) {
    showToast('已有监测在进行，结束后再启动')
    return
  }
  $('run-error').hidden = true
  $('run-dialog').showModal()
}

$('btn-new').addEventListener('click', openRunDialog)

$('btn-cancel').addEventListener('click', () => {
  $('run-dialog').close()
})

$('btn-pick-agent').addEventListener('click', () => pickInto('input-agent', 'file'))
$('btn-pick-dir').addEventListener('click', () => pickInto('input-workdir', 'dir'))

$('btn-export').addEventListener('click', async () => {
  if (!selectedId || !api()) return
  if (isObserving && selectedId === observingId) {
    showToast('监测结束后才能导出审计包')
    return
  }
  $('btn-export').disabled = true
  try {
    const path = await api().ExportSession(selectedId)
    lastExportPath = path
    showToast('审计包已导出', '打开文件夹')
  } catch (e) {
    lastExportPath = null
    showToast(String(e))
  } finally {
    $('btn-export').disabled = false
  }
})

$('toast-action').addEventListener('click', async () => {
  if (!lastExportPath || !api()?.RevealPath) return
  try {
    await api().RevealPath(lastExportPath)
  } catch (e) {
    showToast(String(e))
  }
})

$('run-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  const fd = new FormData(e.target)
  const agent = String(fd.get('agent') || '').trim()
  const workdir = String(fd.get('workdir') || '').trim()
  const session = String(fd.get('session') || '').trim()
  const argsRaw = String(fd.get('args') || '').trim()
  const args = argsRaw ? argsRaw.split(/\s+/) : []
  const errEl = $('run-error')
  const a = api()
  if (!a) {
    errEl.textContent = '后端未连接'
    errEl.hidden = false
    return
  }
  if (isObserving) {
    errEl.textContent = '已有监测在进行'
    errEl.hidden = false
    return
  }
  errEl.hidden = true
  $('run-dialog').close()

  observingName = basename(agent) || 'Agent'
  observingId = null
  setObservingUI(true, observingName)
  selectedId = null
  showReportShell(friendlyWhen(new Date().toISOString()) || '刚刚', `${observingName} · 正在启动`)
  $('tree').textContent = '启动中…'
  cachedEvents = []
  renderTimeline([])
  $('highlight').hidden = true

  try {
    const info = await a.RunAgent(agent, workdir, session, args)
    e.target.reset()
    stopLiveTimers()
    const finishedId = info?.id || observingId
    setObservingUI(false)
    await listSessions()
    if (finishedId) {
      selectedId = finishedId
      await refreshSession(finishedId)
    }
    const label = basename(info?.agent) || finishedId || observingName
    showToast(info?.status === 'failed' ? `监测失败：${label}` : `监测完成：${label}`)
  } catch (err) {
    stopLiveTimers()
    setObservingUI(false)
    $('run-dialog').showModal()
    errEl.textContent = String(err)
    errEl.hidden = false
    hideReport()
  }
})

if (window.runtime?.EventsOnMultiple || window.runtime?.EventsOn) {
  EventsOn('basb:run-ready', (info) => {
    onRunReady(info)
  })
  EventsOn('basb:run-failed', (msg) => {
    stopLiveTimers()
    setObservingUI(false)
    showToast(String(msg || '监测启动失败'))
  })
}

async function syncMaximisedState() {
  try {
    const maximised = await WindowIsMaximised()
    document.body.classList.toggle('is-maximised', !!maximised)
    const btn = $('btn-win-max')
    if (btn) {
      btn.title = maximised ? '还原' : '最大化'
      btn.setAttribute('aria-label', maximised ? '还原' : '最大化')
    }
  } catch {
    /* runtime unavailable outside Wails */
  }
}

function wireTitlebar() {
  $('btn-win-min')?.addEventListener('click', () => WindowMinimise())
  $('btn-win-max')?.addEventListener('click', async () => {
    WindowToggleMaximise()
    await syncMaximisedState()
  })
  $('btn-win-close')?.addEventListener('click', () => Quit())
  $('titlebar')?.addEventListener('dblclick', async (e) => {
    if (e.target.closest('.chrome-controls, .titlebar-controls')) return
    WindowToggleMaximise()
    await syncMaximisedState()
  })
  window.addEventListener('resize', () => {
    syncMaximisedState()
  })
}

async function boot() {
  wireTitlebar()
  await syncMaximisedState()
  renderFilters()
  const ok = await pingHealth()
  await listSessions()
  if (!ok) return
}

boot()
