/**
 * Screen Guard — Client half.
 *
 * Three separate icon buttons above the composer (left aligned). Hovering one
 * slides its label out to the right; clicking toggles it.
 *
 *   屏幕常亮  — Wake Lock keeps the display on.
 *   防窥遮罩  — an opaque frame-wide layer; a click or Esc restores the UI.
 *   锁定      — the same layer, but it only opens with the password.
 *
 * No helper process exists: everything runs in this page and the Host process it
 * belongs to, so quitting DSH ends it. The password is a hash in localStorage;
 * that stops a passer-by, not someone with DevTools.
 */
window.__ModuleLoader__.load({
  id: '@local/dsh-screen-guard',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const ARM_MS = 320
    const MASK_Z = 2147480000
    const LOCK_KEY = 'dsh.screen-guard.lock'
    const LOG_KEY = 'dsh.screen-guard.log'
    const LOG_MAX = 50

    /** Strip anything that could identify the machine before a log leaves the page. */
    function redact(value) {
      return String(value)
        .replace(/file:\/\/\/\S+/gu, '<path>')
        .replace(/[A-Za-z]:[\\/]\S+/gu, '<path>')
        .replace(/https?:\/\/\S+/gu, '<url>')
        .replace(/\b[a-f0-9]{32,}\b/giu, '<hex>')
        .replace(/\s+/gu, ' ')
        .slice(0, 300)
    }

    function readLog() {
      try {
        const parsed = JSON.parse(window.localStorage.getItem(LOG_KEY) ?? '[]')
        return Array.isArray(parsed) ? parsed.filter((entry) => entry !== null && typeof entry === 'object') : []
      } catch {
        return []
      }
    }

    function clearLog() {
      try {
        window.localStorage.removeItem(LOG_KEY)
      } catch {
        // storage disabled
      }
    }

    /** Record one failure. Only failures are stored; normal use writes nothing. */
    function captureError(source, error) {
      const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error)
      const entry = { at: new Date().toISOString(), source, message: redact(message) }
      const list = readLog()
      list.push(entry)
      while (list.length > LOG_MAX) list.shift()
      try {
        window.localStorage.setItem(LOG_KEY, JSON.stringify(list))
      } catch {
        // storage disabled: the entry is still visible in the console
      }
      try {
        console.warn('[screen-guard]', entry)
      } catch {
        // never throw from logging
      }
    }

    /* ------------------------------------------------------------------ */
    /* Storage + hashing                                                   */
    /* ------------------------------------------------------------------ */

    function readLock() {
      try {
        const raw = window.localStorage.getItem(LOCK_KEY)
        if (raw === null) return { hash: null, alg: null, locked: false }
        const parsed = JSON.parse(raw)
        return {
          hash: typeof parsed?.hash === 'string' ? parsed.hash : null,
          alg: typeof parsed?.alg === 'string' ? parsed.alg : null,
          locked: parsed?.locked === true,
        }
      } catch {
        return { hash: null, alg: null, locked: false }
      }
    }

    function writeLock(next) {
      try {
        window.localStorage.setItem(LOCK_KEY, JSON.stringify(next))
      } catch {
        // storage disabled: the lock still works for this page
      }
    }

    async function digest(text) {
      try {
        if (globalThis.crypto?.subtle !== undefined) {
          const bytes = new TextEncoder().encode(text)
          const buffer = await globalThis.crypto.subtle.digest('SHA-256', bytes)
          return { alg: 'sha256', hash: [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('') }
        }
      } catch {
        // fall through
      }
      let value = 2166136261
      for (const char of text) {
        value ^= char.codePointAt(0)
        value = Math.imul(value, 16777619) >>> 0
      }
      return { alg: 'fnv1a', hash: value.toString(16).padStart(8, '0') }
    }

    async function matches(password, stored) {
      const result = await digest(password)
      return result.hash === stored.hash && result.alg === stored.alg
    }

    /* ------------------------------------------------------------------ */
    /* Store                                                               */
    /* ------------------------------------------------------------------ */

    const initial = readLock()
    const listeners = new Set()
    const state = {
      wake: 'off',
      mask: false,
      locked: initial.locked,
      hasPassword: initial.hash !== null,
      panel: null,
      viewer: false,
      burst: 0,
      locking: false,
    }

    const emit = () => {
      for (const listener of [...listeners]) {
        try {
          listener()
        } catch {
          // one broken subscriber must not break the rest
        }
      }
    }

    const set = (patch) => {
      Object.assign(state, patch)
      emit()
    }

    function subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    }

    function useGuard() {
      const [, force] = React.useState(0)
      React.useEffect(() => subscribe(() => force((n) => n + 1)), [])
      return state
    }

    /* ------------------------------------------------------------------ */
    /* Wake lock                                                           */
    /* ------------------------------------------------------------------ */

    let sentinel = null
    let wantWake = false

    async function acquire() {
      if (typeof navigator === 'undefined' || !('wakeLock' in navigator)) {
        set({ wake: 'unsupported' })
        return
      }
      set({ wake: 'pending' })
      try {
        const lock = await navigator.wakeLock.request('screen')
        sentinel = lock
        lock.addEventListener('release', () => {
          if (sentinel === lock) sentinel = null
          if (wantWake && document.visibilityState === 'visible') acquire()
        })
        set({ wake: 'on' })
      } catch (error) {
        wantWake = false
        set({ wake: 'error' })
        captureError('wake', error)
      }
    }

    function toggleWake() {
      if (wantWake) {
        wantWake = false
        const lock = sentinel
        sentinel = null
        try {
          lock?.release()
        } catch {
          // already released
        }
        set({ wake: 'off' })
        return
      }
      wantWake = true
      acquire()
    }

    /* ------------------------------------------------------------------ */
    /* Icons                                                               */
    /* ------------------------------------------------------------------ */

    const svg = (children, size = 18) =>
      h('svg', {
        viewBox: '0 0 24 24', width: size, height: size, 'aria-hidden': true,
        fill: 'none', stroke: 'currentColor', strokeWidth: 1.8,
        strokeLinecap: 'round', strokeLinejoin: 'round',
      }, children)

    const sunGlyph = (size) =>
      svg([
        h('circle', { key: 'c', cx: 12, cy: 12, r: 4 }),
        h('path', { key: 'r', d: 'M12 2.5v2.2M12 19.3v2.2M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6' }),
      ], size)

    const eyeGlyph = (size) =>
      svg([
        h('path', { key: 'a', d: 'M2.5 12C3.5 10 7 6 12 6s8.5 4 9.5 6c-1 2-4.5 6-9.5 6s-8.5-4-9.5-6Z' }),
        h('circle', { key: 'b', cx: 12, cy: 12, r: 3 }),
      ], size)

    const eyeOffGlyph = (size) =>
      svg([
        h('path', { key: 'a', d: 'M3 3l18 18' }),
        h('path', { key: 'b', d: 'M10.6 6.2A9.9 9.9 0 0 1 12 6c5 0 8.5 4 9.5 6a12.7 12.7 0 0 1-2.7 3.6' }),
        h('path', { key: 'c', d: 'M6.1 7.8C4.2 9.3 3 11.2 2.5 12c1 2 4.5 6 9.5 6 1.5 0 2.8-.4 4-1' }),
        h('path', { key: 'd', d: 'M10 10a2.8 2.8 0 0 0 4 4' }),
      ], size)

    const lockGlyph = (size, closed = true) =>
      svg([
        h('rect', { key: 'r', x: 4.5, y: 10, width: 15, height: 10.5, rx: 2.5 }),
        h('g', { key: 'g', className: 'dsg-shackle', 'data-open': String(!closed) },
          h('path', {
            d: closed
              ? 'M8 10V7.5a4 4 0 0 1 8 0V10'
              : 'M8 8.2V7.1a4 4 0 0 1 8 0V10',
          }),
        ),
        h('circle', { key: 'k', cx: 12, cy: 15.2, r: 1.25, fill: 'currentColor', stroke: 'none' }),
      ], size)

    /* ------------------------------------------------------------------ */
    /* Styles                                                              */
    /* ------------------------------------------------------------------ */

    const STYLE = `
.dsg-dock { display: flex; justify-content: flex-start; padding: 0 2px 0; }
/* When the conversation pane is wide enough, the composer card leaves a free
   column on its left: the toolbar may drop beside the card and hug the bottom.
   When it is narrow the card reaches the left edge, so the toolbar stays above
   its top border. */
.dsg-tools { transition: transform .18s ease; }
.dsg-tools[data-drop='true'] { transform: translateY(104px); }
.dsg-tools { position: relative; z-index: 6; display: flex; flex-direction: column; align-items: flex-start; gap: 8px; }

.dsg-item { position: relative; display: inline-flex; }
.dsg-item:hover { z-index: 20; }
.dsg-item:hover .dsg-label, .dsg-item:focus-within .dsg-label { max-width: 220px; opacity: 1; transform: translateY(-50%) translateX(0); padding: 5px 11px; }

.dsg-button {
  position: relative; display: inline-grid; place-items: center;
  width: 38px; height: 38px; padding: 0; border-radius: 999px;
  border: 1px solid var(--dsw-alias-border-l1);
  background: linear-gradient(150deg, rgba(255,255,255,.10), rgba(255,255,255,0) 55%), var(--dsw-alias-bg-layer-2);
  color: var(--dsw-alias-label-secondary); cursor: pointer;
  backdrop-filter: blur(14px) saturate(140%);
  box-shadow: 0 1px 2px rgba(0,0,0,.10), 0 6px 18px rgba(0,0,0,.10), inset 0 1px 0 rgba(255,255,255,.10);
  transition: transform .16s cubic-bezier(.2,.8,.2,1), box-shadow .16s ease, color .16s ease, border-color .16s ease;
}
.dsg-button:hover { transform: translateY(-1px); color: var(--dsw-alias-label-primary); box-shadow: 0 2px 4px rgba(0,0,0,.12), 0 10px 26px rgba(0,0,0,.16), inset 0 1px 0 rgba(255,255,255,.14); }
.dsg-button:active { transform: translateY(0) scale(.97); }
.dsg-button:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 3px; }
.dsg-button[data-active='true'] {
  color: #fff; border-color: transparent;
  background: linear-gradient(135deg, #4D6BFE 0%, #7C5CFF 52%, #A855F7 100%);
  box-shadow: 0 0 0 3px rgba(124,92,255,.16), 0 8px 24px rgba(93,92,255,.38), inset 0 1px 0 rgba(255,255,255,.22);
}
.dsg-button:disabled { opacity: .45; cursor: default; }

.dsg-button[data-tone='sun'][data-active='true'] {
  color: #9A5714;
  border-color: rgba(214,150,88,.34);
  background: #FFE9D2;
  box-shadow: 0 2px 10px rgba(219,150,92,.16), inset 0 1px 0 rgba(255,255,255,.55);
}
.dsg-button[data-tone='lock'][data-active='true'] {
  color: var(--dsw-alias-label-secondary);
  border-color: var(--dsw-alias-border-l2);
  background: var(--dsw-alias-bg-layer-1);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.08);
}

.dsg-burst { position: absolute; inset: -2px; border-radius: 999px; border: 2px solid rgba(244,183,124,.9); pointer-events: none; animation: dsg-burst .72s cubic-bezier(.2,.7,.3,1) forwards; }
.dsg-burst.second { animation-delay: .09s; border-color: rgba(244,183,124,.5); }
@keyframes dsg-burst { 0% { transform: scale(.72); opacity: .95; } 100% { transform: scale(2.1); opacity: 0; } }

.dsg-shackle { transform-box: fill-box; transform-origin: 50% 100%; transition: transform .3s cubic-bezier(.34,1.56,.64,1); }
.dsg-shackle[data-open='true'] { transform: translateY(-0.9px); }

.dsg-label {
  position: absolute; left: calc(100% + 6px); top: 50%;
  display: inline-flex; align-items: center; gap: 6px;
  max-width: 0; opacity: 0; overflow: hidden; white-space: nowrap;
  transform: translateY(-50%) translateX(-8px);
  padding: 5px 0; border-radius: 999px;
  border: 1px solid var(--dsw-alias-border-l1);
  background: var(--dsw-alias-bg-overlay);
  backdrop-filter: blur(16px) saturate(150%);
  box-shadow: 0 8px 22px rgba(0,0,0,.16);
  color: var(--dsw-alias-label-primary);
  font-size: 12px; line-height: 1; pointer-events: none;
  transition: max-width .2s cubic-bezier(.2,.8,.2,1), opacity .16s ease, transform .2s cubic-bezier(.2,.8,.2,1), padding .2s ease;
}
.dsg-label-text { padding-left: 2px; }
.dsg-label-manage { pointer-events: auto; border: 0; background: transparent; color: var(--dsw-alias-label-secondary); font: inherit; font-size: 11px; cursor: pointer; padding: 1px 2px; border-left: 1px solid var(--dsw-alias-border-l1); margin-left: 2px; }
.dsg-label-manage:hover { color: var(--dsw-alias-label-primary); }

.dsg-pop {
  position: absolute; left: 0; bottom: calc(100% + 10px); z-index: 70;
  width: 258px; padding: 10px; border-radius: 14px;
  border: 1px solid var(--dsw-alias-border-l1);
  background: var(--dsw-alias-bg-overlay);
  backdrop-filter: blur(20px) saturate(150%);
  box-shadow: 0 18px 44px rgba(0,0,0,.22), 0 2px 8px rgba(0,0,0,.12);
  animation: dsg-in .14s ease-out;
}
@keyframes dsg-in { from { opacity: 0; transform: translateY(4px) scale(.98); } to { opacity: 1; transform: none; } }

.dsg-log { width: 300px; }
.dsg-log-list { display: flex; flex-direction: column; gap: 5px; max-height: 220px; overflow: auto; padding-right: 2px; }
.dsg-log-item { display: flex; gap: 6px; font-size: 11px; line-height: 1.45; }
.dsg-log-time { flex: none; color: var(--dsw-alias-label-secondary); opacity: .65; font-variant-numeric: tabular-nums; }
.dsg-log-src { flex: none; color: var(--dsw-alias-label-primary); }
.dsg-log-msg { color: var(--dsw-alias-label-secondary); overflow-wrap: anywhere; }

.dsg-form { display: flex; flex-direction: column; gap: 8px; }
.dsg-form-title { font-size: 12px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.dsg-input { width: 100%; box-sizing: border-box; height: 32px; padding: 0 10px; border-radius: 9px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); font: inherit; font-size: 13px; outline: none; }
.dsg-input:focus { border-color: var(--dsw-alias-brand-primary); box-shadow: 0 0 0 3px rgba(77,107,254,.16); }
.dsg-error { font-size: 11px; color: var(--dsw-alias-state-error-primary); }
.dsg-form-actions { display: flex; gap: 8px; justify-content: flex-end; }
.dsg-btn { height: 28px; padding: 0 12px; border-radius: 8px; border: 1px solid var(--dsw-alias-border-l1); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); font: inherit; font-size: 12px; cursor: pointer; }
.dsg-btn:hover { border-color: var(--dsw-alias-border-l2); }
.dsg-btn[data-variant='primary'] { border-color: transparent; background: linear-gradient(135deg, #4D6BFE, #8B5CF6); color: #fff; }

.dsg-mask { position: fixed; inset: 0; z-index: ${MASK_Z}; display: grid; place-items: center; background: var(--dsw-alias-bg-base); backdrop-filter: blur(48px); pointer-events: auto; cursor: pointer; user-select: none; animation: dsg-fade .2s ease both; }
@keyframes dsg-fade { from { opacity: 0; } to { opacity: 1; } }
.dsg-sweep { position: fixed; inset: 0; overflow: hidden; pointer-events: none; z-index: ${MASK_Z + 1}; }
.dsg-sweep::before {
  content: ''; position: absolute; left: 50%; top: 50%; width: 320vmax; height: 2px;
  background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,.0) 35%, rgba(255,255,255,.95) 50%, rgba(255,255,255,0) 65%, transparent 100%);
  box-shadow: 0 0 22px 5px rgba(77,107,254,.35);
  transform-origin: center;
  animation: dsg-sweep .5s cubic-bezier(.4,0,.2,1) both;
}
@keyframes dsg-sweep {
  from { transform: translate(-50%, -50%) rotate(45deg) translateY(-150vmax); opacity: 0; }
  20% { opacity: 1; }
  80% { opacity: 1; }
  to { transform: translate(-50%, -50%) rotate(45deg) translateY(150vmax); opacity: 0; }
}
.dsg-mask[data-locked='true'] { cursor: default; }
.dsg-mask-inner { display: flex; flex-direction: column; align-items: center; gap: 10px; color: var(--dsw-alias-label-secondary); cursor: pointer; }
.dsg-mask-glyph { color: var(--dsw-alias-brand-primary); opacity: .9; }
.dsg-mask-title { margin: 0; font-size: 14px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.dsg-mask-hint { margin: 0; font-size: 12px; }
.dsg-mask-sub { margin: 0; font-size: 11px; opacity: .7; }

.dsg-lock-form { display: flex; flex-direction: column; gap: 10px; width: 260px; margin-top: 6px; cursor: default; }
.dsg-lock-field {
  position: relative; display: grid; place-items: center;
  width: 100%; height: 36px; border-radius: 9px;
  border: 1px solid var(--dsw-alias-border-l2);
  background: var(--dsw-alias-bg-layer-2);
  cursor: text; overflow: hidden;
}
.dsg-lock-ghost {
  position: absolute; inset: 0; width: 100%; height: 100%;
  margin: 0; padding: 0; border: 0; background: transparent;
  color: transparent; caret-color: transparent; opacity: 0;
  outline: none !important; -webkit-appearance: none; appearance: none;
}
.dsg-lock-value { display: inline-flex; align-items: center; font-size: 15px; letter-spacing: .34em; text-indent: .34em; color: var(--dsw-alias-label-primary); }
.dsg-lock-caret { display: inline-block; width: 1.5px; height: 16px; background: var(--dsw-alias-label-primary); animation: dsg-caret 1.06s steps(1) infinite; }
@keyframes dsg-caret { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }
@media (prefers-reduced-motion: reduce) { .dsg-lock-caret { animation: none; } }
.dsg-lock-placeholder { font-size: 13px; letter-spacing: .12em; color: var(--dsw-alias-label-secondary); }
.dsg-lock-error { min-height: 14px; font-size: 11px; color: var(--dsw-alias-state-error-primary); text-align: center; }
.dsg-shake { animation: dsg-shake .28s ease; }
@keyframes dsg-shake { 0%,100% { transform: none; } 25% { transform: translateX(-6px); } 75% { transform: translateX(6px); } }
`

    /* ------------------------------------------------------------------ */
    /* Password panel                                                      */
    /* ------------------------------------------------------------------ */

    function LockPanel({ view, onClose }) {
      const [draft, setDraft] = React.useState({ a: '', b: '', current: '' })
      const [error, setError] = React.useState('')
      const [step, setStep] = React.useState(view)

      const reset = () => {
        setDraft({ a: '', b: '', current: '' })
        setError('')
      }

      const save = async () => {
        if (draft.a.length < 4) return setError('密码至少 4 位')
        if (draft.a !== draft.b) return setError('两次输入不一致')
        writeLock({ ...(await digest(draft.a)), locked: true })
        set({ hasPassword: true, locked: true, panel: null })
        reset()
      }

      const verifyThen = async (next) => {
        const stored = readLock()
        if (stored.hash === null) return
        if (!(await matches(draft.current, stored))) return setError('当前密码不正确')
        if (next === 'setup') {
          setStep('setup')
          reset()
          return
        }
        writeLock({ hash: null, alg: null, locked: false })
        set({ hasPassword: false, locked: false, panel: null })
        reset()
      }

      if (step === 'setup') {
        return h('div', { className: 'dsg-form' },
          h('div', { className: 'dsg-form-title' }, '设置解锁密码'),
          h('input', { className: 'dsg-input', type: 'password', autoFocus: true, placeholder: '密码（至少 4 位）', value: draft.a, onChange: (e) => setDraft({ ...draft, a: e.target.value }) }),
          h('input', { className: 'dsg-input', type: 'password', placeholder: '再输一次', value: draft.b, onChange: (e) => setDraft({ ...draft, b: e.target.value }), onKeyDown: (e) => { if (e.key === 'Enter') save() } }),
          error !== '' ? h('div', { className: 'dsg-error' }, error) : null,
          h('div', { className: 'dsg-form-actions' },
            h('button', { className: 'dsg-btn', onClick: () => { onClose(); reset() } }, '取消'),
            h('button', { className: 'dsg-btn', 'data-variant': 'primary', onClick: save }, '设置并锁定'),
          ),
        )
      }

      return h('div', { className: 'dsg-form' },
        h('div', { className: 'dsg-form-title' }, '验证当前密码'),
        h('input', { className: 'dsg-input', type: 'password', autoFocus: true, placeholder: '当前密码', value: draft.current, onChange: (e) => setDraft({ ...draft, current: e.target.value }), onKeyDown: (e) => { if (e.key === 'Enter') verifyThen('setup') } }),
        error !== '' ? h('div', { className: 'dsg-error' }, error) : null,
        h('div', { className: 'dsg-form-actions' },
          h('button', { className: 'dsg-btn', onClick: () => { onClose(); reset() } }, '取消'),
          h('button', { className: 'dsg-btn', onClick: () => verifyThen('remove') }, '清除密码'),
          h('button', { className: 'dsg-btn', 'data-variant': 'primary', onClick: () => verifyThen('setup') }, '下一步'),
        ),
      )
    }

    /* ------------------------------------------------------------------ */
    /* Toolbar                                                             */
    /* ------------------------------------------------------------------ */

    function LogViewer({ onClose }) {
      const [entries, setEntries] = React.useState(readLog())
      const [copied, setCopied] = React.useState(false)
      const text = entries.map((entry) => `${entry.at} [${entry.source}] ${entry.message}`).join('\n')

      return h('div', { className: 'dsg-form' },
        h('div', { className: 'dsg-form-title' }, '崩溃日志'),
        entries.length === 0
          ? h('div', { className: 'dsg-row-desc' }, '暂无记录')
          : h('div', { className: 'dsg-log-list' },
            entries.slice().reverse().map((entry, index) =>
              h('div', { className: 'dsg-log-item', key: index },
                h('span', { className: 'dsg-log-time' }, entry.at.slice(11, 19)),
                h('span', { className: 'dsg-log-src' }, entry.source),
                h('span', { className: 'dsg-log-msg' }, entry.message),
              ),
            ),
          ),
        h('div', { className: 'dsg-form-actions' },
          h('button', { className: 'dsg-btn', onClick: () => { clearLog(); setEntries([]) } }, '清空'),
          h('button', {
            className: 'dsg-btn',
            onClick: async () => {
              try {
                await navigator.clipboard.writeText(text)
                setCopied(true)
                setTimeout(() => setCopied(false), 1200)
              } catch (error) {
                captureError('clipboard', error)
              }
            },
          }, copied ? '已复制' : '复制全部'),
          h('button', { className: 'dsg-btn', 'data-variant': 'primary', onClick: onClose }, '关闭'),
        ),
      )
    }

    function GuardControls() {
      const snapshot = useGuard()
      const rootRef = React.useRef(null)
      const dockRef = React.useRef(null)
      const lockTimer = React.useRef(0)
      const [drop, setDrop] = React.useState(false)

      // The dock row spans the whole conversation pane; the toolbar itself is
      // only 38px wide, so it is the row that has to be measured.
      React.useEffect(() => {
        const element = dockRef.current
        if (element === null || typeof ResizeObserver === 'undefined') return undefined
        const update = () => setDrop(element.getBoundingClientRect().width >= 1000)
        update()
        const observer = new ResizeObserver(update)
        observer.observe(element)
        return () => observer.disconnect()
      }, [])

      React.useEffect(() => () => clearTimeout(lockTimer.current), [])

      React.useEffect(() => {
        if (snapshot.panel === null && !snapshot.viewer) return undefined
        const onPointer = (event) => {
          if (rootRef.current !== null && !rootRef.current.contains(event.target)) set({ panel: null, viewer: false })
        }
        const onKey = (event) => {
          if (event.key === 'Escape') set({ panel: null, viewer: false })
        }
        document.addEventListener('pointerdown', onPointer, true)
        document.addEventListener('keydown', onKey, true)
        return () => {
          document.removeEventListener('pointerdown', onPointer, true)
          document.removeEventListener('keydown', onKey, true)
        }
      }, [snapshot.panel, snapshot.viewer])

      const wakeOn = snapshot.wake === 'on'

      const clickWake = () => {
        if (!wakeOn) set({ burst: snapshot.burst + 1 })
        toggleWake()
      }

      const clickLock = () => {
        if (!snapshot.hasPassword) {
          set({ panel: 'setup' })
          return
        }
        if (snapshot.locking || snapshot.locked) return
        set({ locking: true })
        lockTimer.current = setTimeout(() => {
          writeLock({ ...readLock(), locked: true })
          set({ locked: true, locking: false })
        }, 320)
      }

      const item = (key, tone, active, glyph, label, onClick, extra, onContextMenu) =>
        h('div', { className: 'dsg-item', key },
          h('button', {
            type: 'button', className: 'dsg-button',
            'data-active': String(active), 'data-tone': tone,
            'aria-label': label, onClick, onContextMenu,
          }, glyph),
          h('span', { className: 'dsg-label', 'aria-hidden': true },
            h('span', { className: 'dsg-label-text' }, label),
            extra ?? null,
          ),
        )

      const sunButton = h('div', { className: 'dsg-item', key: 'wake' },
        h('button', {
          type: 'button', className: 'dsg-button',
          'data-active': String(wakeOn), 'data-tone': 'sun',
          'aria-label': wakeOn ? '关闭屏幕常亮' : '开启屏幕常亮',
          onClick: clickWake,
        },
          snapshot.burst > 0
            ? [
              h('span', { key: 'b1', className: 'dsg-burst' }),
              h('span', { key: 'b2', className: 'dsg-burst second' }),
            ]
            : null,
          sunGlyph(18),
        ),
        h('span', { className: 'dsg-label', 'aria-hidden': true },
          h('span', { className: 'dsg-label-text' }, wakeOn ? '屏幕常亮 · 开' : '屏幕常亮'),
        ),
      )

      // Remount the burst rings for every click so the animation restarts.
      const burstKeyed = snapshot.burst > 0
        ? h(React.Fragment, { key: snapshot.burst }, sunButton)
        : sunButton

      return h('div', { className: 'dsg-dock', ref: dockRef },
        h('div', { className: 'dsg-tools', ref: rootRef, 'data-drop': String(drop) },
          burstKeyed,

          item('mask', 'mask', false, eyeGlyph(18), '防窥遮罩', () => set({ mask: true }), null,
            (event) => { event.preventDefault(); set({ viewer: !snapshot.viewer }) },
          ),

          item('lock', 'lock', snapshot.locked, lockGlyph(18, snapshot.locked || snapshot.locking), '密码锁屏', clickLock, null,
            snapshot.hasPassword && !snapshot.locked
              ? (event) => { event.preventDefault(); set({ panel: 'manage' }) }
              : undefined,
          ),

          snapshot.panel !== null
            ? h('div', { className: 'dsg-pop' },
              h(LockPanel, { view: snapshot.panel, onClose: () => set({ panel: null }) }),
            )
            : null,

          snapshot.viewer
            ? h('div', { className: 'dsg-pop dsg-log' },
              h(LogViewer, { onClose: () => set({ viewer: false }) }),
            )
            : null,
        ),
        h('style', null, STYLE),
      )
    }

    /* ------------------------------------------------------------------ */
    /* Mask + lock screen                                                  */
    /* ------------------------------------------------------------------ */

    function GuardMask() {
      const snapshot = useGuard()
      const armedAt = React.useRef(0)
      const ghostRef = React.useRef(null)
      const [typed, setTyped] = React.useState('')
      const [focused, setFocused] = React.useState(false)
      const [wrong, setWrong] = React.useState(false)

      React.useEffect(() => {
        if (!snapshot.mask && !snapshot.locked) return undefined
        armedAt.current = Date.now() + ARM_MS
        const dismiss = (event) => {
          if (event.type !== 'keydown' || event.key !== 'Escape') return
          if (snapshot.locked) return
          if (Date.now() < armedAt.current) return
          event.preventDefault()
          set({ mask: false })
        }
        document.addEventListener('keydown', dismiss, true)
        return () => document.removeEventListener('keydown', dismiss, true)
      }, [snapshot.mask, snapshot.locked])

      if (!snapshot.mask && !snapshot.locked) return null

      const unlock = async () => {
        const stored = readLock()
        if (stored.hash === null) {
          set({ locked: false })
          return
        }
        if (await matches(typed, stored)) {
          writeLock({ ...stored, locked: false })
          setTyped('')
          setWrong(false)
          set({ locked: false })
          return
        }
        setWrong(true)
        setTyped('')
      }

      const onClick = (event) => {
        if (snapshot.locked) return
        if (Date.now() < armedAt.current || event.detail === 0) return
        event.preventDefault()
        set({ mask: false })
      }

      return h('div', {
        className: 'dsg-mask',
        'data-locked': String(snapshot.locked),
        onClick,
        role: 'presentation',
      },
        h('style', null, STYLE),
        snapshot.locked ? null : h('span', { className: 'dsg-sweep' }),
        snapshot.locked
          ? h('div', { className: 'dsg-mask-inner', onClick: (e) => e.stopPropagation() },
            h('span', { className: 'dsg-mask-glyph' }, lockGlyph(32)),
            h('p', { className: 'dsg-mask-title' }, '已锁定'),
            h('p', { className: 'dsg-mask-hint' }, '输入密码解锁'),
            h('div', { className: 'dsg-lock-form' },
              h('div', {
                className: `dsg-lock-field${wrong ? ' dsg-shake' : ''}`,
                onClick: () => ghostRef.current?.focus(),
              },
                h('input', {
                  ref: ghostRef,
                  className: 'dsg-lock-ghost',
                  type: 'password', autoFocus: true, 'aria-label': '密码',
                  value: typed, spellCheck: false, autoComplete: 'off',
                  onChange: (e) => { setTyped(e.target.value); setWrong(false) },
                  onFocus: () => setFocused(true),
                  onBlur: () => setFocused(false),
                  onKeyDown: (e) => { if (e.key === 'Enter') unlock() },
                }),
                h('span', { className: 'dsg-lock-value' },
                  typed.length > 0
                    ? '•'.repeat(typed.length)
                    : (focused ? null : h('span', { className: 'dsg-lock-placeholder' }, '密码')),
                  focused ? h('span', { className: 'dsg-lock-caret' }) : null,
                ),
              ),
              h('div', { className: 'dsg-lock-error' }, wrong ? '密码不正确' : ''),
              h('button', { className: 'dsg-btn', 'data-variant': 'primary', onClick: unlock }, '解锁'),
            ),
          )
          : h('div', { className: 'dsg-mask-inner' },
            h('span', { className: 'dsg-mask-glyph' }, eyeOffGlyph(30)),
            h('p', { className: 'dsg-mask-title' }, '已开启防窥遮罩'),
            h('p', { className: 'dsg-mask-hint' }, '点击任意位置恢复'),
            h('p', { className: 'dsg-mask-sub' }, '也可以按 Esc 键'),
          ),
      )
    }

    /* ------------------------------------------------------------------ */
    /* Crash boundaries                                                    */
    /* ------------------------------------------------------------------ */

    class Boundary extends React.Component {
      constructor(props) {
        super(props)
        this.state = { crashed: false }
      }

      static getDerivedStateFromError() {
        return { crashed: true }
      }

      componentDidCatch(error) {
        captureError('ui', error)
      }

      render() {
        if (!this.state.crashed) return this.props.children
        return this.props.fallback ?? null
      }
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.effect(() => {
          const ours = (text) => /screen-guard|dsg-/u.test(text)
          const onError = (event) => {
            const text = `${event.message ?? ''} ${event.filename ?? ''}`
            if (ours(text)) captureError('window', event.error ?? event.message)
          }
          const onRejection = (event) => {
            const reason = event.reason
            if (ours(String(reason?.stack ?? reason))) captureError('promise', reason)
          }
          window.addEventListener('error', onError)
          window.addEventListener('unhandledrejection', onRejection)
          return () => {
            window.removeEventListener('error', onError)
            window.removeEventListener('unhandledrejection', onRejection)
          }
        }, 'screen-guard error capture')

        ctx.effect(() => {
          const onVisible = () => {
            if (document.visibilityState === 'visible' && wantWake && sentinel === null) acquire()
          }
          document.addEventListener('visibilitychange', onVisible)
          return () => {
            document.removeEventListener('visibilitychange', onVisible)
            wantWake = false
            const lock = sentinel
            sentinel = null
            try {
              lock?.release()
            } catch {
              // already gone
            }
          }
        }, 'screen-guard wake lock')

        ctx.slots.inject('conversation.input.dock', () => ctx.slots.register({
          name: 'conversation.input.dock',
          id: 'screen-guard.controls',
          order: 30,
        }, () => h(Boundary, { fallback: null }, h(GuardControls))))

        ctx.slots.inject('shell.overlay', () => ctx.slots.register({
          name: 'shell.overlay',
          id: 'screen-guard.mask',
          order: 200,
        }, () => h(Boundary, { fallback: null }, h(GuardMask))))
      },
    }
  },
})
