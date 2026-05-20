/**
 * aao-event-gate.js — All Aboard Ohio event access gate
 *
 * A lightweight web component that wraps protected content behind a
 * passphrase gate + Cloudflare Turnstile bot check. Designed for field
 * tools (canvassing, station feedback) that need minimal anonymous auth
 * without storing any personal user data.
 *
 * Usage:
 *   <script type="module" src="...aao-event-gate.js"></script>
 *   <aao-event-gate
 *     auth-url="https://your-worker.workers.dev/auth"
 *     site-key="0x4AAAAAAA..."
 *     event-name="July Canvass"
 *     ttl="8"
 *   >
 *     <your-protected-content></your-protected-content>
 *   </aao-event-gate>
 *
 * Attributes:
 *   auth-url    (required) URL of the Cloudflare Worker auth endpoint
 *   site-key    (required) Cloudflare Turnstile site key (public, safe to embed)
 *   event-name  (optional) Displayed on the gate screen; defaults to "AAO Field Tool"
 *   ttl         (optional) Not used by the component directly — the Worker controls
 *                          token expiry. The component reads the JWT exp claim.
 *
 * Events dispatched:
 *   aao-gate-unlock  — fired on the element when auth succeeds
 *                      detail: { event: string, exp: number }
 *
 * Session storage:
 *   aao-gate-token   — JWT stored in sessionStorage (clears when tab closes)
 */

const GATE_STORAGE_KEY   = 'aao-gate-token';
const TURNSTILE_SCRIPT   = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const TURNSTILE_SCRIPT_ID = 'aao-turnstile-script';
const SPIN_STYLE_ID      = 'aao-gate-spin-style';

// ── SVGs ──────────────────────────────────────────────────────────────────────

const TRAIN_SVG = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="16" height="16" x="4" y="3" rx="2"/><path d="M4 11h16"/><path d="M12 3v8"/><path d="m8 19-2 3"/><path d="m16 19 2 3"/><circle cx="9" cy="15" r="1"/><circle cx="15" cy="15" r="1"/></svg>`;

const LOCK_SVG = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;

const CHECK_SVG = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>`;

const SPIN_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="animation:aao-spin 0.9s linear infinite" aria-hidden="true"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>`;

// ── JWT helpers ───────────────────────────────────────────────────────────────
// Client-side only: we decode the payload to read the exp claim.
// We do NOT verify the signature client-side — that would require the secret.

function decodeJWTPayload(token) {
  try {
    const payloadB64 = token.split('.')[1];
    if (!payloadB64) return null;
    return JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
  } catch {
    return null;
  }
}

function isTokenValid(token) {
  if (!token || typeof token !== 'string') return false;
  const payload = decodeJWTPayload(token);
  if (!payload || typeof payload.exp !== 'number') return false;
  // Allow 30-second clock skew
  return Date.now() / 1000 < payload.exp - 30;
}

// ── Component ─────────────────────────────────────────────────────────────────

class AaoEventGate extends HTMLElement {
  constructor() {
    super();
    this._gateEl        = null;   // the overlay DOM element
    this._contentEl     = null;   // wrapper for original children
    this._widgetId      = null;   // Turnstile widget ID
    this._turnstileToken = null;  // Turnstile challenge token (set in callback)
    this._locked        = false;  // true after server-side lockout
    this._initialized   = false;
  }

  connectedCallback() {
    if (this._initialized) return;
    this._initialized = true;

    // Move all existing children into a hidden wrapper div.
    // This preserves the slotted content while we overlay the gate.
    this._contentEl = document.createElement('div');
    this._contentEl.className = 'aao-gate-content';
    this._contentEl.setAttribute('aria-hidden', 'true');
    this._contentEl.style.display = 'none';
    while (this.firstChild) this._contentEl.appendChild(this.firstChild);
    this.appendChild(this._contentEl);

    // Check for a valid stored session (same tab only — sessionStorage)
    const stored = sessionStorage.getItem(GATE_STORAGE_KEY);
    if (stored && isTokenValid(stored)) {
      this._unlock(stored, false);
      return;
    }

    // Remove any expired/invalid token
    sessionStorage.removeItem(GATE_STORAGE_KEY);
    this._renderGate();
  }

  // ── Gate UI render ───────────────────────────────────────────────────────────

  _renderGate() {
    const eventName = this.getAttribute('event-name') || 'AAO Field Tool';
    const siteKey   = this.getAttribute('site-key')   || '';

    if (!siteKey) {
      console.error('[aao-event-gate] Missing required attribute: site-key');
    }

    this._gateEl = document.createElement('div');
    this._gateEl.className = 'aao-gate-overlay';
    this._gateEl.setAttribute('role', 'dialog');
    this._gateEl.setAttribute('aria-modal', 'true');
    this._gateEl.setAttribute('aria-label', `Access gate for ${eventName}`);

    // Full-viewport fixed overlay — sits on top of everything
    Object.assign(this._gateEl.style, {
      position:       'fixed',
      inset:          '0',
      zIndex:         '9999',
      background:     '#011e36',
      display:        'flex',
      alignItems:     'center',
      justifyContent: 'center',
      fontFamily:     "'Montserrat', system-ui, sans-serif",
      padding:        '20px',
      boxSizing:      'border-box',
    });

    this._gateEl.innerHTML = `
      <div style="
        background:#012f55;
        border:1px solid rgba(255,255,255,0.1);
        border-radius:16px;
        padding:40px 36px;
        width:100%;
        max-width:420px;
        box-shadow:0 24px 64px rgba(0,0,0,0.6);
      ">
        <!-- AAO branding row -->
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:32px;">
          <span style="color:#388CBB;">${TRAIN_SVG}</span>
          <span style="
            color:#FBF3E3;
            font-family:'Poppins',system-ui,sans-serif;
            font-weight:700;
            font-size:14px;
            letter-spacing:0.04em;
          ">All Aboard Ohio</span>
        </div>

        <!-- Lock icon + heading -->
        <div style="color:#94b8cc;margin-bottom:8px;">${LOCK_SVG}</div>
        <h1 style="
          color:#fff;
          font-family:'Poppins',system-ui,sans-serif;
          font-size:22px;
          font-weight:800;
          margin:0 0 8px;
          line-height:1.3;
        ">${eventName}</h1>
        <p style="
          color:#80aac2;
          font-size:13px;
          margin:0 0 28px;
          line-height:1.6;
        ">
          Enter the event code to access this tool.
          Contact your event organizer if you don&apos;t have one.
        </p>

        <!-- Form -->
        <form id="aao-gate-form" autocomplete="off" novalidate>
          <label for="aao-gate-input" style="
            display:block;
            color:#94b8cc;
            font-size:11px;
            font-weight:700;
            letter-spacing:0.1em;
            text-transform:uppercase;
            margin-bottom:7px;
          ">Event code</label>

          <input
            id="aao-gate-input"
            type="password"
            autocomplete="new-password"
            spellcheck="false"
            autocorrect="off"
            autocapitalize="off"
            placeholder="Enter event code"
            maxlength="256"
            style="
              display:block;
              width:100%;
              box-sizing:border-box;
              background:#011e36;
              border:1.5px solid rgba(56,140,187,0.35);
              border-radius:8px;
              color:#fff;
              font-family:monospace;
              font-size:15px;
              padding:11px 14px;
              outline:none;
              transition:border-color 0.2s;
              -webkit-appearance:none;
            "
          />

          <!-- Turnstile widget container -->
          <div id="aao-gate-turnstile" style="margin:20px 0 8px;min-height:65px;"></div>

          <!-- Error message -->
          <div
            id="aao-gate-error"
            role="alert"
            aria-live="polite"
            style="
              display:none;
              color:#fc8181;
              font-size:12px;
              margin-bottom:14px;
              line-height:1.55;
              padding:10px 12px;
              background:rgba(183,39,23,0.15);
              border:1px solid rgba(183,39,23,0.3);
              border-radius:6px;
            "
          ></div>

          <button
            id="aao-gate-submit"
            type="submit"
            disabled
            style="
              display:flex;
              align-items:center;
              justify-content:center;
              gap:8px;
              width:100%;
              padding:13px 20px;
              border:none;
              border-radius:8px;
              background:#B72717;
              color:#fff;
              font-family:'Poppins',system-ui,sans-serif;
              font-size:14px;
              font-weight:700;
              cursor:not-allowed;
              transition:background 0.2s, opacity 0.2s, transform 0.1s;
              opacity:0.45;
            "
          >
            <span id="aao-gate-btn-icon" aria-hidden="true">${LOCK_SVG}</span>
            <span id="aao-gate-btn-label">Complete the security check</span>
          </button>
        </form>

        <p style="
          color:#3d6880;
          font-size:11px;
          text-align:center;
          margin:20px 0 0;
          line-height:1.5;
        ">No account required &middot; No personal data collected</p>
      </div>
    `;

    this.appendChild(this._gateEl);
    this._injectSpinStyle();
    this._bindFormEvents();
    this._loadTurnstile(siteKey);

    // Focus the input once the overlay is ready
    requestAnimationFrame(() => {
      this._gateEl?.querySelector('#aao-gate-input')?.focus();
    });
  }

  // ── Turnstile ────────────────────────────────────────────────────────────────

  _loadTurnstile(siteKey) {
    if (!siteKey) {
      this._showTurnstileError('site-key attribute is missing — cannot load security check.');
      return;
    }

    const renderWidget = () => {
      const container = this._gateEl?.querySelector('#aao-gate-turnstile');
      if (!container) return;

      this._widgetId = window.turnstile.render(container, {
        sitekey:           siteKey,
        theme:             'dark',
        callback:          (token) => this._onTurnstileSuccess(token),
        'expired-callback': ()     => this._onTurnstileExpired(),
        'error-callback':  ()     => this._onTurnstileError(),
      });
    };

    if (window.turnstile) {
      renderWidget();
      return;
    }

    // Inject the Turnstile script once (idempotent)
    if (!document.getElementById(TURNSTILE_SCRIPT_ID)) {
      const script = document.createElement('script');
      script.id    = TURNSTILE_SCRIPT_ID;
      script.src   = TURNSTILE_SCRIPT;
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }

    // Poll until window.turnstile is available (fires ~100ms after script loads)
    const startMs = Date.now();
    const poll = setInterval(() => {
      if (window.turnstile) {
        clearInterval(poll);
        renderWidget();
        return;
      }
      // Timeout after 12 seconds
      if (Date.now() - startMs > 12_000) {
        clearInterval(poll);
        this._showTurnstileError(
          'Security check failed to load. Check your connection and refresh the page.'
        );
      }
    }, 100);
  }

  _onTurnstileSuccess(token) {
    this._turnstileToken = token;
    const submit   = this._gateEl?.querySelector('#aao-gate-submit');
    const btnLabel = this._gateEl?.querySelector('#aao-gate-btn-label');
    const btnIcon  = this._gateEl?.querySelector('#aao-gate-btn-icon');
    if (!submit) return;
    submit.disabled = false;
    submit.style.opacity = '1';
    submit.style.cursor  = 'pointer';
    if (btnLabel) btnLabel.textContent = 'Unlock';
    if (btnIcon)  btnIcon.innerHTML    = LOCK_SVG;
  }

  _onTurnstileExpired() {
    this._turnstileToken = null;
    const submit   = this._gateEl?.querySelector('#aao-gate-submit');
    const btnLabel = this._gateEl?.querySelector('#aao-gate-btn-label');
    if (!submit) return;
    submit.disabled = true;
    submit.style.opacity = '0.45';
    submit.style.cursor  = 'not-allowed';
    if (btnLabel) btnLabel.textContent = 'Security check expired — please re-verify';
    this._showError('The security check expired. Please re-verify above.');
  }

  _onTurnstileError() {
    this._turnstileToken = null;
    this._showTurnstileError(
      'The security check encountered an error. Refresh the page to try again.'
    );
  }

  _resetTurnstile() {
    if (this._widgetId !== null && window.turnstile) {
      try { window.turnstile.reset(this._widgetId); } catch {}
    }
    this._turnstileToken = null;
    const submit   = this._gateEl?.querySelector('#aao-gate-submit');
    const btnLabel = this._gateEl?.querySelector('#aao-gate-btn-label');
    if (submit) {
      submit.disabled = true;
      submit.style.opacity = '0.45';
      submit.style.cursor  = 'not-allowed';
    }
    if (btnLabel) btnLabel.textContent = 'Complete the security check';
  }

  // ── Form events ───────────────────────────────────────────────────────────────

  _bindFormEvents() {
    const form   = this._gateEl.querySelector('#aao-gate-form');
    const input  = this._gateEl.querySelector('#aao-gate-input');

    input.addEventListener('focus', () => {
      input.style.borderColor = 'rgba(56,140,187,0.85)';
    });
    input.addEventListener('blur', () => {
      input.style.borderColor = 'rgba(56,140,187,0.35)';
    });
    input.addEventListener('input', () => this._clearError());

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      this._handleSubmit();
    });
  }

  async _handleSubmit() {
    if (this._locked) return;

    const input = this._gateEl?.querySelector('#aao-gate-input');
    if (!input) return;

    const code = input.value.trim();
    if (!code) {
      this._showError('Please enter the event code.');
      input.focus();
      return;
    }

    if (!this._turnstileToken) {
      this._showError('Please complete the security check above first.');
      return;
    }

    const authUrl = this.getAttribute('auth-url');
    if (!authUrl) {
      this._showError('Configuration error: auth-url attribute is missing.');
      console.error('[aao-event-gate] Missing required attribute: auth-url');
      return;
    }

    this._setLoading(true);

    try {
      const res = await fetch(authUrl, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ code, turnstileToken: this._turnstileToken }),
      });

      // Guard against non-JSON responses (e.g. Cloudflare error pages)
      let data;
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        data = await res.json();
      } else {
        throw new Error(`Unexpected response: ${res.status} ${res.statusText}`);
      }

      if (res.ok && data.token) {
        sessionStorage.setItem(GATE_STORAGE_KEY, data.token);
        this._setLoading(false);
        this._showSuccess();
        setTimeout(() => this._unlock(data.token, true), 800);
      } else if (res.status === 429 || (data.retriesLeft !== undefined && data.retriesLeft <= 0)) {
        this._setLoading(false);
        this._lockout();
      } else {
        const retriesLeft = typeof data.retriesLeft === 'number' ? data.retriesLeft : '?';
        this._showError(
          `Incorrect code. ${retriesLeft} attempt${retriesLeft === 1 ? '' : 's'} remaining before lockout.`
        );
        this._resetTurnstile();
        this._setLoading(false);
      }
    } catch (err) {
      console.error('[aao-event-gate] Auth request failed:', err);
      this._showError(
        'Unable to reach the auth server. Check your connection and try again.'
      );
      this._resetTurnstile();
      this._setLoading(false);
    }
  }

  // ── UI state helpers ─────────────────────────────────────────────────────────

  _setLoading(loading) {
    const submit   = this._gateEl?.querySelector('#aao-gate-submit');
    const btnLabel = this._gateEl?.querySelector('#aao-gate-btn-label');
    const btnIcon  = this._gateEl?.querySelector('#aao-gate-btn-icon');
    const input    = this._gateEl?.querySelector('#aao-gate-input');
    if (!submit) return;

    if (loading) {
      submit.disabled      = true;
      submit.style.opacity = '0.7';
      submit.style.cursor  = 'not-allowed';
      if (btnIcon)  btnIcon.innerHTML    = SPIN_SVG;
      if (btnLabel) btnLabel.textContent = 'Checking\u2026';
      if (input)    input.disabled       = true;
    } else {
      if (input) input.disabled = false;
      // Button re-enable is handled by Turnstile reset or _showSuccess
    }
  }

  _showError(msg) {
    const err = this._gateEl?.querySelector('#aao-gate-error');
    if (!err) return;
    err.textContent  = msg;
    err.style.display = 'block';
  }

  _showTurnstileError(msg) {
    const container = this._gateEl?.querySelector('#aao-gate-turnstile');
    if (container) {
      container.innerHTML = `<p style="color:#fc8181;font-size:12px;margin:0;line-height:1.5;">${msg}</p>`;
    }
  }

  _clearError() {
    const err = this._gateEl?.querySelector('#aao-gate-error');
    if (err) err.style.display = 'none';
  }

  _showSuccess() {
    const submit   = this._gateEl?.querySelector('#aao-gate-submit');
    const btnLabel = this._gateEl?.querySelector('#aao-gate-btn-label');
    const btnIcon  = this._gateEl?.querySelector('#aao-gate-btn-icon');
    if (!submit) return;
    submit.style.background = '#16833d';
    submit.style.opacity    = '1';
    if (btnIcon)  btnIcon.innerHTML    = CHECK_SVG;
    if (btnLabel) btnLabel.textContent = 'Access granted';
  }

  _lockout() {
    this._locked = true;
    const input  = this._gateEl?.querySelector('#aao-gate-input');
    const submit = this._gateEl?.querySelector('#aao-gate-submit');
    const btnLabel = this._gateEl?.querySelector('#aao-gate-btn-label');
    if (input)  { input.disabled = true; input.style.opacity = '0.5'; }
    this._showError(
      'Too many incorrect attempts. Please wait 15 minutes before trying again, or contact your event organizer.'
    );
    if (submit) {
      submit.disabled      = true;
      submit.style.opacity = '0.35';
      submit.style.cursor  = 'not-allowed';
    }
    if (btnLabel) btnLabel.textContent = 'Locked out';
  }

  // ── Unlock ───────────────────────────────────────────────────────────────────

  _unlock(token, animate) {
    const payload = decodeJWTPayload(token);

    // Tear down Turnstile widget cleanly
    if (this._widgetId !== null && window.turnstile) {
      try { window.turnstile.remove(this._widgetId); } catch {}
      this._widgetId = null;
    }

    const reveal = () => {
      if (this._gateEl) { this._gateEl.remove(); this._gateEl = null; }
      if (this._contentEl) {
        this._contentEl.style.display = '';
        this._contentEl.removeAttribute('aria-hidden');
      }
      this.dispatchEvent(new CustomEvent('aao-gate-unlock', {
        bubbles: true,
        composed: true,
        detail: {
          event: payload?.event ?? null,
          exp:   payload?.exp   ?? null,
        },
      }));
    };

    if (animate && this._gateEl) {
      this._gateEl.style.transition = 'opacity 0.35s ease';
      this._gateEl.style.opacity    = '0';
      setTimeout(reveal, 370);
    } else {
      reveal();
    }
  }

  // ── Misc ─────────────────────────────────────────────────────────────────────

  _injectSpinStyle() {
    if (document.getElementById(SPIN_STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = SPIN_STYLE_ID;
    style.textContent = '@keyframes aao-spin{to{transform:rotate(360deg)}}';
    document.head.appendChild(style);
  }
}

if (!customElements.get('aao-event-gate')) {
  customElements.define('aao-event-gate', AaoEventGate);
}
