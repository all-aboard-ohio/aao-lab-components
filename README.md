# aao-dev-components

Shared UI components for All Aboard Ohio developer sites. Framework-agnostic Web Components — drop into any project regardless of stack.

---

## `<aao-banner>`

A notification banner that fetches its content from a central GitHub-hosted JSON config. Supports four display modes.

### Quick start

```html
<!-- 1. Load the component (works in any HTML page or framework) -->
<script type="module" src="https://all-aboard-ohio.github.io/aao-dev-components/aao-banner.js"></script>

<!-- 2. Drop the element wherever you want the banner to appear (usually just below <body> or below your site's nav) -->
<aao-banner
  config-url="https://raw.githubusercontent.com/all-aboard-ohio/aao-dev-components/main/banner.json"
  mode="standard"
></aao-banner>
```

To publish a banner across all AAO sites, edit `banner.json` in this repo and set `"active": true`. To hide it, set `"active": false`. No code deploys needed on consumer sites.

---

### Modes

| Mode | Description |
|------|-------------|
| `standard` | Default. Beige/warm background with icon, message, optional link, dismiss button. |
| `lite` | Light blue tint. Subtle, low-visual-weight. |
| `dark` | AAO dark blue background with white text. High contrast. |
| `compact` | Government-style attribution bar: *"An official site of the All Aboard Ohio Developer Program · Learn more →"* No config fetch — always renders. |

```html
<!-- Compact mode — no config needed, always visible -->
<aao-banner mode="compact"></aao-banner>

<!-- Dark mode pulling from config -->
<aao-banner config-url="..." mode="dark"></aao-banner>

<!-- Inline mode — skip config fetch, supply data as attributes -->
<aao-banner
  inline
  mode="lite"
  banner-id="my-banner-v1"
  message="New route data is available."
  link="https://example.com"
  link-text="View routes"
  type="success"
></aao-banner>
```

---

### Config JSON schema

```json
{
  "active": true,
  "id": "banner-2026-05",
  "message": "Economic Impact Calculator is now live!",
  "link": "https://...",
  "linkText": "Open the tool",
  "type": "info"
}
```

| Field | Required | Values |
|-------|----------|--------|
| `active` | yes | `true` / `false` — gates rendering |
| `id` | yes | unique string — used as localStorage dismiss key |
| `message` | yes | plain text notification message |
| `link` | no | URL for the call-to-action |
| `linkText` | no | CTA label (defaults to "Learn more") |
| `type` | no | `"info"` (default) / `"warning"` / `"success"` |

---

### Dismiss behavior

Users can dismiss any `standard`, `lite`, or `dark` banner. The dismissal is stored in `localStorage` keyed by the banner's `id`. Changing the `id` in `banner.json` causes the banner to reappear for all users — useful for new announcements.

---

### React usage

```jsx
// Works as-is — React passes unknown elements through to the DOM
import 'https://all-aboard-ohio.github.io/aao-dev-components/aao-banner.js';

export function Layout({ children }) {
  return (
    <>
      <aao-banner config-url="..." mode="standard" />
      <Header />
      {children}
      <Footer />
      <aao-banner mode="compact" />
    </>
  );
}
```

---

### Footer placement

The `compact` mode is designed for footer use — it attributes the site to the AAO Developer Program without taking up visual space.

```html
<aao-banner mode="compact"></aao-banner>
```

---

## `<aao-event-gate>`

A passphrase gate + Cloudflare Turnstile bot check for field tools that need
minimal anonymous auth without storing any personal user data. Designed for
use cases like canvassing tools and station feedback forms where a shared
event code is distributed to a team before each shift.

### How it works

1. Field workers open the tool URL and see a branded gate screen
2. They enter the event code (distributed via Slack/Signal before the shift)
3. Cloudflare Turnstile verifies they're human (no CAPTCHA solving for managed mode)
4. A Cloudflare Worker validates the code against a stored PBKDF2 hash and issues a short-lived JWT
5. The JWT is stored in `sessionStorage` — it clears automatically when the tab closes
6. The tool content is revealed; subsequent page loads within the same tab skip the gate

No usernames, emails, or personal identifiers are ever stored.

### Quick start

```html
<!-- 1. Load the component -->
<script type="module"
  src="https://all-aboard-ohio.github.io/aao-dev-components/aao-event-gate.js">
</script>

<!-- 2. Wrap your protected content -->
<aao-event-gate
  auth-url="https://aao-event-gate.YOUR-SUBDOMAIN.workers.dev"
  site-key="0x4AAAAAAA_YOUR_TURNSTILE_SITE_KEY"
  event-name="July Canvass"
>
  <!-- Everything here is hidden until auth succeeds -->
  <your-tool-content></your-tool-content>
</aao-event-gate>
```

### Attributes

| Attribute | Required | Description |
|---|---|---|
| `auth-url` | yes | URL of the Cloudflare Worker auth endpoint |
| `site-key` | yes | Cloudflare Turnstile **site key** (public — safe to embed in HTML) |
| `event-name` | no | Displayed on the gate screen. Defaults to "AAO Field Tool". |

### Event

```js
document.querySelector('aao-event-gate')
  .addEventListener('aao-gate-unlock', (e) => {
    // e.detail.event — event name from the JWT
    // e.detail.exp   — Unix timestamp when the session expires
  });
```

### Backend (Cloudflare Worker)

The component requires a Cloudflare Worker to handle auth server-side.
A complete Worker template, hash generator, and setup guide are in
[`worker-template/`](./worker-template/).

See [`worker-template/README.md`](./worker-template/README.md) for full
deployment instructions including how to rotate the event code before each shift.

### Security model

| Threat | Mitigation |
|---|---|
| Bot/automated brute force | Cloudflare Turnstile (managed challenge) |
| Manual brute force | 5 attempts per IP per 15 min (KV rate limit, server-enforced) |
| Event code in source | Only a PBKDF2-SHA256 hash (100k iterations) is stored server-side |
| Hash comparison timing leak | HMAC-based constant-time comparison in the Worker |
| Stolen JWT forgery | HMAC-SHA256 with a 256-bit random secret (set via `wrangler secret put`) |
| Persistent sessions | `sessionStorage` only — clears on tab close |
