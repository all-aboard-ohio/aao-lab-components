# aao-event-gate Worker — Setup Guide

This Cloudflare Worker backs the `<aao-event-gate>` web component. It handles:

1. **Turnstile bot verification** — rejects automated requests before any auth logic runs
2. **Rate limiting** — max 5 failed attempts per IP per 15 minutes (stored in KV)
3. **Passphrase check** — PBKDF2-SHA256 hash comparison (constant-time)
4. **JWT issuance** — returns a short-lived HS256 token on success

No user data is stored. The code hash and JWT signing key rotate per event.

---

## Prerequisites

- [Node.js](https://nodejs.org) v18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/): `npm install -g wrangler`
- A Cloudflare account (free tier is sufficient)
- A [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/) site configured for your tool's domain

---

## One-time setup

### 1. Authenticate Wrangler

```bash
wrangler login
```

### 2. Create the KV namespace for rate limiting

```bash
wrangler kv namespace create RATE_LIMIT_KV
```

Copy the `id` from the output and paste it into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id      = "paste-your-id-here"
```

### 3. Create Turnstile keys

In the [Cloudflare Dashboard](https://dash.cloudflare.com/?to=/:account/turnstile):

1. Click **Add site**
2. Enter your tool's domain (e.g. `lab.allaboardohio.org`)
3. Choose **Managed** challenge type
4. Copy the **Site key** (public — goes into the `site-key` attribute on your HTML element)
5. Copy the **Secret key** (private — set as a Worker secret below)

### 4. Set Worker secrets

```bash
wrangler secret put TURNSTILE_SECRET
# Paste the Turnstile secret key when prompted

wrangler secret put JWT_SECRET
# Paste a random 32-byte base64 string — generate one with:
#   openssl rand -base64 32
```

> **Never commit secrets to source control.** All three secrets (`EVENT_CODE_HASH`, `JWT_SECRET`, `TURNSTILE_SECRET`) must be set via `wrangler secret put`, not in `wrangler.toml`.

---

## Before each event

### 1. Choose an event code

Pick a short, memorable passphrase that organizers can communicate to field workers before the shift. Example: `blazing-cardinal-2026`. Avoid dictionary words alone — a two-word combination with a number is strong enough given the rate limiting.

### 2. Generate the hash

```bash
node generate-hash.js "blazing-cardinal-2026"
```

Output:
```
EVENT_CODE_HASH=k3Xv8...base64...==
```

### 3. Set it as a secret

```bash
wrangler secret put EVENT_CODE_HASH
# Paste the hash value (not the event code itself) when prompted
```

The event code **never touches the server** — only its derived hash is stored.

### 4. Update wrangler.toml

Change `EVENT_NAME` to label this event (it's embedded in issued JWTs for logging):

```toml
[vars]
EVENT_NAME = "July Canvass Columbus"
TTL_HOURS  = "8"
```

### 5. Deploy

```bash
wrangler deploy
```

---

## In your tool's HTML

```html
<!-- Load the web component -->
<script type="module"
  src="https://all-aboard-ohio.github.io/aao-dev-components/aao-event-gate.js">
</script>

<!-- Wrap your protected content -->
<aao-event-gate
  auth-url="https://aao-event-gate.YOUR-SUBDOMAIN.workers.dev"
  site-key="0x4AAAAAAA_YOUR_TURNSTILE_SITE_KEY"
  event-name="July Canvass"
  ttl="8"
>
  <!-- Everything here is hidden until auth succeeds -->
  <your-canvass-tool></your-canvass-tool>
</aao-event-gate>
```

Listen for the unlock event if you need to react when auth succeeds:

```js
document.querySelector('aao-event-gate').addEventListener('aao-gate-unlock', (e) => {
  console.log('Auth succeeded, event:', e.detail.event, 'expires:', e.detail.exp);
});
```

---

## Local development

For local testing with `wrangler dev`:

1. Create a preview KV namespace:
   ```bash
   wrangler kv namespace create RATE_LIMIT_KV --preview
   ```
   Add the `preview_id` to `wrangler.toml`.

2. Add secrets to `.dev.vars` (gitignored — never commit):
   ```
   EVENT_CODE_HASH=base64hashFromGenerateScript
   JWT_SECRET=anyRandomStringForLocalTesting
   TURNSTILE_SECRET=1x0000000000000000000000000000000AA
   ```
   > The Turnstile secret `1x000...` is Cloudflare's official test secret that always passes verification in development.

3. Run the worker:
   ```bash
   wrangler dev
   ```

4. In your component, point `auth-url` at `http://localhost:8787` during development.

---

## Rotating after an event

Since session tokens are stored only in `sessionStorage` (cleared when the tab closes), expiry is automatic. To invalidate any still-active sessions from a past event immediately:

1. Generate a new hash for the next event code
2. `wrangler secret put EVENT_CODE_HASH` with the new hash
3. `wrangler deploy`

Old tokens will fail if the Worker verifies them (it doesn't currently — the component only checks `exp` client-side). If you need server-side token verification for a specific tool, open an issue to discuss adding a `/verify` endpoint.

---

## Security properties

| Property | How it's achieved |
|---|---|
| Bot blocking | Cloudflare Turnstile (challenge must pass before any auth logic runs) |
| Brute force protection | 5 attempts per IP per 15 min (KV rate limit), enforced server-side |
| Passphrase not stored | Only a PBKDF2-SHA256 hash (100k iterations) is stored, never the code itself |
| Timing-safe comparison | HMAC-based constant-time comparison in the Worker |
| JWT forgery prevention | HMAC-SHA256 signing with a 256-bit random secret |
| Session scope | `sessionStorage` only — tokens clear when the tab closes |
| CORS | `ALLOWED_ORIGINS` restricts which domains browsers can call this worker from |
| No personal data | No emails, names, IPs, or user identifiers are stored anywhere |
