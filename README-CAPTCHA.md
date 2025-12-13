# Captcha (Cloudflare Turnstile, Invisible)

1) Set these **Environment Variables** in Vercel (Project → Settings → Environment Variables), for **Production** and **Preview**:
- `TURNSTILE_SITE_KEY` = your Turnstile site key
- `TURNSTILE_SECRET` = your Turnstile secret key
- (Existing Graph vars) `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `SENDER`, `CONTACT_TO`

2) The `contact.html` form uses an **Invisible** Turnstile widget. Vercel injects envs at runtime only for serverless functions; for the site
we reference the site key in markup. If you want to hardcode it, replace `{{TURNSTILE_SITE_KEY}}` in `contact.html` with your key.

3) Anti‑spam: the API applies a simple 5 requests / minute per IP limit (HTTP 429).

