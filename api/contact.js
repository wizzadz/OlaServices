// Contact endpoint with Turnstile (Invisible) verification, rate-limit, and Microsoft Graph sendMail.
// Env vars required: TENANT_ID, CLIENT_ID, CLIENT_SECRET, SENDER, CONTACT_TO, TURNSTILE_SECRET
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 5;
const hits = new Map();

function getIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  const xrip = req.headers['x-real-ip'];
  if (xrip) return String(xrip).trim();
  return (req.socket && req.socket.remoteAddress) || '';
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    // Read raw body
    let raw = '';
    await new Promise((resolve) => {
      req.on('data', (chunk) => (raw += chunk));
      req.on('end', resolve);
    });
    const body = raw ? JSON.parse(raw) : {};
    const { name = '', email = '', message = '', cf_token = '' } = body;

    // Basic validation
    if (!name || !email || !message) return res.status(400).json({ error: 'Missing fields' });

    // Rate limit
    const ip = getIP(req);
    const now = Date.now();
    const record = hits.get(ip) || { count: 0, ts: now };
    if (now - record.ts > RATE_LIMIT_WINDOW_MS) {
      record.count = 0;
      record.ts = now;
    }
    record.count += 1;
    hits.set(ip, record);
    if (record.count > RATE_LIMIT_MAX) {
      return res.status(429).json({ error: 'Too many requests' });
    }

    // Verify Turnstile
    const secret = process.env.TURNSTILE_SECRET;
    if (!secret) {
      console.error('TURNSTILE_SECRET not set');
      return res.status(500).json({ error: 'Server misconfig' });
    }
    if (!cf_token) return res.status(400).json({ error: 'Captcha required' });
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret, response: cf_token, remoteip: ip }),
    });
    const verify = await verifyRes.json();
    if (!verify.success) {
      console.error('Turnstile verify failed:', verify);
      return res.status(400).json({ error: 'Captcha failed' });
    }

    // Acquire Graph token (client credentials)
    const tenant = process.env.TENANT_ID;
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;
    if (!tenant || !clientId || !clientSecret) {
      console.error('Graph env missing');
      return res.status(500).json({ error: 'Server misconfig' });
    }
    const tokenRes = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    });
    const tokenJson = await tokenRes.json();
    if (!tokenRes.ok) {
      console.error('Token error:', tokenJson);
      return res.status(500).json({ error: 'Auth failed' });
    }
    const accessToken = tokenJson.access_token;

    const sender = process.env.SENDER;
    const to = process.env.CONTACT_TO || sender;
    if (!sender || !to) return res.status(500).json({ error: 'Mail config missing' });

    const subject = `New inquiry from ${name}`;
    const htmlBody = `<div style="font-family:Arial,sans-serif;font-size:14px">
      <p><strong>Name:</strong> ${escapeHtml(name)}</p>
      <p><strong>Email:</strong> ${escapeHtml(email)}</p>
      <p><strong>Message:</strong><br>${escapeHtml(message).replace(/\\n/g,'<br>')}</p>
      <hr><p style="color:#666">IP: ${escapeHtml(ip)}</p>
    </div>`;

    const payload = {
      message: {
        subject,
        body: { contentType: 'HTML', content: htmlBody },
        toRecipients: [{ emailAddress: { address: to } }],
        replyTo: [{ emailAddress: { address: email } }]
      },
      saveToSentItems: 'false',
    };

    const sendRes = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(sender)}/sendMail`, {
      method: 'POST',
      headers: {
        'authorization': `Bearer ${accessToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!sendRes.ok) {
      const e = await sendRes.text();
      console.error('Graph send error:', e);
      return res.status(500).json({ error: 'Send failed' });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
}

// Simple HTML escape
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
