
async function verifyTurnstile(req, token){
  try {
    const secret = process.env.TURNSTILE_SECRET || '0x4AAAAAACGfDAVLDZj2fDlNYXtWkeZRpH8';
    if (!token) return { success:false, error: 'missing-token'};
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket?.remoteAddress || '';
    const body = new URLSearchParams();
    body.append('secret', secret);
    body.append('response', token);
    if (ip) body.append('remoteip', ip);
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body
    });
    return await resp.json();
  } catch(e){
    return { success:false, error: 'exception' };
  }
}

// Microsoft Graph sendMail with basic anti-spam & rate limit.
const hits = new Map();

function getIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  const xrip = req.headers['x-real-ip'];
  if (xrip) return String(xrip).trim();
  return req.socket?.remoteAddress || '';
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const data = JSON.parse(raw || "{}");
    const { name, email, message, hp, ts } = data;

    // Honeypot & timing check
    if (hp) return res.status(200).json({ ok: true });
    const now = Date.now();
    const tsNum = Number(ts || 0);
    if (!tsNum || (now - tsNum) < 3000 || (now - tsNum) > 60*60*1000) {
      return res.status(400).json({ error: "Invalid timing" });
    }

    // Basic validation
    if (!name || !email || !message) return res.status(400).json({ error: "Missing fields" });
    if (String(name).length > 200) return res.status(400).json({ error: "Name too long" });
    if (String(message).length > 5000) return res.status(400).json({ error: "Message too long" });
    const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email));
    if (!emailOk) return res.status(400).json({ error: "Invalid email" });

    // Per-IP rate limit
    const ip = getIP(req) || 'unknown';
    const windowMs = 10 * 60 * 1000;
    const maxHits = 3;
    const arr = hits.get(ip) || [];
    const recent = arr.filter(t => (now - t) < windowMs);
    if (recent.length >= maxHits) {
      hits.set(ip, recent);
      return res.status(429).json({ error: "Too many requests" });
    }
    recent.push(now);
    hits.set(ip, recent);

    // Token
    const tokenRes = await fetch(`https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        scope: process.env.GRAPH_SCOPE || "https://graph.microsoft.com/.default",
        grant_type: "client_credentials",
      }),
    });
    if (!tokenRes.ok) {
      const txt = await tokenRes.text();
      console.error("Token error:", txt);
      return res.status(500).json({ error: "Auth failed" });
    }
    const { access_token } = await tokenRes.json();

    // Build and send
    const mailboxUPN  = process.env.MAILBOX_UPN || "michael@olaolu-services.com";
    const to = process.env.CONTACT_TO || mailboxUPN;
    const mail = {
      message: {
        subject: `New inquiry from ${name}`,
        toRecipients: [{ emailAddress: { address: to } }],
        replyTo: [{ emailAddress: { address: email } }],
        body: { contentType: "Text", content: `Name: ${name}\nEmail: ${email}\nIP: ${ip}\n\n${message}` },
      },
      saveToSentItems: true,
    };

    const sendRes = await fetch(
      `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(mailboxUPN)}/sendMail`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
        body: JSON.stringify(mail),
      }
    );

    if (!sendRes.ok) {
      const e = await sendRes.text();
      console.error("Graph send error:", e);
      return res.status(500).json({ error: "Send failed" });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
}
