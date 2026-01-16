import crypto from "crypto";

// --------- Config knobs (tune as you like) ----------
const MAX_MESSAGE_CHARS = 2000;

// Cooldown: minimum ms between allowed requests from the same browser
const COOLDOWN_MS = 4000;

// Cookie names
const COOKIE_SESSION = "bgpt_sess";
const COOKIE_COOLDOWN = "bgpt_cd";

// Facts About Me
const benFacts = `
FACTS ABOUT BEN (PUBLIC, APPROVED SOURCE)

IDENTITY
- Ben Shectman is an executive UX and product design leader with more than 20 years of professional experience.
- His work focuses on building and scaling design organizations and delivering enterprise-grade digital products.
- He specializes in complex, regulated, and multi-stakeholder enterprise environments.

RECENT ROLE
- From 2019 to 2025, Ben served as Experience Design Chapter Leader at Johnson & Johnson.
- He established and scaled an Experience Design center of excellence supporting corporate, finance, supply chain, technology services, and information security organizations.
- He was accountable for UX leadership across more than 40 workforce-facing enterprise platforms.
- He built and led a design team that grew from one designer to more than twenty.
- He directed a design services portfolio exceeding $6M across more than 45 engagements.

KEY INITIATIVES
- Ben led design for SigniFi, a multi-year global transformation of finance operations.
- He oversaw UX for SupplierHub, a multi-sided platform connecting internal corporate functions with external suppliers.
- He directed analytics-driven initiatives including Service Operations Performance Analytics and a Supply Chain Digital Twin.
- He championed exploration of GenAI-enabled rapid prototyping tools to accelerate design discovery.

DESIGN PRACTICE & LEADERSHIP
- Ben has established DesignOps practices, design systems, and governance models to support scaling teams.
- He has created component libraries and prototyping systems in collaboration with global brand organizations.
- He has standardized UX practices across product delivery lifecycles and cross-functional product squads.
- He has mentored and coached designers, supporting skills development and career progression.

PRIOR LEADERSHIP ROLES
- Director of User Experience at Crestron Electronics (2016-2018), leading UX across residential and enterprise control systems.
- Head of User Experience at REDI Global Technologies (2015), supporting institutional trading platform development.
- Director of User Experience at Sparta Systems (2012-2014), establishing an internal UX function for enterprise software.
- Practice Lead, Digital Strategy at EMC2 Global Consulting.
- Senior UX leadership roles at Pfizer and other digital and consulting organizations.

RESEARCH & METHODS
- Ben has led qualitative and quantitative user research programs, including usability testing, contextual inquiry, and behavioral analysis.
- He applies human-centered design, Lean UX, and agile practices within product development environments.

EDUCATION & CERTIFICATIONS
- Bachelor of Arts in Psychology from Yale University.
- Certifications include Pragmatic Marketing (PMC-II), Simplexity Applied Creativity Facilitator (Basadur), and Design Leadership (Cooper).

TOPICS BEN WRITES AND SPEAKS ABOUT
- Design leadership and organizational scaling
- Human-AI interaction and cognitive bias
- Enterprise UX for complex systems
- DesignOps and systems thinking

BOUNDARIES
- This assistant may answer questions only using the facts listed above.
- If a question cannot be answered using these facts, the assistant must say it does not know.
- The assistant must not speculate, infer private details, or provide personal contact information.

END FACTS.
`;

// HMAC signing secret for cookies (set BGPT_COOKIE_SECRET in Netlify env vars)
function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}


// --------- Helpers ----------
function parseCookies(cookieHeader = "") {
  return Object.fromEntries(
    cookieHeader
      .split(";")
      .map(v => v.trim())
      .filter(Boolean)
      .map(pair => {
        const idx = pair.indexOf("=");
        if (idx === -1) return [pair, ""];
        return [decodeURIComponent(pair.slice(0, idx)), decodeURIComponent(pair.slice(idx + 1))];
      })
  );
}

function setCookie(name, value, opts = {}) {
  const parts = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  return parts.join("; ");
}

function nowMs() {
  return Date.now();
}

function hmacSign(payload, secret) {
  return crypto.createHmac("sha256", secret).update(payload).digest("base64url");
}

function makeSignedToken(obj, secret) {
  const payload = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = hmacSign(payload, secret);
  return `${payload}.${sig}`;
}

function readSignedToken(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const expected = hmacSign(payload, secret);
  // Timing-safe compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;

  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function getAllowedOrigin(request) {
  const origin = request.headers.get("origin") || "";
  const allowlist = (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  if (allowlist.length === 0) return "";
  return allowlist.includes(origin) ? origin : "";
}

// Simple “non-browser” heuristic.
// Not a security guarantee. Just reduces casual curl/script hammering.
function looksLikeBrowser(request) {
  const ua = request.headers.get("user-agent") || "";
  const accept = request.headers.get("accept") || "";
  const secFetchSite = request.headers.get("sec-fetch-site") || "";

  // Browser UAs are messy, but empty UA is very suspicious.
  if (!ua || ua.length < 8) return false;

  // Most browsers send Accept with text/html or */*.
  if (!accept) return false;

  // sec-fetch-site is modern browser-y, but not universal.
  // If present and says "none" or "same-origin" or "same-site", that is a good sign.
  if (secFetchSite && !["none", "same-origin", "same-site", "cross-site"].includes(secFetchSite)) {
    return false;
  }

  return true;
}

function jsonResponse(body, { status = 200, allowedOrigin = "", setCookies = [] } = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(allowedOrigin ? { "Access-Control-Allow-Origin": allowedOrigin } : {}),
  };

  // Support multiple Set-Cookie headers
  if (setCookies.length === 1) headers["Set-Cookie"] = setCookies[0];
  // Netlify supports multiValueHeaders via a different shape, but Response supports multiple headers entries.
  // We'll append via headers array by using Headers object below.
  const h = new Headers(headers);
  for (let i = 0; i < setCookies.length; i++) {
    h.append("Set-Cookie", setCookies[i]);
  }

  return new Response(JSON.stringify(body), { status, headers: h });
}

// --------- Main handler ----------
export default async (request, context) => {
  const allowedOrigin = getAllowedOrigin(request);

  // CORS preflight
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        ...(allowedOrigin ? { "Access-Control-Allow-Origin": allowedOrigin } : {}),
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // Block disallowed browser origins
  const requestOrigin = request.headers.get("origin");
  if (requestOrigin && !allowedOrigin) {
    return jsonResponse({ error: "CORS blocked" }, { status: 403 });
  }

  if (request.method !== "POST") {
    return jsonResponse({ error: "Use POST" }, { status: 405, allowedOrigin });
  }

  // Optional: reject obvious non-browser requests
  // If you want to allow curl while testing, set BGPT_REQUIRE_BROWSER=false in env.
  const requireBrowser = (process.env.BGPT_REQUIRE_BROWSER ?? "true") === "true";
  if (requireBrowser && !looksLikeBrowser(request)) {
    return jsonResponse({ error: "Browser required" }, { status: 403, allowedOrigin });
  }

  // Parse body
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON" }, { status: 400, allowedOrigin });
  }

  // ---- 1) Reject empty messages ----
  const raw = String(body?.message ?? "");
  const message = raw.trim().slice(0, MAX_MESSAGE_CHARS);
  if (!message) {
    return jsonResponse({ error: "Empty message" }, { status: 400, allowedOrigin });
  }

  // ---- 2) Reject very frequent requests (browser cooldown cookie) ----
  // This is per-browser-session, not per-IP. It is simple and helps prevent accidental rapid-fire usage.
  // Determined attackers can bypass it, but it reduces casual abuse and double-clicks.
  const secret = requireEnv("BGPT_COOKIE_SECRET");

  const cookies = parseCookies(request.headers.get("cookie") || "");

  // Ensure session cookie exists (helps track a browser without storing server state)
  let sess = cookies[COOKIE_SESSION];
  const newCookies = [];

  if (!sess) {
    sess = crypto.randomBytes(16).toString("hex");
    newCookies.push(
      setCookie(COOKIE_SESSION, sess, {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        maxAge: 60 * 60 * 24 * 30, // 30 days
      })
    );
  }

  // Read cooldown token
  const cdToken = cookies[COOKIE_COOLDOWN];
  const cd = readSignedToken(cdToken, secret);

  const now = nowMs();
  if (cd && cd.sess === sess && typeof cd.nextAllowedMs === "number") {
    if (now < cd.nextAllowedMs) {
      const waitMs = cd.nextAllowedMs - now;
      return jsonResponse(
        { error: "Too many requests", retry_after_ms: waitMs },
        { status: 429, allowedOrigin, setCookies: newCookies }
      );
    }
  }

  // Set next cooldown token
  const nextAllowedMs = now + COOLDOWN_MS;
  const nextToken = makeSignedToken({ sess, nextAllowedMs }, secret);
  newCookies.push(
    setCookie(COOKIE_COOLDOWN, nextToken, {
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      maxAge: 60 * 60, // 1 hour
    })
  );

  // ---- OpenAI call (your existing logic, kept minimal) ----
  if (!process.env.OPENAI_API_KEY) {
    return jsonResponse(
      { error: "Missing OPENAI_API_KEY" },
      { status: 500, allowedOrigin, setCookies: newCookies }
    );
  }

  const system = [
    "You are a conversational representation of Ben for a public website.",
    "Answer only with professional, public information.",
    "Use the provided FACTS as the sole source of truth. Do not rely on prior knowledge.",
    "Do not invent facts about Ben. If you do not know, say you do not know.",
    "Do not provide private personal details.",
    "Keep responses concise unless the user asks for depth.",
  ].join(" ");

  try {
    const resp = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4.1-mini",
        input: [
          { role: "system", content: system },
          { role: "system", content: benFacts },
          { role: "user", content: message },
        ],
      }),
    });

    if (!resp.ok) {
      const errText = await resp.text();
      return jsonResponse(
        { error: "OpenAI error", details: errText },
        { status: 502, allowedOrigin, setCookies: newCookies }
      );
    }

    const data = await resp.json();

    const answer =
      data.output_text ||
      data.output?.map(o => o.content?.map(c => c.text).join("")).join("\n") ||
      "No text returned.";

    return jsonResponse(
      { answer },
      { status: 200, allowedOrigin, setCookies: newCookies }
    );
  } catch (e) {
    return jsonResponse(
      { error: "Server error", details: String(e) },
      { status: 500, allowedOrigin, setCookies: newCookies }
    );
  }
};
