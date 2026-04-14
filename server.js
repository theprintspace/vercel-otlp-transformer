const http = require("node:http");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 3000);
const SIGNOZ_OTLP_URL = process.env.SIGNOZ_OTLP_URL || "https://otel-collector-production-dcf9.up.railway.app/v1/logs";
const SIGNOZ_INGEST_TOKEN = process.env.SIGNOZ_INGEST_TOKEN || "";
const VERCEL_VERIFY_TOKEN = process.env.VERCEL_VERIFY_TOKEN || "";
const VERCEL_LOG_DRAIN_SECRET = process.env.VERCEL_LOG_DRAIN_SECRET || "";

if (!SIGNOZ_INGEST_TOKEN) {
  console.error("missing SIGNOZ_INGEST_TOKEN");
  process.exit(1);
}

const SEVERITY_NUMBER = { trace: 1, debug: 5, info: 9, notice: 10, warn: 13, warning: 13, error: 17, fatal: 21, critical: 21 };

function severityNumberOf(level) {
  if (!level) return 9;
  return SEVERITY_NUMBER[String(level).toLowerCase()] ?? 9;
}

function timestampToNano(ts) {
  if (!ts) return String(Date.now() * 1_000_000);
  if (typeof ts === "number") {
    return String(ts < 1e12 ? ts * 1_000_000_000 : ts * 1_000_000);
  }
  const d = Date.parse(ts);
  return Number.isNaN(d) ? String(Date.now() * 1_000_000) : String(d * 1_000_000);
}

function attrsFrom(obj) {
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue;
    if (typeof v === "string") out.push({ key: k, value: { stringValue: v } });
    else if (typeof v === "number") out.push({ key: k, value: Number.isInteger(v) ? { intValue: String(v) } : { doubleValue: v } });
    else if (typeof v === "boolean") out.push({ key: k, value: { boolValue: v } });
    else out.push({ key: k, value: { stringValue: JSON.stringify(v) } });
  }
  return out;
}

function vercelEntryToOtlpRecord(entry) {
  const body = entry.message ?? entry.payload?.text ?? entry.payload?.message ?? JSON.stringify(entry);
  const attrs = {
    "vercel.id": entry.id,
    "vercel.source": entry.source,
    "vercel.type": entry.type,
    "vercel.host": entry.host,
    "vercel.path": entry.path,
    "vercel.method": entry.method,
    "vercel.statusCode": entry.statusCode,
    "vercel.requestId": entry.requestId,
    "vercel.proxy.region": entry.proxy?.region,
    "vercel.proxy.statusCode": entry.proxy?.statusCode,
    "vercel.proxy.userAgent": Array.isArray(entry.proxy?.userAgent) ? entry.proxy.userAgent.join(" ") : entry.proxy?.userAgent,
    "vercel.entrypoint": entry.entrypoint,
    "vercel.executionRegion": entry.executionRegion,
    "vercel.environment": entry.environment,
    "vercel.branch": entry.branch,
  };
  return {
    timeUnixNano: timestampToNano(entry.timestamp),
    observedTimeUnixNano: String(Date.now() * 1_000_000),
    severityNumber: severityNumberOf(entry.level),
    severityText: entry.level || "INFO",
    body: { stringValue: typeof body === "string" ? body : JSON.stringify(body) },
    attributes: attrsFrom(attrs),
  };
}

function groupByResource(entries) {
  const groups = new Map();
  for (const e of entries) {
    const projectId = e.projectId || "unknown";
    const projectName = e.projectName || projectId;
    const env = e.environment || "production";
    const key = `${projectId}|${env}`;
    if (!groups.has(key)) {
      groups.set(key, {
        resource: {
          attributes: attrsFrom({
            "service.name": projectName,
            "service.namespace": "vercel",
            "vercel.projectId": projectId,
            "vercel.deploymentId": e.deploymentId,
            "deployment.environment": env,
          }),
        },
        scopeLogs: [{ scope: { name: "vercel-log-drain" }, logRecords: [] }],
      });
    }
    groups.get(key).scopeLogs[0].logRecords.push(vercelEntryToOtlpRecord(e));
  }
  return Array.from(groups.values());
}

function parseBody(buf, contentType) {
  const text = buf.toString("utf8").trim();
  if (!text) return [];
  if (contentType?.includes("application/x-ndjson") || text.includes("\n")) {
    return text.split("\n").filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
  }
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }
}

async function forwardToSignoz(payload) {
  const res = await fetch(SIGNOZ_OTLP_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${SIGNOZ_INGEST_TOKEN}`,
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OTLP ${res.status}: ${text.slice(0, 500)}`);
  }
}

const server = http.createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  if ((req.method === "GET" || req.method === "HEAD") && req.url?.startsWith("/vercel")) {
    const incoming = req.headers["x-vercel-verify"];
    const verify = (typeof incoming === "string" && incoming) || VERCEL_VERIFY_TOKEN || "ok";
    res.writeHead(200, { "x-vercel-verify": verify, "Content-Type": "text/plain" });
    res.end(verify);
    return;
  }

  if (req.method === "POST" && req.url?.startsWith("/vercel")) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const buf = Buffer.concat(chunks);

    if (VERCEL_LOG_DRAIN_SECRET) {
      const sig = req.headers["x-vercel-signature"];
      if (!sig) {
        res.writeHead(401);
        res.end("missing signature");
        return;
      }
      const expected = crypto.createHmac("sha1", VERCEL_LOG_DRAIN_SECRET).update(buf).digest("hex");
      if (sig !== expected) {
        res.writeHead(401);
        res.end("bad signature");
        return;
      }
    }

    const entries = parseBody(buf, req.headers["content-type"]);
    if (entries.length === 0) {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      await forwardToSignoz({ resourceLogs: groupByResource(entries) });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ accepted: entries.length }));
    } catch (err) {
      console.error("forward failed:", err.message);
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  res.writeHead(404);
  res.end("not found");
});

server.listen(PORT, () => {
  console.log(`vercel-otlp-transformer listening on :${PORT}`);
});
