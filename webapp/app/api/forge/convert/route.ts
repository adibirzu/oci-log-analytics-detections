import { spawn } from "node:child_process"
import path from "node:path"
import { NextRequest, NextResponse } from "next/server"
import { z } from "zod"
import { conversionRequestSchema, conversionResponseSchema } from "@/lib/api-contracts"

export const runtime = "nodejs"

const RATE_LIMIT = 30
const RATE_WINDOW_MS = 60_000
// Trusting X-Forwarded-For for rate limiting is OPT-IN. FORGE_TRUSTED_PROXY_HOPS
// is the number of trusted reverse-proxy hops (e.g. OCI LB + ingress) that append
// to X-Forwarded-For in front of this app; the trusted client IP is the entry that
// many positions from the RIGHT of the chain. When the variable is unset or invalid
// it resolves to 0, meaning X-Forwarded-For is NOT trusted at all and every request
// shares one bucket (fail-closed) — so a caller cannot mint fresh rate-limit buckets
// by sending spoofed headers when no trusted proxy depth has been declared.
const RATE_TRUSTED_PROXY_HOPS = (() => {
  // Strict parse: only a clean, whole, non-negative integer string enables
  // X-Forwarded-For trust. Number.parseInt is lenient ("1abc" -> 1, "1.9" -> 1,
  // "0x2" handling, etc.), so a malformed value must NOT silently turn on trust —
  // anything that is not exactly digits resolves to 0 (fail-closed).
  const raw = (process.env.FORGE_TRUSTED_PROXY_HOPS ?? "").trim()
  if (!/^\d+$/.test(raw)) {
    return 0
  }
  const parsed = Number.parseInt(raw, 10)
  return Number.isFinite(parsed) && parsed >= 1 ? parsed : 0
})()
const CONVERSION_TIMEOUT_MS = 12_000
const CSRF_TOKEN_PATTERN = /^[A-Za-z0-9_-]{32,256}$/
const BUNDLED_CONVERTER_SCRIPT = "scripts/logan_workbench_convert.py"

// conversionRequestSchema and conversionResponseSchema are imported from
// @/lib/api-contracts — they are the single source of truth for these shapes.

interface Bucket {
  resetAt: number
  count: number
}

const buckets = new Map<string, Bucket>()
// Upper bound on distinct rate-limit buckets retained in memory. Without a bound
// the map would grow indefinitely as new client keys appear (a slow
// memory-exhaustion DoS). When the table is full we reclaim memory ONLY from
// buckets whose window has already expired; we never evict an active bucket,
// because resetting a live counter would let an abuser wash out their own limit by
// churning the table with new keys. If the table is still full of active windows a
// new client is denied (fail closed) instead.
const MAX_TRACKED_CLIENTS = 10_000

function commaSeparatedList(value: string | undefined): string[] {
  return (value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
}

function trustedInternalHosts(): string[] {
  return commaSeparatedList(process.env.FORGE_TRUSTED_INTERNAL_HOSTS).map((value) => value.toLowerCase())
}

function hostMatchesTrustedInternalHost(host: string | null): boolean {
  if (!host) {
    return false
  }

  const normalizedHost = host.toLowerCase().split(":")[0]
  return trustedInternalHosts().includes(normalizedHost)
}

function originMatchesTrustedInternalHost(origin: string): boolean {
  try {
    const parsed = new URL(origin)
    return hostMatchesTrustedInternalHost(parsed.hostname)
  } catch {
    return false
  }
}

function isTrustedInternalRequest(request: NextRequest): boolean {
  return hostMatchesTrustedInternalHost(request.headers.get("host")) || hostMatchesTrustedInternalHost(request.headers.get("x-forwarded-host"))
}

function getClientKey(request: NextRequest): string {
  // SECURITY: X-Forwarded-For is "client, proxy1, ..., edgeProxy" and every entry
  // to the LEFT of the address our own trusted proxy appended is attacker-supplied
  // and trivially spoofable. We therefore trust X-Forwarded-For ONLY when the
  // deployment has explicitly declared its trusted-proxy depth
  // (FORGE_TRUSTED_PROXY_HOPS >= 1), and then key strictly on the entry that many
  // positions from the RIGHT — the address our proxy inserted, which a client
  // cannot influence by prepending spoofed values. With no declared proxy depth,
  // or a chain shorter than that depth, we FAIL CLOSED to a single shared bucket
  // rather than trust client-controlled input, so the limit cannot be bypassed by
  // spoofing headers.
  if (RATE_TRUSTED_PROXY_HOPS < 1) {
    return "shared"
  }
  const chain = (request.headers.get("x-forwarded-for") ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
  if (chain.length >= RATE_TRUSTED_PROXY_HOPS) {
    return chain[chain.length - RATE_TRUSTED_PROXY_HOPS]
  }
  return "shared"
}

function rateLimit(request: NextRequest) {
  const key = getClientKey(request)
  const now = Date.now()
  const current = buckets.get(key)

  // Known client with an active window: increment its existing bucket. Active
  // buckets are never evicted, so an abuser cannot reset their own counter by
  // flooding the table with new keys.
  if (current && current.resetAt > now) {
    const nextBucket = { resetAt: current.resetAt, count: current.count + 1 }
    buckets.set(key, nextBucket)
    return {
      allowed: nextBucket.count <= RATE_LIMIT,
      remaining: Math.max(0, RATE_LIMIT - nextBucket.count),
      resetSeconds: Math.max(1, Math.ceil((nextBucket.resetAt - now) / 1000)),
    }
  }

  // A new (or expired) client needs a fresh bucket. Reclaim memory from expired
  // windows first so the common case stays well under the cap.
  if (buckets.size >= MAX_TRACKED_CLIENTS) {
    for (const [trackedKey, trackedBucket] of buckets) {
      if (trackedBucket.resetAt <= now) {
        buckets.delete(trackedKey)
      }
    }
  }

  // If the table is still full of active windows, refuse to start tracking a new
  // client rather than evict (and thereby reset) an active limit. This bounds
  // memory and fails closed instead of handing out a fresh allowance under churn.
  if (buckets.size >= MAX_TRACKED_CLIENTS) {
    return {
      allowed: false,
      remaining: 0,
      resetSeconds: Math.ceil(RATE_WINDOW_MS / 1000),
    }
  }

  const nextBucket = { resetAt: now + RATE_WINDOW_MS, count: 1 }
  buckets.set(key, nextBucket)
  return {
    allowed: nextBucket.count <= RATE_LIMIT,
    remaining: Math.max(0, RATE_LIMIT - nextBucket.count),
    resetSeconds: Math.max(1, Math.ceil((nextBucket.resetAt - now) / 1000)),
  }
}

function isAllowedOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin")
  if (!origin) {
    return true
  }

  const sameOrigin = request.nextUrl.origin
  if (origin === sameOrigin) {
    return true
  }

  if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(origin)) {
    return process.env.NODE_ENV !== "production"
  }

  const configured = commaSeparatedList(process.env.FORGE_ALLOWED_ORIGINS)

  return origin === sameOrigin || configured.includes(origin) || originMatchesTrustedInternalHost(origin)
}

function verifyCsrf(request: NextRequest): boolean {
  const cookieToken = request.cookies.get("logan_forge_csrf")?.value
  const headerToken = request.headers.get("x-logan-forge-csrf")
  if (!headerToken || !CSRF_TOKEN_PATTERN.test(headerToken)) {
    return false
  }
  if (cookieToken) {
    return cookieToken === headerToken
  }

  const secFetchSite = request.headers.get("sec-fetch-site")
  return secFetchSite === "same-origin" || secFetchSite === "none" || !secFetchSite || isTrustedInternalRequest(request)
}

function withSecurityHeaders(response: NextResponse, limitState?: ReturnType<typeof rateLimit>) {
  response.headers.set("Cache-Control", "no-store")
  response.headers.set("X-Content-Type-Options", "nosniff")
  if (limitState) {
    response.headers.set("X-RateLimit-Limit", String(RATE_LIMIT))
    response.headers.set("X-RateLimit-Remaining", String(limitState.remaining))
    response.headers.set("X-RateLimit-Reset", String(limitState.resetSeconds))
  }
  return response
}

function jsonError(message: string, status: number, limitState?: ReturnType<typeof rateLimit>) {
  return withSecurityHeaders(
    NextResponse.json(
      {
        error: message,
      },
      { status },
    ),
    limitState,
  )
}

async function proxyToBackend(payload: z.output<typeof conversionRequestSchema>) {
  const backendUrl = process.env.LOGAN_FORGE_BACKEND_URL
  if (!backendUrl) {
    return null
  }
  if (process.env.NODE_ENV === "production" && !backendUrl.startsWith("https://")) {
    throw new Error("LOGAN_FORGE_BACKEND_URL must use https in production")
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), CONVERSION_TIMEOUT_MS)
  try {
    const response = await fetch(backendUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(process.env.LOGAN_FORGE_BACKEND_TOKEN
          ? { Authorization: `Bearer ${process.env.LOGAN_FORGE_BACKEND_TOKEN}` }
          : {}),
      },
      body: JSON.stringify({
        source_language: payload.sourceLanguage,
        source_query: payload.sourceQuery,
        read_only: payload.readOnly,
        example_id: payload.exampleId,
      }),
      signal: controller.signal,
    })
    const body = await response.json()
    if (!response.ok) {
      throw new Error(`backend conversion failed with ${response.status}`)
    }
    return conversionResponseSchema.parse(body)
  } finally {
    clearTimeout(timeout)
  }
}

function publicConversionResponse(response: z.output<typeof conversionResponseSchema>) {
  const usesBundledScript = response.backend === BUNDLED_CONVERTER_SCRIPT
  return {
    ...response,
    backend: usesBundledScript ? "Bundled read-only converter" : "Logan Forge API",
    metadata: {
      ...response.metadata,
      execution_mode: usesBundledScript ? "bundled_python_script" : "remote_api_gateway",
      ...(usesBundledScript ? { backend_script: BUNDLED_CONVERTER_SCRIPT } : {}),
    },
  }
}

async function runLocalScript(payload: z.output<typeof conversionRequestSchema>) {
  const detectionsRepoPath = process.env.LOGAN_DETECTIONS_REPO
    ? path.resolve(process.env.LOGAN_DETECTIONS_REPO)
    : path.resolve(process.cwd(), "..")
  const scriptPath = path.join(detectionsRepoPath, "scripts", "logan_workbench_convert.py")

  return new Promise<z.output<typeof conversionResponseSchema>>((resolve, reject) => {
    const child = spawn("python3", [scriptPath], {
      cwd: detectionsRepoPath,
      env: {
        PATH: process.env.PATH || "/usr/bin:/bin",
        PYTHONUNBUFFERED: "1",
        NODE_ENV: process.env.NODE_ENV || "production",
      },
    })

    let stdout = ""
    let stderr = ""
    const timeout = setTimeout(() => {
      child.kill("SIGKILL")
      reject(new Error("conversion backend timed out"))
    }, CONVERSION_TIMEOUT_MS)

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8")
    })
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8")
    })
    child.on("error", (error) => {
      clearTimeout(timeout)
      reject(error)
    })
    child.on("close", () => {
      clearTimeout(timeout)
      try {
        const parsed = conversionResponseSchema.parse(JSON.parse(stdout))
        resolve(parsed)
      } catch (error) {
        reject(new Error(stderr.trim() || (error instanceof Error ? error.message : "invalid backend response")))
      }
    })

    child.stdin.write(
      JSON.stringify({
        source_language: payload.sourceLanguage,
        source_query: payload.sourceQuery,
        read_only: payload.readOnly,
        example_id: payload.exampleId,
      }),
    )
    child.stdin.end()
  })
}

export async function POST(request: NextRequest) {
  if (!isAllowedOrigin(request)) {
    return jsonError("origin is not allowed", 403)
  }
  if (!verifyCsrf(request)) {
    return jsonError("csrf token is missing or invalid", 403)
  }

  const limitState = rateLimit(request)
  if (!limitState.allowed) {
    return jsonError("rate limit exceeded", 429, limitState)
  }

  let payload: z.output<typeof conversionRequestSchema>
  try {
    payload = conversionRequestSchema.parse(await request.json())
  } catch {
    return jsonError("invalid conversion request", 400, limitState)
  }

  try {
    const proxied = await proxyToBackend(payload)
    const response = NextResponse.json(publicConversionResponse(proxied ?? (await runLocalScript(payload))))
    return withSecurityHeaders(response, limitState)
  } catch (error) {
    if (process.env.NODE_ENV !== "production") {
      return jsonError(error instanceof Error ? error.message : "conversion backend failed", 502, limitState)
    }
    console.error("Forge conversion failed", error)
    return jsonError("conversion backend failed", 502, limitState)
  }
}
