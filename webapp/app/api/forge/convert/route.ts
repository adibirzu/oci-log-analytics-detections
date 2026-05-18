import { spawn } from "node:child_process"
import path from "node:path"
import { NextRequest, NextResponse } from "next/server"
import { z } from "zod"

export const runtime = "nodejs"

const MAX_QUERY_CHARS = 20_000
const RATE_LIMIT = 30
const RATE_WINDOW_MS = 60_000
const CONVERSION_TIMEOUT_MS = 12_000

const conversionRequestSchema = z
  .object({
    sourceLanguage: z.enum(["sigma_yaml", "sentinel_kql", "splunk_spl", "elastic_lucene", "elastic_eql", "oci_logan"]),
    sourceQuery: z.string().min(1).max(MAX_QUERY_CHARS),
    readOnly: z.boolean().optional().default(true),
    exampleId: z.string().max(160).optional(),
  })
  .strict()

const warningSchema = z.object({
  code: z.string(),
  message: z.string(),
  severity: z.enum(["info", "warning", "error"]),
})

const conversionResponseSchema = z
  .object({
    schema_version: z.literal("1.0.0"),
    generated_at: z.string(),
    source_language: z.string().optional(),
    source_query: z.string().optional(),
    logan_query: z.string(),
    support_level: z.enum(["supported", "partial", "lossy", "unsupported"]),
    explanation: z.string(),
    warnings: z.array(warningSchema),
    metadata: z.record(z.unknown()),
    backend: z.string(),
  })
  .passthrough()

interface Bucket {
  resetAt: number
  count: number
}

const buckets = new Map<string, Bucket>()

function getClientKey(request: NextRequest): string {
  const forwardedFor = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
  return forwardedFor || request.headers.get("x-real-ip") || "local"
}

function rateLimit(request: NextRequest) {
  const key = getClientKey(request)
  const now = Date.now()
  const current = buckets.get(key)
  const bucket = current && current.resetAt > now ? current : { resetAt: now + RATE_WINDOW_MS, count: 0 }
  const nextBucket = { ...bucket, count: bucket.count + 1 }
  buckets.set(key, nextBucket)
  const remaining = Math.max(0, RATE_LIMIT - nextBucket.count)
  return {
    allowed: nextBucket.count <= RATE_LIMIT,
    remaining,
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

  const configured = (process.env.FORGE_ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)

  return origin === sameOrigin || configured.includes(origin)
}

function verifyCsrf(request: NextRequest): boolean {
  const cookieToken = request.cookies.get("logan_forge_csrf")?.value
  const headerToken = request.headers.get("x-logan-forge-csrf")
  return Boolean(cookieToken && headerToken && cookieToken === headerToken)
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
  return {
    ...response,
    backend: response.backend === "scripts/logan_workbench_convert.py" ? "Bundled read-only converter" : "Logan Forge API",
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
