/**
 * Phase 12 — Artifact API contract + frontend-boundary tests.
 *
 * Coverage:
 *  1. GET /api/health          — response shape, security headers
 *  2. GET /api/forge/session   — response shape, CSRF cookie, security headers
 *  3. GET /api/forge/artifacts — response shape, artifact metadata, security headers
 *  4. Surface boundary         — paths outside the allowed surface return 404
 *                                (or redirect for browser HTML requests)
 *
 * These tests do NOT call the conversion backend (Python); they exercise only
 * the pure-TypeScript routes and the middleware boundary logic.
 */

import { expect, test } from "@playwright/test"

// ── /api/health ──────────────────────────────────────────────────────────────

test.describe("GET /api/health — contract", () => {
  test("returns 200 with expected JSON shape", async ({ request }) => {
    const response = await request.get("/api/health")

    expect(response.status()).toBe(200)

    const body = (await response.json()) as unknown
    const payload = body as Record<string, unknown>
    expect(payload.ok).toBe(true)
    expect(typeof payload.service).toBe("string")
    expect(typeof payload.version).toBe("string")
    expect((payload.service as string).length).toBeGreaterThan(0)
    expect((payload.version as string).length).toBeGreaterThan(0)
  })

  test("sets Cache-Control: no-store", async ({ request }) => {
    const response = await request.get("/api/health")

    expect(response.headers()["cache-control"]).toBe("no-store")
  })
})

// ── /api/forge/session ───────────────────────────────────────────────────────

test.describe("GET /api/forge/session — contract", () => {
  test("returns 200 with a CSRF token and rate-limit metadata", async ({ request }) => {
    const response = await request.get("/api/forge/session")

    expect(response.status()).toBe(200)

    const payload = (await response.json()) as Record<string, unknown>
    expect(typeof payload.csrfToken).toBe("string")
    expect((payload.csrfToken as string).length).toBeGreaterThanOrEqual(32)
    expect(typeof payload.expiresInSeconds).toBe("number")
    expect((payload.expiresInSeconds as number)).toBeGreaterThan(0)

    const rateLimit = payload.rateLimit as Record<string, unknown>
    expect(typeof rateLimit.limit).toBe("number")
    expect(typeof rateLimit.windowSeconds).toBe("number")
    expect((rateLimit.limit as number)).toBeGreaterThan(0)
    expect((rateLimit.windowSeconds as number)).toBeGreaterThan(0)
  })

  test("sets Cache-Control: no-store", async ({ request }) => {
    const response = await request.get("/api/forge/session")

    expect(response.headers()["cache-control"]).toBe("no-store")
  })

  test("sets the logan_forge_csrf cookie", async ({ request }) => {
    const response = await request.get("/api/forge/session")

    expect(response.status()).toBe(200)
    const setCookieHeader = response.headers()["set-cookie"]
    expect(setCookieHeader).toBeDefined()
    expect(setCookieHeader).toContain("logan_forge_csrf")
    expect(setCookieHeader).toContain("HttpOnly")
    // Next.js serialises SameSite=lax (lowercase); match case-insensitively.
    expect(setCookieHeader.toLowerCase()).toContain("samesite=lax")
  })

  test("returns the same token when the cookie already exists", async ({ request }) => {
    const first = await request.get("/api/forge/session")
    const { csrfToken: token1 } = (await first.json()) as { csrfToken: string }

    const second = await request.get("/api/forge/session")
    const { csrfToken: token2 } = (await second.json()) as { csrfToken: string }

    // The second call re-uses the cookie set by the first.
    expect(token1).toBe(token2)
  })
})

// ── /api/forge/artifacts ─────────────────────────────────────────────────────

test.describe("GET /api/forge/artifacts — contract", () => {
  test("returns 200 with artifact metadata", async ({ request }) => {
    const response = await request.get("/api/forge/artifacts")

    expect(response.status()).toBe(200)

    const payload = (await response.json()) as Record<string, unknown>

    // generatedAt is either a string or null
    expect(
      payload.generatedAt === null || typeof payload.generatedAt === "string",
    ).toBe(true)

    // errors is an array of strings
    expect(Array.isArray(payload.errors)).toBe(true)

    // statuses is an array of status objects
    expect(Array.isArray(payload.statuses)).toBe(true)
    const statuses = payload.statuses as Array<Record<string, unknown>>
    for (const status of statuses) {
      expect(typeof status.key).toBe("string")
      expect(typeof status.label).toBe("string")
      expect(typeof status.relativePath).toBe("string")
      expect(typeof status.ok).toBe("boolean")
    }

    // item counts are non-negative integers
    expect(typeof payload.examplesCount).toBe("number")
    expect(typeof payload.patternsCount).toBe("number")
    expect(typeof payload.commandsCount).toBe("number")
    expect(payload.examplesCount as number).toBeGreaterThanOrEqual(0)
    expect(payload.patternsCount as number).toBeGreaterThanOrEqual(0)
    expect(payload.commandsCount as number).toBeGreaterThanOrEqual(0)
  })

  test("reports all four expected artifact keys in statuses", async ({ request }) => {
    const response = await request.get("/api/forge/artifacts")
    const payload = (await response.json()) as { statuses: Array<{ key: string }> }

    const keys = payload.statuses.map((status) => status.key).sort()
    expect(keys).toContain("referenceCatalog")
    expect(keys).toContain("mappingPatterns")
    expect(keys).toContain("conversionExamples")
    expect(keys).toContain("capabilityMatrix")
  })

  test("sets Cache-Control: no-store", async ({ request }) => {
    const response = await request.get("/api/forge/artifacts")

    expect(response.headers()["cache-control"]).toBe("no-store")
  })

  test("artifact counts are positive when artifacts are present", async ({ request }) => {
    const response = await request.get("/api/forge/artifacts")
    const payload = (await response.json()) as {
      errors: string[]
      examplesCount: number
      patternsCount: number
      commandsCount: number
    }

    // If there are no errors, every count should be positive.
    if (payload.errors.length === 0) {
      expect(payload.examplesCount).toBeGreaterThan(0)
      expect(payload.patternsCount).toBeGreaterThan(0)
      expect(payload.commandsCount).toBeGreaterThan(0)
    }
  })
})

// ── Exposed-surface boundary ─────────────────────────────────────────────────

test.describe("Exposed-surface boundary — middleware enforcement", () => {
  test("GET /forge returns 200 (on the allowed surface)", async ({ request }) => {
    const response = await request.get("/forge")
    // The page route should succeed, even if it renders a shell.
    expect(response.status()).toBe(200)
  })

  test("GET /api/nonexistent returns 404 (middleware blocks it)", async ({ request }) => {
    const response = await request.get("/api/nonexistent-route-that-does-not-exist")
    expect(response.status()).toBe(404)
  })

  test("GET /api/v1/queries returns 404 (not on the allowed surface)", async ({ request }) => {
    const response = await request.get("/api/v1/queries")
    expect(response.status()).toBe(404)
  })

  test("GET /api/forge (no trailing slash) returns 404 (no such route)", async ({ request }) => {
    // /api/forge without a trailing slash is not a registered route; Next.js returns 404.
    const response = await request.get("/api/forge")
    expect(response.status()).toBe(404)
  })

  test("GET /admin returns 404 for non-HTML requests (middleware blocks it)", async ({ request }) => {
    const response = await request.get("/admin")
    expect(response.status()).toBe(404)
  })

  test("GET / redirects to /forge for HTML requests (middleware redirect)", async ({ page }) => {
    await page.goto("/")
    expect(page.url()).toContain("/forge")
  })

  test("GET /api/forge/artifacts and /api/forge/session are on the allowed surface", async ({ request }) => {
    // Both must return something other than 404; the middleware must pass them through.
    const [artifactsResponse, sessionResponse] = await Promise.all([
      request.get("/api/forge/artifacts"),
      request.get("/api/forge/session"),
    ])
    expect(artifactsResponse.status()).not.toBe(404)
    expect(sessionResponse.status()).not.toBe(404)
  })

  test("POST /api/forge/convert without CSRF returns 403 (not a bypass path)", async ({ request }) => {
    // The route is on the allowed surface but CSRF enforcement is still active.
    const response = await request.post("/api/forge/convert", {
      data: { sourceLanguage: "sentinel_kql", sourceQuery: "SecurityEvent | take 1" },
    })
    expect(response.status()).toBe(403)
  })
})
