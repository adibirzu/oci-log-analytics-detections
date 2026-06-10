import { randomBytes } from "node:crypto"
import { NextRequest } from "next/server"
import { NextResponse } from "next/server"
import type { SessionResponse } from "@/lib/api-contracts"

export const runtime = "nodejs"

const SESSION_TTL_SECONDS = 15 * 60
const RATE_LIMIT = 30
const RATE_WINDOW_SECONDS = 60

export async function GET(request: NextRequest) {
  const existingToken = request.cookies.get("logan_forge_csrf")?.value
  const csrfToken = existingToken && existingToken.length >= 32 ? existingToken : randomBytes(32).toString("base64url")
  const body: SessionResponse = {
    csrfToken,
    expiresInSeconds: SESSION_TTL_SECONDS,
    rateLimit: {
      limit: RATE_LIMIT,
      windowSeconds: RATE_WINDOW_SECONDS,
    },
  }
  const response = NextResponse.json(body, {
    headers: {
      "Cache-Control": "no-store",
    },
  })

  response.cookies.set({
    name: "logan_forge_csrf",
    value: csrfToken,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/api/forge",
    maxAge: SESSION_TTL_SECONDS,
  })

  return response
}
