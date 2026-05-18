import { randomBytes } from "node:crypto"
import { NextResponse } from "next/server"

export const runtime = "nodejs"

const SESSION_TTL_SECONDS = 15 * 60

export async function GET() {
  const csrfToken = randomBytes(32).toString("base64url")
  const response = NextResponse.json(
    {
      csrfToken,
      expiresInSeconds: SESSION_TTL_SECONDS,
      rateLimit: {
        limit: 30,
        windowSeconds: 60,
      },
    },
    {
      headers: {
        "Cache-Control": "no-store",
      },
    },
  )

  response.cookies.set({
    name: "logan_forge_csrf",
    value: csrfToken,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/api/forge",
    maxAge: SESSION_TTL_SECONDS,
  })

  return response
}
