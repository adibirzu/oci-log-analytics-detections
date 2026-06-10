import { NextResponse } from "next/server"
import type { HealthResponse } from "@/lib/api-contracts"

export const runtime = "nodejs"

export async function GET() {
  const body: HealthResponse = {
    ok: true,
    service: "logan-forge-frontend",
    version: process.env.NEXT_PUBLIC_APP_VERSION ?? "0.1.0",
  }
  return NextResponse.json(body, {
    headers: {
      "Cache-Control": "no-store",
    },
  })
}
