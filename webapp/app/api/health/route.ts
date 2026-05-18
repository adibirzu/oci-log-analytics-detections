import { NextResponse } from "next/server"

export const runtime = "nodejs"

export async function GET() {
  return NextResponse.json(
    {
      ok: true,
      service: "logan-forge-frontend",
      version: process.env.NEXT_PUBLIC_APP_VERSION || "0.1.0",
    },
    {
      headers: {
        "Cache-Control": "no-store",
      },
    },
  )
}
