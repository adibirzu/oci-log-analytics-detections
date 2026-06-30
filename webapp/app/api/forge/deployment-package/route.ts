/**
 * GET /api/forge/deployment-package
 *
 * Builds a read-only OCI Resource Manager package from committed deployment
 * content. The endpoint accepts no input and never receives OCI credentials or
 * tenancy identifiers; the user authenticates and selects a compartment inside
 * the OCI Resource Manager console.
 */

import { execFile } from "node:child_process"
import { randomUUID } from "node:crypto"
import { readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { promisify } from "node:util"
import { NextResponse } from "next/server"

export const runtime = "nodejs"

const execFileAsync = promisify(execFile)
const detectionsRepoPath = process.env.LOGAN_DETECTIONS_REPO
  ? path.resolve(process.env.LOGAN_DETECTIONS_REPO)
  : path.resolve(process.cwd(), "..")
const packageBuilderPath = path.join(detectionsRepoPath, "scripts", "build_orm_stack.py")
const PACKAGE_CACHE_MS = 5 * 60_000

let cachedPackage: { contents: Buffer; expiresAt: number } | null = null
let packageBuildInFlight: Promise<Buffer> | null = null

async function getDeploymentPackage(): Promise<Buffer> {
  if (cachedPackage && cachedPackage.expiresAt > Date.now()) {
    return cachedPackage.contents
  }
  if (packageBuildInFlight) {
    return packageBuildInFlight
  }

  packageBuildInFlight = (async () => {
    const outputPath = path.join(tmpdir(), `oci-log-analytics-deployment-${randomUUID()}.zip`)
    try {
      await execFileAsync("python3", [packageBuilderPath, "--out", outputPath], {
        cwd: detectionsRepoPath,
        timeout: 30_000,
        maxBuffer: 64 * 1024,
      })
      const contents = await readFile(outputPath)
      cachedPackage = { contents, expiresAt: Date.now() + PACKAGE_CACHE_MS }
      return contents
    } finally {
      await rm(outputPath, { force: true }).catch(() => undefined)
    }
  })()

  try {
    return await packageBuildInFlight
  } finally {
    packageBuildInFlight = null
  }
}

export async function GET() {
  try {
    const packageContents = await getDeploymentPackage()

    return new NextResponse(packageContents, {
      headers: {
        "Cache-Control": "no-store",
        "Content-Disposition": 'attachment; filename="oci-log-analytics-deployment.zip"',
        "Content-Type": "application/zip",
        "X-Content-Type-Options": "nosniff",
      },
    })
  } catch {
    return NextResponse.json(
      { error: "The deployment package is temporarily unavailable." },
      {
        status: 503,
        headers: {
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      },
    )
  }
}
