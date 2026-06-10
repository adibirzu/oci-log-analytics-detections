/**
 * GET /api/forge/artifacts
 *
 * Returns lightweight metadata about the repo-generated workbench artifacts:
 * file availability, schema-validation status, generation timestamp, and
 * item counts. The full artifact arrays (examples, patterns, commands) are
 * served to the Forge page via server-side rendering and are NOT duplicated
 * here to avoid large JSON responses over this route.
 *
 * Intended uses:
 *  - Frontend health badges ("Artifact contract valid / degraded")
 *  - Monitoring / readiness probes that don't need the full page load
 *  - Client-side polling for artifact-refresh events
 */

import { NextResponse } from "next/server"
import { getLoganWorkbenchArtifacts } from "@/lib/logan-workbench-artifacts"
import { artifactsResponseSchema, type ArtifactsResponse } from "@/lib/api-contracts"

export const runtime = "nodejs"

export async function GET() {
  const artifacts = await getLoganWorkbenchArtifacts()

  const body: ArtifactsResponse = artifactsResponseSchema.parse({
    generatedAt: artifacts.generatedAt,
    errors: artifacts.errors,
    statuses: artifacts.statuses,
    examplesCount: artifacts.examples.length,
    patternsCount: artifacts.patterns.length,
    commandsCount: artifacts.commands.length,
  })

  return NextResponse.json(body, {
    headers: {
      "Cache-Control": "no-store",
    },
  })
}
