"use client"

import { useSearchParams } from "next/navigation"

import { DeploymentWorkspace } from "@/components/deployment/deployment-workspace"
import { LogSamplesWorkspace } from "@/components/log-samples/log-samples-workspace"
import type { DeploymentContentSummary } from "@/lib/deployment-content"
import { ForgeWorkbench } from "@/components/logan-workbench/forge-workbench"
import type {
  LoganCommand,
  LoganConversionExample,
  LoganMappingPattern,
  WorkbenchArtifactReadStatus,
} from "@/lib/logan-workbench-artifacts"
import type { SiemLogExamplesCatalog } from "@/lib/siem-log-examples-contract"

interface ForgeSurfaceProps {
  commands: LoganCommand[]
  patterns: LoganMappingPattern[]
  examples: LoganConversionExample[]
  statuses: WorkbenchArtifactReadStatus[]
  generatedAt: string | null
  siemCatalog: SiemLogExamplesCatalog | null
  siemError: string | null
  deploymentSummary: DeploymentContentSummary | null
  deploymentError: string | null
}

export function ForgeSurface({
  commands,
  patterns,
  examples,
  statuses,
  generatedAt,
  siemCatalog,
  siemError,
  deploymentSummary,
  deploymentError,
}: ForgeSurfaceProps) {
  const searchParams = useSearchParams()
  const view = searchParams.get("view")

  if (view === "log-samples") {
    return <LogSamplesWorkspace catalog={siemCatalog} error={siemError} />
  }

  if (view === "deployment") {
    return <DeploymentWorkspace summary={deploymentSummary} error={deploymentError} />
  }

  return (
    <ForgeWorkbench
      commands={commands}
      patterns={patterns}
      examples={examples}
      statuses={statuses}
      generatedAt={generatedAt}
    />
  )
}
