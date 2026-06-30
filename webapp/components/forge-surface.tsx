"use client"

import { useSearchParams } from "next/navigation"

import { LogSamplesWorkspace } from "@/components/log-samples/log-samples-workspace"
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
}

export function ForgeSurface({
  commands,
  patterns,
  examples,
  statuses,
  generatedAt,
  siemCatalog,
  siemError,
}: ForgeSurfaceProps) {
  const searchParams = useSearchParams()
  const view = searchParams.get("view")

  if (view === "log-samples") {
    return <LogSamplesWorkspace catalog={siemCatalog} error={siemError} />
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
