import { Suspense } from "react"

import { ForgeSurface } from "@/components/forge-surface"
import { getLoganWorkbenchArtifacts } from "@/lib/logan-workbench-artifacts"
import { getSiemLogExamples } from "@/lib/siem-log-examples"

export default async function ForgePage() {
  const [artifacts, siemExamples] = await Promise.all([
    getLoganWorkbenchArtifacts(),
    getSiemLogExamples(),
  ])

  return (
    <Suspense fallback={<div className="min-h-[calc(100vh-60px)] bg-surface-sunken" />}>
      <ForgeSurface
        commands={artifacts.commands}
        patterns={artifacts.patterns}
        examples={artifacts.examples}
        statuses={artifacts.statuses}
        generatedAt={artifacts.generatedAt}
        siemCatalog={siemExamples.catalog}
        siemError={siemExamples.error}
      />
    </Suspense>
  )
}
