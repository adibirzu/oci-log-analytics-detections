import { ForgeWorkbench } from "@/components/logan-workbench/forge-workbench"
import { getLoganWorkbenchArtifacts } from "@/lib/logan-workbench-artifacts"

export default async function ForgePage() {
  const artifacts = await getLoganWorkbenchArtifacts()

  return (
    <ForgeWorkbench
      commands={artifacts.commands}
      patterns={artifacts.patterns}
      examples={artifacts.examples}
      statuses={artifacts.statuses}
      generatedAt={artifacts.generatedAt}
    />
  )
}
