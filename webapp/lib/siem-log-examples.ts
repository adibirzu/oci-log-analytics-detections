import "server-only"

import path from "node:path"
import { readFile } from "node:fs/promises"
import { cache } from "react"

import {
  parseSiemLogExamples,
  type SiemLogExamplesCatalog,
} from "@/lib/siem-log-examples-contract"

const detectionsRepoPath = process.env.LOGAN_DETECTIONS_REPO
  ? path.resolve(process.env.LOGAN_DETECTIONS_REPO)
  : path.resolve(process.cwd(), "..")

export interface SiemLogExamplesResult {
  catalog: SiemLogExamplesCatalog | null
  error: string | null
}

export const getSiemLogExamples = cache(async (): Promise<SiemLogExamplesResult> => {
  try {
    const artifactPath = path.join(detectionsRepoPath, "queries", "siem_log_examples.json")
    const contents = await readFile(artifactPath, "utf8")
    return { catalog: parseSiemLogExamples(JSON.parse(contents)), error: null }
  } catch {
    return { catalog: null, error: "SIEM log sample artifact is unavailable or invalid." }
  }
})
