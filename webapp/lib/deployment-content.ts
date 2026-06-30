import "server-only"

import path from "node:path"
import { readFile } from "node:fs/promises"
import { cache } from "react"
import { z } from "zod"

const detectionsRepoPath = process.env.LOGAN_DETECTIONS_REPO
  ? path.resolve(process.env.LOGAN_DETECTIONS_REPO)
  : path.resolve(process.cwd(), "..")

const catalogSchema = z.object({
  total_rules: z.number().int().nonnegative(),
  total_content_items: z.number().int().nonnegative(),
})

const dashboardInventorySchema = z.object({
  summary: z.object({
    total_dashboards: z.number().int().nonnegative(),
    total_widgets: z.number().int().nonnegative(),
  }),
})

export interface DeploymentContentSummary {
  rules: number
  contentItems: number
  dashboards: number
  savedSearches: number
}

export interface DeploymentContentResult {
  summary: DeploymentContentSummary | null
  error: string | null
}

export const getDeploymentContent = cache(async (): Promise<DeploymentContentResult> => {
  try {
    const [catalogContents, dashboardContents] = await Promise.all([
      readFile(path.join(detectionsRepoPath, "queries", "catalog.json"), "utf8"),
      readFile(path.join(detectionsRepoPath, "queries", "dashboard_inventory.json"), "utf8"),
    ])
    const catalog = catalogSchema.parse(JSON.parse(catalogContents))
    const dashboards = dashboardInventorySchema.parse(JSON.parse(dashboardContents))

    return {
      summary: {
        rules: catalog.total_rules,
        contentItems: catalog.total_content_items,
        dashboards: dashboards.summary.total_dashboards,
        savedSearches: dashboards.summary.total_widgets,
      },
      error: null,
    }
  } catch {
    return { summary: null, error: "Deployment inventory is unavailable or invalid." }
  }
})
