import "server-only"

import path from "node:path"
import { readFile } from "node:fs/promises"
import { cache } from "react"
import { z } from "zod"

const detectionsRepoPath = process.env.LOGAN_DETECTIONS_REPO
  ? path.resolve(process.env.LOGAN_DETECTIONS_REPO)
  : path.resolve(process.cwd(), "..")

const supportLevelSchema = z.enum(["supported", "partial", "lossy", "unsupported"])
const sourceLanguageSchema = z.enum([
  "sigma_yaml",
  "sentinel_kql",
  "splunk_spl",
  "elastic_lucene",
  "elastic_eql",
  "oci_logan",
])

const commandSchema = z
  .object({
    name: z.string(),
    category: z.string(),
    source_url: z.string().url(),
    source_title: z.string().optional().default("OCI Log Analytics"),
    retrieved_at: z.string(),
    summary: z.string(),
    syntax: z.string(),
    examples: z.array(z.string()).optional().default([]),
    notes: z.array(z.string()).optional().default([]),
    provenance: z.record(z.unknown()).optional().default({}),
  })
  .passthrough()

const referenceCatalogSchema = z
  .object({
    schema_version: z.literal("1.0.0"),
    generated_at: z.string(),
    sources: z.array(z.string().url()),
    required_commands: z.array(z.string()),
    commands: z.array(commandSchema),
  })
  .passthrough()

const mappingPatternSchema = z.object({
  id: z.string(),
  source_language: z.string(),
  source_construct: z.string(),
  oci_mapping: z.string(),
  support_level: supportLevelSchema,
  logan_commands: z.array(z.string()),
  warning_behavior: z.string(),
  example_ids: z.array(z.string()),
})

const mappingPatternsSchema = z.object({
  schema_version: z.literal("1.0.0"),
  generated_at: z.string(),
  patterns: z.array(mappingPatternSchema),
})

const conversionExampleSchema = z.object({
  id: z.string(),
  title: z.string(),
  source_language: sourceLanguageSchema,
  source_query: z.string(),
  expected_logan_ql: z.string(),
  explanation: z.string(),
  warnings: z.array(z.string()).optional().default([]),
  support_level: supportLevelSchema,
  synthetic_log_shape: z.string(),
  pattern_ids: z.array(z.string()),
})

const conversionExamplesSchema = z.object({
  schema_version: z.literal("1.0.0"),
  generated_at: z.string(),
  examples: z.array(conversionExampleSchema),
})

export type LoganCommand = z.infer<typeof commandSchema>
export type LoganMappingPattern = z.infer<typeof mappingPatternSchema>
export type LoganConversionExample = z.infer<typeof conversionExampleSchema>
export type LoganSourceLanguage = z.infer<typeof sourceLanguageSchema>

type WorkbenchArtifactKey = "referenceCatalog" | "mappingPatterns" | "conversionExamples"

export interface WorkbenchArtifactReadStatus {
  key: WorkbenchArtifactKey
  label: string
  relativePath: string
  ok: boolean
  error?: string
}

interface WorkbenchArtifactReadResult<T> {
  status: WorkbenchArtifactReadStatus
  data: T | null
}

export interface LoganWorkbenchArtifacts {
  detectionsRepoPath: string
  commands: LoganCommand[]
  patterns: LoganMappingPattern[]
  examples: LoganConversionExample[]
  statuses: WorkbenchArtifactReadStatus[]
  errors: string[]
  generatedAt: string | null
}

async function readJsonArtifact<TSchema extends z.ZodTypeAny>(
  key: WorkbenchArtifactKey,
  label: string,
  relativePath: string,
  schema: TSchema,
): Promise<WorkbenchArtifactReadResult<z.output<TSchema>>> {
  const absolutePath = path.join(detectionsRepoPath, relativePath)

  try {
    const fileContents = await readFile(absolutePath, "utf8")
    const parsed = schema.parse(JSON.parse(fileContents))
    return {
      status: { key, label, relativePath, ok: true },
      data: parsed,
    }
  } catch (error) {
    return {
      status: {
        key,
        label,
        relativePath,
        ok: false,
        error: error instanceof z.ZodError ? "Artifact schema validation failed." : "Artifact is unavailable.",
      },
      data: null,
    }
  }
}

export const getLoganWorkbenchArtifacts = cache(async (): Promise<LoganWorkbenchArtifacts> => {
  const [referenceCatalog, mappingPatterns, conversionExamples] = await Promise.all([
    readJsonArtifact(
      "referenceCatalog",
      "Logan QL command reference",
      "queries/logan_ql_reference_catalog.json",
      referenceCatalogSchema,
    ),
    readJsonArtifact(
      "mappingPatterns",
      "Cross-QL mapping patterns",
      "queries/cross_ql_mapping_patterns.json",
      mappingPatternsSchema,
    ),
    readJsonArtifact(
      "conversionExamples",
      "Conversion examples",
      "queries/conversion_examples.json",
      conversionExamplesSchema,
    ),
  ])

  const statuses = [referenceCatalog.status, mappingPatterns.status, conversionExamples.status]
  const generatedAt =
    conversionExamples.data?.generated_at ?? mappingPatterns.data?.generated_at ?? referenceCatalog.data?.generated_at ?? null

  return {
    detectionsRepoPath: "bundled artifact source",
    commands: referenceCatalog.data?.commands ?? [],
    patterns: mappingPatterns.data?.patterns ?? [],
    examples: conversionExamples.data?.examples ?? [],
    statuses,
    errors: statuses.filter((status) => !status.ok).map((status) => `${status.label}: ${status.error}`),
    generatedAt,
  }
})
