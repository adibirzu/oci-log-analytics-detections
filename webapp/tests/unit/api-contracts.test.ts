import test from "node:test"
import assert from "node:assert/strict"
import { artifactsResponseSchema } from "../../lib/api-contracts.ts"

const validResponse = {
  generatedAt: null,
  errors: [],
  statuses: [
    "referenceCatalog",
    "mappingPatterns",
    "conversionExamples",
    "capabilityMatrix",
    "forgeDetectionCatalog",
  ].map((key) => ({ key, label: key, relativePath: `queries/${key}.json`, ok: true })),
  examplesCount: 1,
  patternsCount: 1,
  commandsCount: 1,
}

test("artifact response accepts the explicitly supported Forge catalog status", () => {
  const parsed = artifactsResponseSchema.parse(validResponse)
  assert.equal(parsed.statuses.at(-1)?.key, "forgeDetectionCatalog")
})

test("artifact response rejects an unknown artifact status key", () => {
  assert.throws(() => artifactsResponseSchema.parse({
    ...validResponse,
    statuses: [...validResponse.statuses, {
      key: "unapprovedArtifact",
      label: "unapprovedArtifact",
      relativePath: "queries/unapproved.json",
      ok: true,
    }],
  }))
})
