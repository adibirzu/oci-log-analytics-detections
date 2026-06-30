import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import path from "node:path"
import test from "node:test"

import { parseSiemLogExamples } from "../../lib/siem-log-examples-contract.ts"

const artifactPath = path.resolve(process.cwd(), "..", "queries", "siem_log_examples.json")
const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as unknown

test("generated SIEM artifact passes the frontend boundary contract", () => {
  const parsed = parseSiemLogExamples(artifact)
  assert.equal(parsed.schema_version, "1.0.0")
  assert.equal(parsed.raw_log_samples.length, 10)
  assert.equal(parsed.detection_samples.length, 10)
  assert.ok(parsed.raw_log_samples.every((sample) => sample.official_doc_url.startsWith("https://docs.oracle.com/")))
})

test("frontend boundary rejects incomplete artifacts", () => {
  const incomplete = { ...(artifact as Record<string, unknown>), detection_samples: [] }
  assert.throws(() => parseSiemLogExamples(incomplete))
})

test("frontend boundary rejects malformed native alarm events", () => {
  const source = artifact as { detection_samples: Array<Record<string, unknown>> }
  const malformed = {
    ...(artifact as Record<string, unknown>),
    detection_samples: [
      { ...source.detection_samples[0], native_alarm: { type: "OK_TO_FIRING" } },
      ...source.detection_samples.slice(1),
    ],
  }
  assert.throws(() => parseSiemLogExamples(malformed))
})
