import assert from "node:assert/strict"
import test from "node:test"

import {
  downloadFilename,
  filterDetectionSamples,
  filterRawSamples,
  parseLogSamplesState,
  serializeDetectionJsonl,
  serializeJson,
  serializeRawJsonl,
} from "../../lib/log-samples-data.ts"

const rawSamples = [
  { id: "oci_audit", service: "OCI Audit", category: "Audit event", description: "Identity activity", event: { type: "audit" } },
  { id: "waf", service: "WAF", category: "Firewall", description: "Blocked requests", event: { type: "waf" } },
]

const detectionSamples = [
  {
    id: "console_brute_force",
    display_title: "OCI Console Brute Force",
    description: "Failed console logins",
    severity: "high",
    normalized_detection: { event_type: "oci.logan.detection", rule: { id: "console_brute_force" } },
    native_alarm: { type: "OK_TO_FIRING", title: "OCI Console Brute Force" },
  },
  {
    id: "waf_frequency",
    display_title: "WAF Attack Frequency",
    description: "Repeated WAF blocks",
    severity: "critical",
    normalized_detection: { event_type: "oci.logan.detection", rule: { id: "waf_frequency" } },
    native_alarm: { type: "OK_TO_FIRING", title: "WAF Attack Frequency" },
  },
]

test("parseLogSamplesState validates tabs, outputs, and sample identifiers", () => {
  const valid = parseLogSamplesState(
    new URLSearchParams("tab=detections&sample=waf_frequency&output=native"),
    rawSamples.map((sample) => sample.id),
    detectionSamples.map((sample) => sample.id),
  )
  assert.deepEqual(valid, { tab: "detections", sampleId: "waf_frequency", output: "native" })

  const fallback = parseLogSamplesState(
    new URLSearchParams("tab=unknown&sample=missing&output=other"),
    rawSamples.map((sample) => sample.id),
    detectionSamples.map((sample) => sample.id),
  )
  assert.deepEqual(fallback, { tab: "raw", sampleId: "oci_audit", output: "normalized" })
})

test("parseLogSamplesState chooses a valid sample for each tab", () => {
  const benefits = parseLogSamplesState(
    new URLSearchParams("tab=benefits&sample=waf"),
    rawSamples.map((sample) => sample.id),
    detectionSamples.map((sample) => sample.id),
  )
  assert.deepEqual(benefits, { tab: "benefits", sampleId: "waf", output: "normalized" })

  const detections = parseLogSamplesState(
    new URLSearchParams("tab=detections&sample=oci_audit"),
    rawSamples.map((sample) => sample.id),
    detectionSamples.map((sample) => sample.id),
  )
  assert.equal(detections.sampleId, "console_brute_force")
})

test("sample filters search meaningful customer-visible fields", () => {
  assert.deepEqual(filterRawSamples(rawSamples, "identity"), [rawSamples[0]])
  assert.deepEqual(filterRawSamples(rawSamples, "firewall"), [rawSamples[1]])
  assert.deepEqual(filterRawSamples(rawSamples, "  "), rawSamples)

  assert.deepEqual(filterDetectionSamples(detectionSamples, "CRITICAL"), [detectionSamples[1]])
  assert.deepEqual(filterDetectionSamples(detectionSamples, "console"), [detectionSamples[0]])
  assert.deepEqual(filterDetectionSamples(detectionSamples, "no-match"), [])
})

test("JSON serializers preserve exact events and emit newline-delimited bundles", () => {
  assert.equal(serializeJson(rawSamples[0].event), '{\n  "type": "audit"\n}')

  const rawLines = serializeRawJsonl(rawSamples).trim().split("\n")
  assert.deepEqual(rawLines.map((line) => JSON.parse(line)), [{ type: "audit" }, { type: "waf" }])

  const normalizedLines = serializeDetectionJsonl(detectionSamples, "normalized").trim().split("\n")
  assert.equal(JSON.parse(normalizedLines[0]).event_type, "oci.logan.detection")

  const nativeLines = serializeDetectionJsonl(detectionSamples, "native").trim().split("\n")
  assert.equal(JSON.parse(nativeLines[1]).type, "OK_TO_FIRING")
})

test("downloadFilename removes unsafe characters and keeps stable extensions", () => {
  assert.equal(downloadFilename("raw", "OCI Audit / Login", "json"), "oci-log-raw-oci-audit-login.json")
  assert.equal(downloadFilename("detection", "WAF_Attack", "jsonl"), "oci-log-detection-waf-attack.jsonl")
})
