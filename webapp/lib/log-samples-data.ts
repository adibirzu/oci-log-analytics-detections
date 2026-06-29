export type LogSamplesTab = "raw" | "detections" | "benefits"
export type DetectionOutput = "normalized" | "native"

export interface LogSamplesState {
  tab: LogSamplesTab
  sampleId: string
  output: DetectionOutput
}

interface RawSearchItem {
  id: string
  service: string
  category: string
  description: string
  event: unknown
}

interface DetectionSearchItem {
  id: string
  display_title: string
  description: string
  severity: string
  normalized_detection: unknown
  native_alarm: unknown
}

const tabs = new Set<LogSamplesTab>(["raw", "detections", "benefits"])
const outputs = new Set<DetectionOutput>(["normalized", "native"])

export function parseLogSamplesState(
  params: URLSearchParams,
  rawIds: readonly string[],
  detectionIds: readonly string[],
): LogSamplesState {
  const requestedTab = params.get("tab") as LogSamplesTab | null
  const tab = requestedTab && tabs.has(requestedTab) ? requestedTab : "raw"
  const requestedOutput = params.get("output") as DetectionOutput | null
  const output = requestedOutput && outputs.has(requestedOutput) ? requestedOutput : "normalized"
  const validIds = tab === "detections" ? detectionIds : rawIds
  const requestedSample = params.get("sample")
  const sampleId = requestedSample && validIds.includes(requestedSample) ? requestedSample : (validIds[0] ?? "")

  return { tab, sampleId, output }
}

export function filterRawSamples<T extends RawSearchItem>(items: readonly T[], search: string): T[] {
  const query = search.trim().toLowerCase()
  if (!query) return [...items]
  return items.filter((item) =>
    [item.service, item.category, item.description, item.id].some((value) => value.toLowerCase().includes(query)),
  )
}

export function filterDetectionSamples<T extends DetectionSearchItem>(items: readonly T[], search: string): T[] {
  const query = search.trim().toLowerCase()
  if (!query) return [...items]
  return items.filter((item) =>
    [item.display_title, item.description, item.severity, item.id].some((value) => value.toLowerCase().includes(query)),
  )
}

export function serializeJson(value: unknown): string {
  return JSON.stringify(value, null, 2)
}

export function serializeRawJsonl<T extends Pick<RawSearchItem, "event">>(items: readonly T[]): string {
  return `${items.map((item) => JSON.stringify(item.event)).join("\n")}\n`
}

export function serializeDetectionJsonl<T extends Pick<DetectionSearchItem, "native_alarm" | "normalized_detection">>(
  items: readonly T[],
  output: DetectionOutput,
): string {
  const key = output === "native" ? "native_alarm" : "normalized_detection"
  return `${items.map((item) => JSON.stringify(item[key])).join("\n")}\n`
}

export function downloadFilename(kind: "raw" | "detection", identifier: string, extension: "json" | "jsonl"): string {
  const slug = identifier
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
  return `oci-log-${kind}-${slug || "sample"}.${extension}`
}
