import { z } from "zod"

const rawLogSampleSchema = z.object({
  id: z.string().min(1),
  service: z.string().min(1),
  category: z.string().min(1),
  official_doc_url: z.string().url().refine((url) => url.startsWith("https://docs.oracle.com/")),
  envelope_type: z.string().min(1),
  repository_coverage: z.enum(["envelope", "payload", "custom", "gap"]),
  repository_dataset: z.string().nullable(),
  description: z.string().min(1),
  event: z.record(z.unknown()),
})

const normalizedDetectionSchema = z.object({
  schema_version: z.literal("1.0.0"),
  event_id: z.string(),
  event_type: z.literal("oci.logan.detection"),
  detected_at: z.string(),
  rule: z.object({
    id: z.string(),
    title: z.string(),
    query_ref: z.string(),
    schedule: z.string(),
    lookback: z.string(),
  }),
  severity: z.string(),
  source: z.object({
    product: z.literal("OCI Log Analytics"),
    log_sources: z.array(z.string()),
  }),
  window: z.object({ start: z.string(), end: z.string() }),
  matched_count: z.number().int().nonnegative(),
  entities: z.array(z.object({ type: z.string(), value: z.string() })),
  mitre: z.object({ tactics: z.array(z.string()), techniques: z.array(z.string()) }),
  evidence: z.record(z.unknown()),
  oci_context: z.object({
    tenancy_id: z.string(),
    compartment_id: z.string(),
    region: z.string(),
  }),
})

const alarmSeveritySchema = z.enum(["CRITICAL", "ERROR", "WARNING", "INFO"])

const nativeAlarmSchema = z.object({
  dedupeKey: z.string().min(1),
  title: z.string().min(1),
  body: z.string().min(1),
  type: z.literal("OK_TO_FIRING"),
  severity: alarmSeveritySchema,
  timestampEpochMillis: z.number().int().nonnegative(),
  timestamp: z.string().min(1),
  alarmMetaData: z.array(z.object({
    id: z.string().min(1),
    status: z.literal("FIRING"),
    severity: alarmSeveritySchema,
    namespace: z.literal("oci_logging_analytics"),
    query: z.string().min(1),
    totalMetricsFiring: z.number().int().positive(),
    dimensions: z.array(z.record(z.string())),
    metricValues: z.array(z.record(z.string())),
    alarmUrl: z.string().min(1),
    alarmSummary: z.string().min(1),
    notificationType: z.string().min(1),
  })).min(1),
  version: z.number(),
})

const detectionSampleSchema = z.object({
  id: z.string().min(1),
  display_title: z.string().min(1),
  description: z.string().min(1),
  query_file: z.string().startsWith("queries/"),
  eligible: z.literal(true),
  severity: z.enum(["high", "critical"]),
  metric_name: z.string().min(1),
  dimensions: z.array(z.string()).max(3),
  primary_raw_sample_ids: z.array(z.string()).min(1),
  native_alarm: nativeAlarmSchema,
  normalized_detection: normalizedDetectionSchema,
})

export const siemLogExamplesSchema = z.object({
  schema_version: z.literal("1.0.0"),
  generated_at: z.string(),
  placeholder_policy: z.object({
    syntax: z.literal("<UPPER_SNAKE_CASE>"),
    description: z.string().min(1),
  }),
  raw_log_samples: z.array(rawLogSampleSchema).length(10),
  detection_samples: z.array(detectionSampleSchema).length(10),
  comparison: z.object({
    native_path: z.array(z.string()).min(1),
    normalized_path: z.array(z.string()).min(1),
    advantages: z.array(z.string()).min(1),
    caution: z.string().min(1),
  }),
})

export type RawLogSample = z.infer<typeof rawLogSampleSchema>
export type NormalizedDetection = z.infer<typeof normalizedDetectionSchema>
export type DetectionSample = z.infer<typeof detectionSampleSchema>
export type SiemLogExamplesCatalog = z.infer<typeof siemLogExamplesSchema>

export function parseSiemLogExamples(payload: unknown): SiemLogExamplesCatalog {
  return siemLogExamplesSchema.parse(payload)
}
