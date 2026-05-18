import type {
  LoganConversionExample,
  LoganMappingPattern,
  LoganSourceLanguage,
} from "@/lib/logan-workbench-artifacts"

export interface ConversionWarning {
  code: string
  message: string
  severity: "info" | "warning" | "error"
}

export interface ConversionResponse {
  schema_version: "1.0.0"
  generated_at: string
  source_language?: string
  source_query?: string
  logan_query: string
  support_level: "supported" | "partial" | "lossy" | "unsupported"
  explanation: string
  warnings: ConversionWarning[]
  metadata: Record<string, unknown>
  backend: string
}

export interface AuditEntry {
  id: string
  time: string
  action: string
  target: string
  detail: string
  status: "ok" | "warn" | "error" | "info"
}

export interface DerivedMetadata {
  mitre: Array<{ id: string; name: string; tactic: string }>
  stig: Array<{ id: string; title: string; severity: string }>
  fields: Array<{ source: string; oci: string; note: string }>
  logSources: Array<{ name: string; status: string; events: string }>
  metadata: Array<{ label: string; value: string }>
  sampleEvent: Array<{ field: string; value: string; matched?: boolean }>
}

export type MetadataTab = "mitre" | "stig" | "fields" | "sources" | "metadata" | "sample"

export const languageLabels: Record<LoganSourceLanguage, string> = {
  sigma_yaml: "Sigma YAML",
  sentinel_kql: "Sentinel KQL",
  splunk_spl: "Splunk SPL",
  elastic_lucene: "Elastic/Lucene",
  elastic_eql: "Elastic EQL",
  oci_logan: "Raw / OCI Logan QL",
}

export const languageOrder: LoganSourceLanguage[] = [
  "sigma_yaml",
  "sentinel_kql",
  "splunk_spl",
  "elastic_lucene",
  "elastic_eql",
  "oci_logan",
]

const techniqueNames: Record<string, { name: string; tactic: string }> = {
  T1059: { name: "Command and Scripting Interpreter", tactic: "Execution" },
  "T1059.001": { name: "PowerShell", tactic: "Execution" },
  T1078: { name: "Valid Accounts", tactic: "Initial Access" },
  "T1078.004": { name: "Cloud Accounts", tactic: "Initial Access" },
  T1110: { name: "Brute Force", tactic: "Credential Access" },
  "T1110.001": { name: "Password Guessing", tactic: "Credential Access" },
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
}

const fieldMaps: Record<LoganSourceLanguage, Array<{ source: string; oci: string; note: string }>> = {
  sigma_yaml: [
    { source: "Image", oci: "Process Name", note: "Sigma process image display field mapping" },
    { source: "CommandLine", oci: "Command Line", note: "Command arguments preserved as a string predicate" },
    { source: "ComputerName", oci: "Host Name", note: "Host dimension for grouped results" },
    { source: "User", oci: "User Name", note: "Identity display field normalization" },
    { source: "url", oci: "Request URL", note: "SOC Application Logs parser field" },
  ],
  sentinel_kql: [
    { source: "EventID", oci: "Event ID", note: "Windows event identifier" },
    { source: "Computer", oci: "Host Name", note: "Entity host dimension" },
    { source: "SubjectUserName", oci: "Subject User Name", note: "Security event subject" },
    { source: "CommandLine", oci: "Command Line", note: "Process command line" },
    { source: "OperationName", oci: "Operation", note: "Cloud audit operation name" },
    { source: "Result", oci: "Status", note: "Cloud audit result status" },
  ],
  splunk_spl: [
    { source: "sourcetype", oci: "Log Source", note: "Source family maps to OCI Log Analytics source" },
    { source: "EventCode", oci: "Event ID", note: "Sysmon or Windows event code" },
    { source: "host", oci: "Host Name", note: "Host grouping field" },
    { source: "User", oci: "User Name", note: "Identity display field" },
    { source: "CommandLine", oci: "Command Line", note: "Process command line" },
    { source: "src_ip", oci: "Source IP", note: "Network source address" },
  ],
  elastic_lucene: [
    { source: "event.code", oci: "Event ID", note: "ECS event identifier" },
    { source: "process.name", oci: "Process Name", note: "ECS process name" },
    { source: "process.command_line", oci: "Command Line", note: "ECS process command line" },
    { source: "url.path/url.query", oci: "Request URL", note: "HTTP URL fields collapse to parser URL" },
    { source: "http.response.status_code", oci: "Response Code", note: "HTTP response status" },
  ],
  elastic_eql: [
    { source: "process.name", oci: "Process Name", note: "EQL process event field" },
    { source: "process.command_line", oci: "Command Line", note: "Command-line predicate" },
    { source: "user.name", oci: "User Name", note: "Identity field" },
    { source: "event.type", oci: "Event Type", note: "Event lifecycle predicate where available" },
  ],
  oci_logan: [
    { source: "Log Source", oci: "Log Source", note: "Passthrough source selector" },
    { source: "Response Code", oci: "Response Code", note: "Native OCI display field" },
    { source: "Service Name", oci: "Service Name", note: "Native OCI display field" },
    { source: "Source IP", oci: "Source IP", note: "Native OCI display field" },
  ],
}

export function supportBadgeClass(level: string) {
  if (level === "supported") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
  if (level === "partial") return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
  if (level === "lossy") return "border-orange-500/30 bg-orange-500/10 text-orange-700 dark:text-orange-300"
  return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300"
}

export function lineCount(value: string) {
  return value ? value.split("\n").length : 0
}

export function sourceFamily(language: string) {
  if (language.startsWith("elastic")) return "elastic"
  if (language === "oci_logan") return "oci"
  return language.replace("_yaml", "").replace("_kql", "").replace("_spl", "")
}

export function toLanguage(value: string | undefined, fallback: LoganSourceLanguage): LoganSourceLanguage {
  return languageOrder.includes(value as LoganSourceLanguage) ? (value as LoganSourceLanguage) : fallback
}

export function getRelevantCommands<T extends { name: string }>(commands: T[], query: string) {
  const lowered = query.toLowerCase()
  const matches = commands.filter((command) => {
    const name = command.name.toLowerCase()
    return lowered.includes(`| ${name}`) || lowered.includes(`${name} `) || lowered.includes(`${name}=`)
  })
  const rest = commands.filter((command) => !matches.some((match) => match.name === command.name))
  return [...matches, ...rest]
}

export function formatLoganQueryForDisplay(query: string) {
  return query
    .replace(/\s+\|\s+/g, "\n| ")
    .replace(/\)\s+and\s+\(/g, ")\n  and (")
    .replace(/\)\s+or\s+\(/g, ")\n  or (")
    .replace(/\s+and\s+'Log Source'/g, "\n  and 'Log Source'")
    .replace(/\s+and\s+'/g, "\n  and '")
    .trim()
}

export function clientSideWarnings(language: LoganSourceLanguage, sourceQuery: string): ConversionWarning[] {
  const lowered = sourceQuery.toLowerCase()
  const unsafeYaml = /!!python|!!js\/function|!!binary/.test(sourceQuery)
  const warnings: ConversionWarning[] = [
    ...(unsafeYaml
      ? [
          {
            code: "blocked_yaml_construct",
            message: "Unsafe YAML tags are blocked before the backend conversion call.",
            severity: "error" as const,
          },
        ]
      : []),
    ...(language === "sentinel_kql" && lowered.includes("| join")
      ? [
          {
            code: "unsupported_join_or_sequence",
            message: "Cross-table joins require a backend correlation strategy and are not silently converted.",
            severity: "error" as const,
          },
        ]
      : []),
    ...(language === "splunk_spl" && /`[^`]+`/.test(sourceQuery)
      ? [
          {
            code: "spl_macro_review",
            message: "SPL macros must be expanded server-side before conversion.",
            severity: "warning" as const,
          },
        ]
      : []),
    ...(lowered.includes("lookup") || lowered.includes("_getwatchlist")
      ? [
          {
            code: "lookup_dependency",
            message: "Lookup/watchlist semantics require an OCI lookup artifact and are surfaced as dependencies.",
            severity: "warning" as const,
          },
        ]
      : []),
    ...(language === "elastic_eql" && lowered.includes("sequence")
      ? [
          {
            code: "eql_sequence_review",
            message: "Elastic sequence semantics are not represented by a single Logan QL query.",
            severity: "warning" as const,
          },
        ]
      : []),
  ]
  return warnings
}

export function deriveMetadata(
  example: LoganConversionExample | undefined,
  result: ConversionResponse | null,
  patterns: LoganMappingPattern[],
  fallbackLanguage: LoganSourceLanguage,
): DerivedMetadata {
  const language = toLanguage(result?.source_language, example?.source_language ?? fallbackLanguage)
  const sourceQuery = result?.source_query ?? example?.source_query ?? ""
  const loganQuery = result?.logan_query ?? example?.expected_logan_ql ?? ""
  const combinedText = `${sourceQuery}\n${loganQuery}\n${example?.title ?? ""}`.toLowerCase()
  const sourcePatternIds = example?.pattern_ids ?? []
  const activePatterns = patterns.filter((pattern) => sourcePatternIds.includes(pattern.id))
  const logSources = extractLogSources(loganQuery, example?.synthetic_log_shape)
  const fields = selectFieldMap(language, combinedText)
  const mitre = extractMitre(combinedText)
  const stig = extractStig(combinedText)

  return {
    mitre,
    stig,
    fields,
    logSources,
    metadata: [
      { label: "title", value: example?.title ?? "Custom conversion" },
      { label: "language", value: languageLabels[language] },
      { label: "support", value: result?.support_level ?? example?.support_level ?? "supported" },
      { label: "backend", value: result?.backend ?? "queries/conversion_examples.json" },
      { label: "generated", value: result?.generated_at ?? "" },
      { label: "schema", value: result?.schema_version ?? "1.0.0" },
      { label: "patterns", value: activePatterns.map((pattern) => pattern.id).join(", ") || sourcePatternIds.join(", ") },
      { label: "synthetic shape", value: example?.synthetic_log_shape ?? "Real OCI Log Analytics event shape" },
    ].filter((item) => item.value),
    sampleEvent: buildSampleEvent(logSources[0]?.name, fields, combinedText),
  }
}

function selectFieldMap(language: LoganSourceLanguage, combinedText: string) {
  const candidates = fieldMaps[language] ?? []
  const selected = candidates.filter((item) => {
    return (
      combinedText.includes(item.source.toLowerCase()) ||
      combinedText.includes(item.oci.toLowerCase()) ||
      ["Log Source", "Event ID"].includes(item.oci)
    )
  })
  return selected.length ? selected : candidates.slice(0, 4)
}

function extractLogSources(query: string, syntheticShape?: string) {
  const matches = Array.from(query.matchAll(/'Log Source'\s*=\s*'([^']+)'/g)).map((match) => match[1])
  const fromShape = syntheticShape?.match(/^[^.]+/)?.[0]
  const names = Array.from(new Set([...(matches.length ? matches : []), ...(fromShape ? [fromShape] : [])]))
  return (names.length ? names : ["OCI Log Analytics"]).map((name, index) => ({
    name,
    status: index === 0 ? "required" : "alternate",
    events: index === 0 ? "real parser shape" : "mapped source",
  }))
}

function extractMitre(combinedText: string) {
  const ids = Array.from(combinedText.matchAll(/attack\.t(\d+(?:\.\d+)?)/gi)).map((match) => `T${match[1]}`)
  const inferred = [
    ...(combinedText.includes("powershell") ? ["T1059.001"] : []),
    ...(combinedText.includes("mfa") || combinedText.includes("signin") ? ["T1078.004"] : []),
    ...(combinedText.includes("brute") ? ["T1110.001"] : []),
    ...(combinedText.includes("xss") || combinedText.includes("<script") ? ["T1190"] : []),
  ]
  return Array.from(new Set([...ids, ...inferred])).map((id) => ({
    id,
    name: techniqueNames[id]?.name ?? "Technique mapping",
    tactic: techniqueNames[id]?.tactic ?? "Mapped",
  }))
}

function extractStig(combinedText: string) {
  const controls = [
    ...(combinedText.includes("mfa")
      ? [{ id: "IA-2", title: "Identification and authentication", severity: "high" }]
      : []),
    ...(combinedText.includes("ps_logging") || combinedText.includes("powershell")
      ? [{ id: "AU-12", title: "Audit record generation", severity: "medium" }]
      : []),
    ...(combinedText.includes("audit")
      ? [{ id: "AU-6", title: "Audit review, analysis, and reporting", severity: "medium" }]
      : []),
    ...(combinedText.includes("kms") || combinedText.includes("key")
      ? [{ id: "SC-12", title: "Cryptographic key establishment", severity: "high" }]
      : []),
  ]
  return Array.from(new Map(controls.map((control) => [control.id, control])).values())
}

function buildSampleEvent(
  logSource: string | undefined,
  fields: Array<{ source: string; oci: string; note: string }>,
  combinedText: string,
) {
  const source = logSource ?? "OCI Log Analytics"
  const base = [
    { field: "Log Source", value: source, matched: true },
    { field: "Time", value: "2026-05-17T12:18:34Z" },
  ]
  const values = fields.slice(0, 5).map((field) => ({
    field: field.oci,
    value: sampleValueForField(field.oci, combinedText),
    matched: combinedText.includes(field.oci.toLowerCase()),
  }))
  return [...base, ...values]
}

function sampleValueForField(field: string, combinedText: string) {
  if (field.includes("Command Line")) return "powershell.exe -NoProfile -EncodedCommand SQBFAFgA"
  if (field.includes("Process")) return combinedText.includes("powershell") ? "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" : "process.exe"
  if (field.includes("Event ID")) return combinedText.includes("4688") ? "4688" : "1"
  if (field.includes("Host")) return "win-demo-01"
  if (field.includes("User")) return "example\\analyst"
  if (field.includes("Request URL")) return "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
  if (field.includes("Response Code")) return "200"
  if (field.includes("Source IP")) return "10.0.12.24"
  if (field.includes("Service Name")) return "checkout-api"
  return "sample-value"
}
