"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { useTheme } from "next-themes"
import {
  AlertTriangle,
  BookOpen,
  Check,
  Clipboard,
  Code2,
  Copy,
  Download,
  ExternalLink,
  FileCode2,
  Github,
  History,
  Link2,
  Lock,
  Moon,
  PanelRightClose,
  PanelRightOpen,
  Play,
  Search,
  SlidersHorizontal,
  Sun,
  Table,
  TerminalSquare,
  Unlock,
  X,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import type {
  LoganCommand,
  LoganConversionExample,
  LoganMappingPattern,
  LoganSourceLanguage,
  WorkbenchArtifactReadStatus,
} from "@/lib/logan-workbench-artifacts"
import {
  type AuditEntry,
  type ConversionResponse,
  type ConversionWarning,
  type MetadataTab,
  clientSideWarnings,
  deriveMetadata,
  formatLoganQueryForDisplay,
  getRelevantCommands,
  languageLabels,
  languageOrder,
  lineCount,
  sourceFamily,
  supportBadgeClass,
} from "./forge-workbench-data"
import { EditorFrame, MetadataPanel, MetadataTabs } from "./forge-workbench-panels"

const repositoryUrl = "https://github.com/adibirzu/oci-log-analytics-detections"

interface ForgeWorkbenchProps {
  commands: LoganCommand[]
  patterns: LoganMappingPattern[]
  examples: LoganConversionExample[]
  statuses: WorkbenchArtifactReadStatus[]
  generatedAt: string | null
}

type LayoutMode = "three-pane" | "split" | "stacked"
type DensityMode = "compact" | "comfortable"

function timeNow() {
  return new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
}

function auditEntry(
  action: string,
  target: string,
  detail: string,
  status: AuditEntry["status"] = "info",
): AuditEntry {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    time: timeNow(),
    action,
    target,
    detail,
    status,
  }
}

function warningClass(severity: ConversionWarning["severity"]) {
  if (severity === "error") return "border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-200"
  if (severity === "warning") return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-200"
  return "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-200"
}

function auditClass(status: AuditEntry["status"]) {
  if (status === "ok") return "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
  if (status === "warn") return "bg-amber-500/10 text-amber-700 dark:text-amber-300"
  if (status === "error") return "bg-red-500/10 text-red-700 dark:text-red-300"
  return "bg-sky-500/10 text-sky-700 dark:text-sky-300"
}

export function ForgeWorkbench({ commands, patterns, examples, statuses, generatedAt }: ForgeWorkbenchProps) {
  const firstExample = examples[0]
  const [selectedExampleId, setSelectedExampleId] = useState(firstExample?.id ?? "")
  const selectedExample = examples.find((example) => example.id === selectedExampleId) ?? firstExample
  const [sourceLanguage, setSourceLanguage] = useState<LoganSourceLanguage>(
    selectedExample?.source_language ?? "sigma_yaml",
  )
  const [sourceQuery, setSourceQuery] = useState(selectedExample?.source_query ?? "")
  const [result, setResult] = useState<ConversionResponse | null>(
    selectedExample
      ? {
          schema_version: "1.0.0",
          generated_at: generatedAt ?? "",
          source_language: selectedExample.source_language,
          source_query: selectedExample.source_query,
          logan_query: selectedExample.expected_logan_ql,
          support_level: selectedExample.support_level,
          explanation: selectedExample.explanation,
          warnings: selectedExample.warnings.map((message) => ({
            code: "example_warning",
            message,
            severity: "warning",
          })),
          metadata: {},
          backend: "Generated example catalog",
        }
      : null,
  )
  const [csrfToken, setCsrfToken] = useState("")
  const [converting, setConverting] = useState(false)
  const [error, setError] = useState("")
  const [docsOpen, setDocsOpen] = useState(true)
  const [readOnly, setReadOnly] = useState(true)
  const [commandSearch, setCommandSearch] = useState("")
  const [exampleSearch, setExampleSearch] = useState("")
  const [copied, setCopied] = useState(false)
  const [shared, setShared] = useState(false)
  const [auditOpen, setAuditOpen] = useState(false)
  const [layoutMode, setLayoutMode] = useState<LayoutMode>("three-pane")
  const [density, setDensity] = useState<DensityMode>("compact")
  const [metadataTab, setMetadataTab] = useState<MetadataTab>("mitre")
  const [audit, setAudit] = useState<AuditEntry[]>([
    auditEntry("SESSION", "artifact menu", "loaded generated OCI command reference", "ok"),
    auditEntry("POLICY", "read-only", "backend write actions are disabled by default", "info"),
  ])
  const [mounted, setMounted] = useState(false)
  const { resolvedTheme, setTheme } = useTheme()

  const addAudit = useCallback((entry: AuditEntry) => {
    setAudit((items) => [entry, ...items].slice(0, 50))
  }, [])

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    let active = true
    fetch("/api/forge/session", { credentials: "same-origin" })
      .then((response) => response.json())
      .then((payload: { csrfToken?: string }) => {
        if (!active) return
        setCsrfToken(payload.csrfToken ?? "")
        addAudit(auditEntry("SESSION", "converter", "conversion session initialized", "ok"))
      })
      .catch(() => {
        if (!active) return
        setError("Could not initialize the conversion session.")
        addAudit(auditEntry("SESSION", "converter", "conversion session initialization failed", "error"))
      })
    return () => {
      active = false
    }
  }, [addAudit])

  const filteredExamples = useMemo(() => {
    const query = exampleSearch.toLowerCase().trim()
    if (!query) return examples
    return examples.filter((example) => {
      return (
        example.title.toLowerCase().includes(query) ||
        languageLabels[example.source_language].toLowerCase().includes(query) ||
        example.id.includes(query)
      )
    })
  }, [exampleSearch, examples])

  const filteredCommands = useMemo(() => {
    const query = commandSearch.toLowerCase().trim()
    const sorted = getRelevantCommands(commands, result?.logan_query ?? "")
    if (!query) return sorted
    return sorted.filter((command) => {
      return (
        command.name.toLowerCase().includes(query) ||
        command.category.toLowerCase().includes(query) ||
        command.summary.toLowerCase().includes(query)
      )
    })
  }, [commandSearch, commands, result?.logan_query])

  const activePatterns = useMemo(() => {
    const family = sourceFamily(sourceLanguage)
    return patterns.filter((pattern) => {
      return (
        pattern.source_language === sourceLanguage ||
        pattern.source_language.includes(family) ||
        pattern.source_language === "cross_ql"
      )
    })
  }, [patterns, sourceLanguage])

  const sourceWarnings = useMemo(() => clientSideWarnings(sourceLanguage, sourceQuery), [sourceLanguage, sourceQuery])
  const derivedMetadata = useMemo(
    () => deriveMetadata(selectedExample, result, patterns, sourceLanguage),
    [patterns, result, selectedExample, sourceLanguage],
  )
  const output = result?.logan_query ?? ""
  const displayOutput = useMemo(() => formatLoganQueryForDisplay(output), [output])
  const failedArtifacts = statuses.filter((status) => !status.ok)
  const showDocs = layoutMode === "three-pane" && docsOpen
  const converterGridClass = layoutMode === "stacked" ? "grid-cols-1" : "lg:grid-cols-2"
  const densityClass = density === "compact" ? "gap-2 p-3 text-[12px]" : "gap-3 p-4 text-[13px]"

  const loadExample = useCallback(
    (example: LoganConversionExample) => {
      setSelectedExampleId(example.id)
      setSourceLanguage(example.source_language)
      setSourceQuery(example.source_query)
      setMetadataTab("mitre")
      setResult({
        schema_version: "1.0.0",
        generated_at: generatedAt ?? "",
        source_language: example.source_language,
        source_query: example.source_query,
        logan_query: example.expected_logan_ql,
        support_level: example.support_level,
        explanation: example.explanation,
        warnings: example.warnings.map((message) => ({ code: "example_warning", message, severity: "warning" })),
        metadata: {},
        backend: "Generated example catalog",
      })
      addAudit(auditEntry("LOAD", example.id, `loaded ${languageLabels[example.source_language]} example`, "ok"))
    },
    [addAudit, generatedAt],
  )

  const convert = useCallback(async () => {
    if (!csrfToken) {
      setError("Secure session is not ready yet.")
      return
    }
    const blockingWarnings = sourceWarnings.filter((warning) => warning.severity === "error")
    if (blockingWarnings.length) {
      setError("Input failed client-side sanitization.")
      addAudit(auditEntry("BLOCK", languageLabels[sourceLanguage], blockingWarnings[0].code, "error"))
      return
    }

    setConverting(true)
    setError("")
    try {
      const response = await fetch("/api/forge/convert", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-Logan-Forge-CSRF": csrfToken,
        },
        body: JSON.stringify({
          sourceLanguage,
          sourceQuery,
          readOnly,
          exampleId: selectedExampleId || undefined,
        }),
      })
      const payload = await response.json()
      if (!response.ok) {
        throw new Error(payload.error || "Conversion failed")
      }
      setResult(payload as ConversionResponse)
      setMetadataTab("mitre")
      addAudit(auditEntry("CONVERT", languageLabels[sourceLanguage], "conversion completed through API", "ok"))
    } catch (conversionError) {
      setError(conversionError instanceof Error ? conversionError.message : "Conversion failed")
      addAudit(auditEntry("CONVERT", languageLabels[sourceLanguage], "conversion failed", "error"))
    } finally {
      setConverting(false)
    }
  }, [addAudit, csrfToken, readOnly, selectedExampleId, sourceLanguage, sourceQuery, sourceWarnings])

  const copyOutput = useCallback(async () => {
    if (!result?.logan_query) return
    await navigator.clipboard.writeText(result.logan_query)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1200)
    addAudit(auditEntry("COPY", "Logan QL", "copied converted query to clipboard", "ok"))
  }, [addAudit, result?.logan_query])

  const downloadOutput = useCallback(() => {
    if (!result) return
    const blob = new Blob([JSON.stringify({ ...result, derived_metadata: derivedMetadata }, null, 2)], {
      type: "application/json",
    })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = `logan-forge-${sourceLanguage}.json`
    anchor.click()
    URL.revokeObjectURL(url)
    addAudit(auditEntry("DOWNLOAD", "conversion", "downloaded conversion JSON", "ok"))
  }, [addAudit, derivedMetadata, result, sourceLanguage])

  const shareOutput = useCallback(async () => {
    const url = new URL(window.location.href)
    if (selectedExampleId) url.searchParams.set("example", selectedExampleId)
    url.searchParams.set("language", sourceLanguage)
    await navigator.clipboard.writeText(url.toString())
    setShared(true)
    window.setTimeout(() => setShared(false), 1200)
    addAudit(auditEntry("SHARE", "workbench URL", "copied share link to clipboard", "ok"))
  }, [addAudit, selectedExampleId, sourceLanguage])

  const deploy = useCallback(() => {
    if (readOnly) return
    setError("Deploy is intentionally gated behind the backend API Gateway workflow.")
    addAudit(auditEntry("DEPLOY", "saved search", "blocked until write API is enabled", "warn"))
  }, [addAudit, readOnly])

  return (
    <main className="flex-1 overflow-hidden bg-background">
      <div className={`flex min-h-[calc(100vh-60px)] flex-col overflow-auto xl:h-[calc(100vh-60px)] xl:overflow-hidden ${densityClass}`}>
        <section className="flex flex-col gap-3 border-b pb-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex size-8 items-center justify-center rounded-md bg-[#c74634] text-white shadow-sm">
                <Code2 className="size-4" />
              </div>
              <div>
                <h1 className="text-2xl font-semibold tracking-tight">OCL Forge</h1>
                <p className="text-sm text-muted-foreground">
                  Convert Sigma, Sentinel KQL, SPL, Elastic, and raw OCI queries through the backend API.
                </p>
              </div>
              <Badge variant={failedArtifacts.length ? "destructive" : "secondary"} className="ml-0 lg:ml-2">
                {failedArtifacts.length ? "Artifact contract degraded" : "Artifact contract valid"}
              </Badge>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setAuditOpen(true)}
              className="inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-sm hover:bg-muted"
            >
              <History className="size-4 text-[#c74634]" />
              Audit
            </button>
            <div className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
              {readOnly ? <Lock className="size-4 text-[#c74634]" /> : <Unlock className="size-4 text-logan-warning" />}
              <span className="text-muted-foreground">Read-only</span>
              <Switch checked={readOnly} onCheckedChange={setReadOnly} aria-label="Toggle read-only mode" />
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => (mounted && resolvedTheme === "dark" ? setTheme("light") : setTheme("dark"))}
            >
              {mounted && resolvedTheme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </Button>
            <Button asChild variant="outline" size="sm">
              <a href={repositoryUrl} target="_blank" rel="noreferrer" title="Open repository for local setup and enhancements">
                <Github className="size-4" />
                Repo
              </a>
            </Button>
          </div>
        </section>

        <section className="flex flex-wrap items-center justify-between gap-2 border-b pb-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              <SlidersHorizontal className="size-3.5" />
              Tweaks
            </span>
            {(["three-pane", "split", "stacked"] as LayoutMode[]).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setLayoutMode(mode)}
                className={`h-8 rounded-md border px-2.5 text-xs font-medium ${
                  layoutMode === mode ? "border-[#c74634] bg-[#c74634]/10 text-[#c74634]" : "hover:bg-muted"
                }`}
              >
                {mode === "three-pane" ? "Three-pane" : mode === "split" ? "Split" : "Stacked"}
              </button>
            ))}
            {(["compact", "comfortable"] as DensityMode[]).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => setDensity(mode)}
                className={`h-8 rounded-md border px-2.5 text-xs font-medium ${
                  density === mode ? "border-[#c74634] bg-[#c74634]/10 text-[#c74634]" : "hover:bg-muted"
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
          <Button variant="outline" size="sm" onClick={() => setDocsOpen((value) => !value)} disabled={layoutMode !== "three-pane"}>
            {showDocs ? <PanelRightClose className="size-4" /> : <PanelRightOpen className="size-4" />}
            Docs
          </Button>
        </section>

        <section
          className={`grid min-h-0 flex-1 gap-3 pt-0 ${
            showDocs ? "xl:grid-cols-[240px_minmax(0,1fr)_320px]" : "xl:grid-cols-[240px_minmax(0,1fr)]"
          }`}
        >
          <aside className="flex min-h-[340px] flex-col overflow-hidden rounded-md border bg-card xl:min-h-0">
            <div className="border-b p-3">
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-2 font-medium">
                  <FileCode2 className="size-4 text-[#c74634]" />
                  Rules and examples
                </div>
                <Badge variant="secondary">{examples.length}</Badge>
              </div>
              <div className="relative">
                <Search className="absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={exampleSearch}
                  onChange={(event) => setExampleSearch(event.target.value)}
                  placeholder="Filter library"
                  className="h-8 pl-8"
                />
              </div>
            </div>
            <div className="min-h-0 flex-1 overflow-auto p-2">
              {filteredExamples.map((example) => (
                <button
                  key={example.id}
                  type="button"
                  onClick={() => loadExample(example)}
                  className={`mb-2 w-full rounded-md border p-3 text-left transition hover:bg-muted ${
                    selectedExampleId === example.id ? "border-[#c74634] bg-[#c74634]/10" : "border-border"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 font-medium leading-snug">{example.title}</div>
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] uppercase ${supportBadgeClass(example.support_level)}`}>
                      {example.support_level}
                    </span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1 text-xs text-muted-foreground">
                    <span>{languageLabels[example.source_language]}</span>
                    <span aria-hidden="true">/</span>
                    <span>{example.pattern_ids.slice(0, 2).join(", ")}</span>
                  </div>
                </button>
              ))}
            </div>
            <div className="border-t p-3 text-xs text-muted-foreground">
              Generated {generatedAt ?? "unknown"} from detections repo artifacts.
            </div>
          </aside>

          <section className={`grid min-h-0 gap-3 ${converterGridClass}`}>
            <div className="flex min-h-[520px] flex-col overflow-hidden rounded-md border bg-card xl:min-h-0">
              <div className="flex flex-wrap items-center gap-2 border-b p-3">
                <TerminalSquare className="size-4 text-[#c74634]" />
                <span className="font-medium">Input</span>
                <span className="text-xs text-muted-foreground">{lineCount(sourceQuery)} lines</span>
                <div className="ml-auto flex flex-wrap gap-1">
                  {languageOrder.map((language) => (
                    <Button
                      key={language}
                      type="button"
                      size="sm"
                      variant={sourceLanguage === language ? "default" : "outline"}
                      className={`h-7 px-2 text-xs ${sourceLanguage === language ? "bg-[#c74634] hover:bg-[#b33d2d]" : ""}`}
                      onClick={() => setSourceLanguage(language)}
                    >
                      {languageLabels[language]}
                    </Button>
                  ))}
                </div>
              </div>
              {sourceWarnings.length ? (
                <div className="grid gap-2 border-b p-3">
                  {sourceWarnings.map((warning) => (
                    <div key={`${warning.code}-${warning.message}`} className={`rounded-md border p-2 text-xs ${warningClass(warning.severity)}`}>
                      <div className="flex items-center gap-1 font-medium">
                        <AlertTriangle className="size-3.5" />
                        {warning.code}
                      </div>
                      <div className="mt-1 opacity-90">{warning.message}</div>
                    </div>
                  ))}
                </div>
              ) : null}
              <EditorFrame
                value={sourceQuery}
                onChange={setSourceQuery}
                label="Source query editor"
                placeholder="Paste a Sigma YAML, Splunk SPL, Sentinel KQL, Elastic query, or raw OCI Logan QL query here..."
              />
              <div className="flex flex-wrap items-center gap-2 border-t p-3">
                <Button onClick={convert} disabled={converting || !csrfToken} className="bg-[#c74634] hover:bg-[#b33d2d]">
                  <Play className="size-4" />
                  {converting ? "Converting" : "Convert"}
                </Button>
                <Button variant="outline" onClick={() => setSourceQuery("")}>
                  Clear
                </Button>
                {error ? (
                  <span className="inline-flex items-center gap-1 text-sm text-logan-danger">
                    <AlertTriangle className="size-4" />
                    {error}
                  </span>
                ) : null}
              </div>
            </div>

            <div className="flex min-h-[520px] flex-col overflow-hidden rounded-md border bg-card xl:min-h-0">
              <div className="flex flex-wrap items-center gap-2 border-b p-3">
                <Clipboard className="size-4 text-[#c74634]" />
                <span className="font-medium">OCI Logan QL</span>
                {result ? (
                  <span className={`rounded border px-2 py-0.5 text-xs ${supportBadgeClass(result.support_level)}`}>
                    {result.support_level}
                  </span>
                ) : null}
                <span className="text-xs text-muted-foreground">{lineCount(displayOutput)} lines</span>
                <div className="ml-auto flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={copyOutput} disabled={!output} title="Copy Logan QL">
                    {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                  </Button>
                  <Button variant="outline" size="sm" onClick={downloadOutput} disabled={!result} title="Download conversion JSON">
                    <Download className="size-4" />
                  </Button>
                  <Button variant="outline" size="sm" onClick={shareOutput} title="Copy share link">
                    {shared ? <Check className="size-4" /> : <Link2 className="size-4" />}
                  </Button>
                  <Button size="sm" onClick={deploy} disabled={readOnly || !output} className="bg-[#c74634] hover:bg-[#b33d2d]">
                    Deploy
                  </Button>
                </div>
              </div>
              <EditorFrame value={displayOutput} label="OCI Logan QL output" placeholder="Conversion output appears here." wrapLines />
              <div className="border-t">
                <MetadataTabs
                  active={metadataTab}
                  onChange={setMetadataTab}
                  counts={{
                    mitre: derivedMetadata.mitre.length,
                    stig: derivedMetadata.stig.length,
                    fields: derivedMetadata.fields.length,
                    sources: derivedMetadata.logSources.length,
                    metadata: derivedMetadata.metadata.length,
                    sample: derivedMetadata.sampleEvent.length,
                  }}
                />
                <div className="max-h-64 overflow-auto p-3">
                  <div className="mb-3 rounded-md border bg-background/60 p-3 text-sm text-muted-foreground">
                    {result?.explanation ?? "Run a conversion to see backend guidance."}
                  </div>
                  {result?.warnings.length ? (
                    <div className="mb-3 grid gap-2">
                      {result.warnings.map((item) => (
                        <div key={`${item.code}-${item.message}`} className={`rounded-md border p-2 text-xs ${warningClass(item.severity)}`}>
                          <div className="font-medium">{item.code}</div>
                          <div className="mt-1 opacity-90">{item.message}</div>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <MetadataPanel tab={metadataTab} metadata={derivedMetadata} />
                </div>
              </div>
            </div>
          </section>

          {showDocs ? (
            <aside id="commands" className="flex min-h-[420px] flex-col overflow-hidden rounded-md border bg-card xl:min-h-0">
              <div className="border-b p-3">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-medium">
                    <BookOpen className="size-4 text-[#c74634]" />
                    OCI command menu
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => setDocsOpen(false)} aria-label="Close documentation panel">
                    <X className="size-4" />
                  </Button>
                </div>
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={commandSearch}
                    onChange={(event) => setCommandSearch(event.target.value)}
                    placeholder="Search Oracle commands"
                    className="h-8 pl-8"
                  />
                </div>
              </div>
              <div className="min-h-0 flex-1 overflow-auto p-3">
                <div className="mb-3 rounded-md border bg-background/60 p-3 text-xs text-muted-foreground">
                  Menu entries are loaded from the generated OCI reference catalog and link back to the official Oracle docs.
                </div>
                <div className="grid gap-2">
                  {filteredCommands.slice(0, 18).map((command) => (
                    <a
                      key={command.name}
                      href={command.source_url}
                      target="_blank"
                      rel="noreferrer"
                      className="rounded-md border p-3 transition hover:border-[#c74634]/50 hover:bg-muted"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <code className="font-mono text-sm text-[#c74634]">{command.name}</code>
                        <ExternalLink className="size-3.5 text-muted-foreground" />
                      </div>
                      <p className="mt-1 line-clamp-3 text-xs leading-5 text-muted-foreground">{command.summary}</p>
                      <pre className="mt-2 overflow-hidden text-ellipsis rounded bg-background p-2 font-mono text-[11px]">
                        {command.syntax}
                      </pre>
                    </a>
                  ))}
                </div>

                <div className="mt-4 border-t pt-4">
                  <div className="mb-2 flex items-center gap-2 text-sm font-medium">
                    <Table className="size-4 text-[#c74634]" />
                    Cross-QL mapping patterns
                  </div>
                  <div className="grid gap-2">
                    {activePatterns.slice(0, 6).map((pattern) => (
                      <div key={pattern.id} className="rounded-md border p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium">{pattern.source_construct}</span>
                          <span className={`rounded border px-1.5 py-0.5 text-[10px] uppercase ${supportBadgeClass(pattern.support_level)}`}>
                            {pattern.support_level}
                          </span>
                        </div>
                        <p className="mt-1 text-xs leading-5 text-muted-foreground">{pattern.oci_mapping}</p>
                        <div className="mt-2 flex flex-wrap gap-1">
                          {pattern.logan_commands.map((command) => (
                            <span key={command} className="rounded border bg-background px-1.5 py-0.5 font-mono text-[10px]">
                              {command}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </aside>
          ) : null}
        </section>

        {!showDocs && layoutMode === "three-pane" ? (
          <button
            type="button"
            onClick={() => setDocsOpen(true)}
            className="fixed right-0 top-1/2 z-40 hidden -translate-y-1/2 rounded-l-md border border-r-0 bg-card px-2 py-3 text-xs font-medium shadow-lg hover:bg-muted xl:inline-flex"
          >
            <BookOpen className="mb-1 size-4 text-[#c74634]" />
            Docs
          </button>
        ) : null}

        {auditOpen ? (
          <div className="fixed inset-0 z-50 flex items-end bg-black/40 p-3" role="dialog" aria-modal="true">
            <div className="mx-auto flex max-h-[70vh] w-full max-w-5xl flex-col overflow-hidden rounded-lg border bg-card shadow-xl">
              <div className="flex items-center gap-2 border-b p-3">
                <History className="size-4 text-[#c74634]" />
                <div className="font-medium">Security audit log</div>
                <Badge variant="secondary">{audit.length} entries</Badge>
                <Button variant="outline" size="sm" className="ml-auto" onClick={() => setAuditOpen(false)}>
                  Close
                </Button>
              </div>
              <div className="overflow-auto p-3">
                <div className="grid min-w-[760px] grid-cols-[100px_120px_160px_1fr_80px] gap-2 border-b pb-2 text-xs font-medium uppercase text-muted-foreground">
                  <span>Time</span>
                  <span>Action</span>
                  <span>Target</span>
                  <span>Detail</span>
                  <span>Status</span>
                </div>
                {audit.map((entry) => (
                  <div
                    key={entry.id}
                    className="grid min-w-[760px] grid-cols-[100px_120px_160px_1fr_80px] gap-2 border-b py-2 text-xs"
                  >
                    <span className="font-mono text-muted-foreground">{entry.time}</span>
                    <span className="font-medium">{entry.action}</span>
                    <span className="truncate text-muted-foreground">{entry.target}</span>
                    <span>{entry.detail}</span>
                    <span className={`rounded px-2 py-0.5 text-center uppercase ${auditClass(entry.status)}`}>{entry.status}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </main>
  )
}
