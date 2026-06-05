"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { useTheme } from "next-themes"
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Check,
  Clipboard,
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
  ShieldCheck,
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
  type MetadataTab,
  auditStatusClass,
  clientSideWarnings,
  convertInBrowser,
  deriveMetadata,
  formatLoganQueryForDisplay,
  getRelevantCommands,
  languageLabels,
  languageOrder,
  lineCount,
  sourceFamily,
  supportBadgeClass,
  warningSeverityClass,
} from "./forge-workbench-data"
import { EditorFrame, MetadataPanel, MetadataTabs } from "./forge-workbench-panels"

const repositoryUrl = "https://github.com/adibirzu/oci-log-analytics-detections"
const staticExport = process.env.NEXT_PUBLIC_FORGE_STATIC_EXPORT === "1"

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
    if (staticExport) {
      setCsrfToken("static-export")
      addAudit(auditEntry("SESSION", "converter", "static GitHub Pages mode initialized", "ok"))
      return
    }

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
  const converterGridClass = layoutMode === "stacked" ? "grid-cols-1" : "lg:grid-cols-[minmax(0,1fr)_2.25rem_minmax(0,1fr)]"
  const shellPadding = density === "compact" ? "gap-3 p-3" : "gap-4 p-5"
  const blockingWarningCount = sourceWarnings.filter((warning) => warning.severity === "error").length

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
      if (staticExport) {
        const payload = convertInBrowser(sourceLanguage, sourceQuery, examples, selectedExampleId || undefined)
        setResult(payload)
        setMetadataTab("mitre")
        addAudit(auditEntry("CONVERT", languageLabels[sourceLanguage], "conversion completed in static browser mode", "ok"))
        return
      }

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
  }, [addAudit, csrfToken, examples, readOnly, selectedExampleId, sourceLanguage, sourceQuery, sourceWarnings])

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
    <main className="console-atmosphere flex-1 overflow-hidden" data-testid="forge-workbench">
      <div className={`flex min-h-[calc(100vh-60px)] flex-col overflow-auto xl:h-[calc(100vh-60px)] xl:overflow-hidden ${shellPadding}`}>
        {/* ── Console masthead ─────────────────────────────────────────── */}
        <header className="console-panel surface-grain animate-console-rise flex flex-col gap-4 p-4 lg:flex-row lg:items-center lg:justify-between lg:p-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <span className="relative flex size-10 shrink-0 items-center justify-center rounded-lg bg-gradient-to-b from-brand-glow to-primary text-primary-foreground shadow-[0_8px_22px_-10px_hsl(var(--primary)/0.8)]">
                <TerminalSquare className="size-5" />
                <span className="pointer-events-none absolute -right-1 -top-1 size-2.5 rounded-full bg-severity-ok ring-2 ring-[hsl(var(--surface-raised))]" />
              </span>
              <div className="min-w-0">
                <p className="eyebrow mb-1 text-primary/80">Detection conversion console</p>
                <h1 className="font-display text-display font-semibold leading-none text-foreground">Forge</h1>
              </div>
              <div className="hidden h-9 w-px bg-border-strong/60 lg:block" aria-hidden="true" />
              <p className="max-w-md text-meta text-muted-foreground">
                {staticExport
                  ? "Browse static conversion examples and pass through raw OCI queries on GitHub Pages."
                  : "Translate Sigma, Sentinel KQL, SPL, Elastic, and raw OCI queries into OCI Log Analytics QL through the secured backend."}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium ${
                failedArtifacts.length
                  ? "border-severity-critical/40 bg-severity-critical/10 text-severity-critical"
                  : "border-severity-ok/40 bg-severity-ok/10 text-severity-ok"
              }`}
            >
              <ShieldCheck className="size-3.5" />
              {failedArtifacts.length ? "Artifact contract degraded" : "Artifact contract valid"}
            </span>
            {staticExport ? (
              <Badge variant="outline" className="border-border-strong/60 text-muted-foreground">
                Static export
              </Badge>
            ) : null}
            <button
              type="button"
              onClick={() => setAuditOpen(true)}
              className="inline-flex h-9 items-center gap-1.5 rounded-md border border-border bg-surface-raised/60 px-3 text-sm text-foreground transition-colors hover:border-primary/40 hover:bg-accent/60"
            >
              <History className="size-4 text-primary" />
              Audit
            </button>
            <div className="flex items-center gap-2 rounded-md border border-border bg-surface-raised/60 px-3 py-1.5 text-sm">
              {readOnly ? <Lock className="size-4 text-primary" /> : <Unlock className="size-4 text-severity-high" />}
              <span className="text-muted-foreground">Read-only</span>
              <Switch checked={readOnly} onCheckedChange={setReadOnly} aria-label="Toggle read-only mode" />
            </div>
            <Button
              variant="outline"
              size="icon"
              onClick={() => (mounted && resolvedTheme === "dark" ? setTheme("light") : setTheme("dark"))}
              aria-label="Toggle color theme"
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
        </header>

        {/* ── View controls ────────────────────────────────────────────── */}
        <section className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="eyebrow inline-flex items-center gap-1.5">
              <SlidersHorizontal className="size-3.5" />
              Layout
            </span>
            <div className="flex items-center gap-1 rounded-md border border-border bg-surface-raised/50 p-1">
              {(["three-pane", "split", "stacked"] as LayoutMode[]).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setLayoutMode(mode)}
                  aria-pressed={layoutMode === mode}
                  className={`h-7 rounded px-2.5 text-xs font-medium transition-colors ${
                    layoutMode === mode ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {mode === "three-pane" ? "Three-pane" : mode === "split" ? "Split" : "Stacked"}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-1 rounded-md border border-border bg-surface-raised/50 p-1">
              {(["compact", "comfortable"] as DensityMode[]).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setDensity(mode)}
                  aria-pressed={density === mode}
                  className={`h-7 rounded px-2.5 text-xs font-medium capitalize transition-colors ${
                    density === mode ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => setDocsOpen((value) => !value)} disabled={layoutMode !== "three-pane"}>
            {showDocs ? <PanelRightClose className="size-4" /> : <PanelRightOpen className="size-4" />}
            Reference
          </Button>
        </section>

        {/* ── Bento workbench grid ─────────────────────────────────────── */}
        <section
          className={`mt-3 grid min-h-0 flex-1 gap-3 ${
            showDocs ? "xl:grid-cols-[252px_minmax(0,1fr)_336px]" : "xl:grid-cols-[252px_minmax(0,1fr)]"
          }`}
        >
          {/* Library rail */}
          <aside className="console-rail flex min-h-[340px] flex-col overflow-hidden xl:min-h-0">
            <div className="border-b border-border/70 p-3">
              <div className="mb-2.5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode2 className="size-4 text-primary" />
                  <span className="text-sm font-semibold">Rule library</span>
                </div>
                <span className="rounded-md bg-primary/12 px-2 py-0.5 font-mono text-[11px] text-primary tabular-nums">
                  {examples.length}
                </span>
              </div>
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={exampleSearch}
                  onChange={(event) => setExampleSearch(event.target.value)}
                  placeholder="Filter library"
                  className="h-9 border-border bg-surface-sunken/50 pl-8"
                  data-testid="example-search"
                />
              </div>
            </div>
            <div className="min-h-0 flex-1 space-y-2 overflow-auto p-2.5">
              {filteredExamples.map((example) => {
                const isActive = selectedExampleId === example.id
                return (
                  <button
                    key={example.id}
                    type="button"
                    onClick={() => loadExample(example)}
                    data-testid={`example-${example.id}`}
                    aria-pressed={isActive}
                    className={`group relative w-full overflow-hidden rounded-lg border p-3 text-left transition-colors duration-150 ${
                      isActive
                        ? "border-primary/50 bg-primary/8"
                        : "border-border/70 bg-surface-raised/40 hover:border-border-strong/70 hover:bg-accent/40"
                    }`}
                  >
                    <span
                      className={`absolute inset-y-0 left-0 w-0.5 transition-opacity ${
                        isActive ? "bg-primary opacity-100" : "opacity-0 group-hover:bg-border-strong group-hover:opacity-100"
                      }`}
                      aria-hidden="true"
                    />
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 text-sm font-medium leading-snug text-foreground">{example.title}</div>
                      <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${supportBadgeClass(example.support_level)}`}>
                        {example.support_level}
                      </span>
                    </div>
                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
                      <span className="rounded bg-muted px-1.5 py-0.5 font-medium text-muted-foreground">
                        {languageLabels[example.source_language]}
                      </span>
                      <span className="truncate font-mono opacity-70">{example.pattern_ids.slice(0, 2).join(" · ")}</span>
                    </div>
                  </button>
                )
              })}
            </div>
            <div className="border-t border-border/70 px-3 py-2.5 text-[11px] text-muted-foreground">
              <span className="eyebrow text-[10px]">Generated</span>{" "}
              <span className="font-mono">{generatedAt ?? "unknown"}</span> · detections repo artifacts
            </div>
          </aside>

          {/* Source -> Target conversion view */}
          <section className={`grid min-h-0 items-stretch gap-3 ${converterGridClass}`}>
            {/* Source panel */}
            <div className="console-panel flex min-h-[480px] flex-col overflow-hidden xl:min-h-0">
              <div className="flex flex-wrap items-center gap-2 border-b border-border/70 bg-surface-raised/60 px-3 py-2.5">
                <span className="eyebrow inline-flex items-center gap-1.5 text-primary/80">
                  <TerminalSquare className="size-3.5" />
                  Source
                </span>
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground tabular-nums">
                  {lineCount(sourceQuery)} ln
                </span>
                <div className="ml-auto flex flex-wrap gap-1">
                  {languageOrder.map((language) => (
                    <button
                      key={language}
                      type="button"
                      onClick={() => setSourceLanguage(language)}
                      data-testid={`language-${language}`}
                      aria-pressed={sourceLanguage === language}
                      className={`h-7 rounded-md px-2 text-[11px] font-medium transition-colors ${
                        sourceLanguage === language
                          ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/40"
                          : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
                      }`}
                    >
                      {languageLabels[language]}
                    </button>
                  ))}
                </div>
              </div>
              {sourceWarnings.length ? (
                <div className="grid gap-2 border-b border-border/70 bg-surface-sunken/30 p-3">
                  {sourceWarnings.map((warning) => (
                    <div key={`${warning.code}-${warning.message}`} className={`rounded-md border p-2 text-xs ${warningSeverityClass(warning.severity)}`}>
                      <div className="flex items-center gap-1.5 font-mono font-medium">
                        <AlertTriangle className="size-3.5" />
                        {warning.code}
                      </div>
                      <div className="mt-1 text-foreground/85">{warning.message}</div>
                    </div>
                  ))}
                </div>
              ) : null}
              <EditorFrame
                value={sourceQuery}
                onChange={setSourceQuery}
                label="Source query editor"
                placeholder="Paste a Sigma YAML, Splunk SPL, Sentinel KQL, Elastic query, or raw OCI Logan QL query here..."
                testId="source-query-editor"
              />
              <div className="flex flex-wrap items-center gap-2 border-t border-border/70 bg-surface-raised/60 p-3">
                <Button
                  onClick={convert}
                  disabled={converting || (!staticExport && !csrfToken)}
                  className="btn-brand h-9"
                  data-testid="convert-button"
                >
                  <Play className="size-4" />
                  {converting ? "Converting…" : "Convert"}
                </Button>
                <Button variant="outline" size="sm" className="h-9" onClick={() => setSourceQuery("")}>
                  Clear
                </Button>
                {blockingWarningCount ? (
                  <span className="ml-auto inline-flex items-center gap-1 text-xs text-severity-critical">
                    <AlertTriangle className="size-3.5" />
                    {blockingWarningCount} blocking
                  </span>
                ) : null}
                {error ? (
                  <span className="inline-flex items-center gap-1 text-sm text-severity-critical" data-testid="conversion-error">
                    <AlertTriangle className="size-4" />
                    {error}
                  </span>
                ) : null}
              </div>
            </div>

            {/* Directional flow connector (decorative on wide screens) */}
            <div className="hidden items-center justify-center lg:flex" aria-hidden="true">
              <div className="relative flex size-9 items-center justify-center rounded-full border border-border-strong/70 bg-surface-raised text-primary shadow-[0_6px_18px_-10px_hsl(var(--primary)/0.7)]">
                <ArrowRight className="size-4" />
                <span className="absolute inset-0 rounded-full bg-primary/30 opacity-60 motion-safe:animate-ping-soft" />
              </div>
            </div>

            {/* Target / output panel */}
            <div className="console-panel flex min-h-[480px] flex-col overflow-hidden xl:min-h-0">
              <div className="flex flex-wrap items-center gap-2 border-b border-border/70 bg-surface-raised/60 px-3 py-2.5">
                <span className="eyebrow inline-flex items-center gap-1.5 text-severity-ok">
                  <Clipboard className="size-3.5" />
                  OCI Logan QL
                </span>
                {result ? (
                  <span
                    className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${supportBadgeClass(result.support_level)}`}
                    data-testid="support-level"
                  >
                    {result.support_level}
                  </span>
                ) : null}
                {result?.backend ? (
                  <span className="rounded border border-border bg-surface-sunken/60 px-2 py-0.5 font-mono text-[10px] text-muted-foreground" data-testid="forge-backend">
                    {result.backend}
                  </span>
                ) : null}
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground tabular-nums">
                  {lineCount(displayOutput)} ln
                </span>
                <div className="ml-auto flex items-center gap-1.5">
                  <Button variant="outline" size="icon" className="size-8" onClick={copyOutput} disabled={!output} title="Copy Logan QL" aria-label="Copy Logan QL">
                    {copied ? <Check className="size-4 text-severity-ok" /> : <Copy className="size-4" />}
                  </Button>
                  <Button variant="outline" size="icon" className="size-8" onClick={downloadOutput} disabled={!result} title="Download conversion JSON" aria-label="Download conversion JSON">
                    <Download className="size-4" />
                  </Button>
                  <Button variant="outline" size="icon" className="size-8" onClick={shareOutput} title="Copy share link" aria-label="Copy share link">
                    {shared ? <Check className="size-4 text-severity-ok" /> : <Link2 className="size-4" />}
                  </Button>
                  <Button size="sm" className="btn-brand h-8" onClick={deploy} disabled={readOnly || !output}>
                    Deploy
                  </Button>
                </div>
              </div>
              <EditorFrame
                value={displayOutput}
                label="OCI Logan QL output"
                placeholder="Conversion output appears here."
                wrapLines
                testId="logan-query-output"
              />
              <div className="border-t border-border/70">
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
                  <div className="mb-3 rounded-md border border-border/70 bg-surface-sunken/40 p-3 text-sm text-muted-foreground">
                    {result?.explanation ?? "Run a conversion to see backend guidance."}
                  </div>
                  {result?.warnings.length ? (
                    <div className="mb-3 grid gap-2">
                      {result.warnings.map((item) => (
                        <div key={`${item.code}-${item.message}`} className={`rounded-md border p-2 text-xs ${warningSeverityClass(item.severity)}`}>
                          <div className="font-mono font-medium">{item.code}</div>
                          <div className="mt-1 text-foreground/85">{item.message}</div>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <MetadataPanel tab={metadataTab} metadata={derivedMetadata} />
                </div>
              </div>
            </div>
          </section>

          {/* Reference / command menu (consumes generated reference catalog) */}
          {showDocs ? (
            <aside id="commands" className="console-rail flex min-h-[420px] flex-col overflow-hidden xl:min-h-0">
              <div className="border-b border-border/70 p-3">
                <div className="mb-2.5 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <BookOpen className="size-4 text-primary" />
                    <span className="text-sm font-semibold">Command reference</span>
                  </div>
                  <Button variant="ghost" size="icon" className="size-7" onClick={() => setDocsOpen(false)} aria-label="Close reference panel">
                    <X className="size-4" />
                  </Button>
                </div>
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={commandSearch}
                    onChange={(event) => setCommandSearch(event.target.value)}
                    placeholder="Search Oracle commands"
                    className="h-9 border-border bg-surface-sunken/50 pl-8"
                  />
                </div>
              </div>
              <div className="min-h-0 flex-1 overflow-auto p-3">
                <div className="mb-3 rounded-md border border-border/70 bg-surface-sunken/40 p-3 text-[11px] leading-5 text-muted-foreground">
                  Entries are loaded from the generated OCI reference catalog and link to the official Oracle docs.
                </div>
                <div className="grid gap-2">
                  {filteredCommands.slice(0, 18).map((command) => (
                    <a
                      key={command.name}
                      href={command.source_url}
                      target="_blank"
                      rel="noreferrer"
                      className="group rounded-lg border border-border/70 bg-surface-raised/40 p-3 transition-colors hover:border-primary/40 hover:bg-accent/40"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <code className="font-mono text-sm font-medium text-primary">{command.name}</code>
                        <ExternalLink className="size-3.5 text-muted-foreground transition-colors group-hover:text-primary" />
                      </div>
                      <p className="mt-1 line-clamp-3 text-[11px] leading-5 text-muted-foreground">{command.summary}</p>
                      <pre className="mt-2 overflow-hidden text-ellipsis rounded bg-[hsl(var(--code-bg))] p-2 font-mono text-[11px] text-foreground/80">
                        {command.syntax}
                      </pre>
                    </a>
                  ))}
                </div>

                <div className="mt-5 border-t border-border/70 pt-4">
                  <div className="mb-2.5 flex items-center gap-2 text-sm font-semibold">
                    <Table className="size-4 text-primary" />
                    Cross-QL mapping
                  </div>
                  <div className="grid gap-2">
                    {activePatterns.slice(0, 6).map((pattern) => (
                      <div key={pattern.id} className="rounded-lg border border-border/70 bg-surface-raised/40 p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium text-foreground">{pattern.source_construct}</span>
                          <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${supportBadgeClass(pattern.support_level)}`}>
                            {pattern.support_level}
                          </span>
                        </div>
                        <p className="mt-1 text-[11px] leading-5 text-muted-foreground">{pattern.oci_mapping}</p>
                        <div className="mt-2 flex flex-wrap gap-1">
                          {pattern.logan_commands.map((command) => (
                            <span key={command} className="rounded border border-border bg-surface-sunken/60 px-1.5 py-0.5 font-mono text-[10px] text-foreground/80">
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
            className="fixed right-0 top-1/2 z-40 hidden -translate-y-1/2 flex-col items-center gap-1 rounded-l-lg border border-r-0 border-border bg-surface-raised px-2 py-3 text-[11px] font-medium text-muted-foreground shadow-lg transition-colors hover:text-foreground xl:inline-flex"
          >
            <BookOpen className="size-4 text-primary" />
            Reference
          </button>
        ) : null}

        {auditOpen ? (
          <div className="fixed inset-0 z-50 flex items-end bg-[hsl(224_60%_3%/0.7)] p-3 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Security audit log">
            <div className="console-panel surface-grain mx-auto flex max-h-[70vh] w-full max-w-5xl flex-col overflow-hidden">
              <div className="flex items-center gap-2 border-b border-border/70 bg-surface-raised/60 p-3">
                <History className="size-4 text-primary" />
                <div className="text-sm font-semibold">Security audit log</div>
                <span className="rounded-md bg-primary/12 px-2 py-0.5 font-mono text-[11px] text-primary tabular-nums">{audit.length}</span>
                <Button variant="outline" size="sm" className="ml-auto" onClick={() => setAuditOpen(false)}>
                  Close
                </Button>
              </div>
              <div className="overflow-auto p-3">
                <div className="grid min-w-[760px] grid-cols-[100px_120px_160px_1fr_80px] gap-2 border-b border-border/70 pb-2 eyebrow">
                  <span>Time</span>
                  <span>Action</span>
                  <span>Target</span>
                  <span>Detail</span>
                  <span>Status</span>
                </div>
                {audit.map((entry) => (
                  <div
                    key={entry.id}
                    className="grid min-w-[760px] grid-cols-[100px_120px_160px_1fr_80px] gap-2 border-b border-border/50 py-2 text-xs"
                  >
                    <span className="font-mono text-muted-foreground tabular-nums">{entry.time}</span>
                    <span className="font-mono font-medium text-foreground">{entry.action}</span>
                    <span className="truncate text-muted-foreground">{entry.target}</span>
                    <span className="text-foreground/85">{entry.detail}</span>
                    <span className={`rounded px-2 py-0.5 text-center text-[10px] font-semibold uppercase ${auditStatusClass(entry.status)}`}>{entry.status}</span>
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
