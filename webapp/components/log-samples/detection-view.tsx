"use client"

import {
  AlertTriangle,
  ArrowRight,
  BellRing,
  Braces,
  ChevronRight,
  Database,
  Filter,
  Network,
  Search,
  ShieldCheck,
} from "lucide-react"
import { useMemo, useState } from "react"

import { Input } from "@/components/ui/input"
import type { DetectionOutput } from "@/lib/log-samples-data"
import {
  downloadFilename,
  filterDetectionSamples,
  serializeDetectionJsonl,
} from "@/lib/log-samples-data"
import type { DetectionSample, SiemLogExamplesCatalog } from "@/lib/siem-log-examples-contract"
import { JsonActions, JsonViewer } from "./log-samples-shared"

function severityClass(severity: DetectionSample["severity"]) {
  return severity === "critical" ? "text-severity-critical" : "text-severity-high"
}

function PathStep({ icon: Icon, label }: { icon: typeof Database; label: string }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col items-center gap-2 text-center">
      <span className="flex size-10 items-center justify-center rounded-lg border border-border-strong bg-surface-sunken text-severity-ok">
        <Icon className="size-4" />
      </span>
      <span className="text-[11px] leading-4 text-muted-foreground">{label}</span>
    </div>
  )
}

function ForwardingPath({ labels, normalized = false }: { labels: string[]; normalized?: boolean }) {
  const icons = normalized ? [Search, Braces, ShieldCheck] : [Database, Network, BellRing]
  return (
    <div className="flex items-start gap-1">
      {labels.map((label, index) => (
        <div key={label} className="contents">
          <PathStep icon={icons[index] ?? Database} label={label} />
          {index < labels.length - 1 ? <ArrowRight className="mt-3 size-3.5 shrink-0 text-muted-foreground" /> : null}
        </div>
      ))}
    </div>
  )
}

export function DetectionView({
  catalog,
  selected,
  output,
  onSelect,
  onOutput,
}: {
  catalog: SiemLogExamplesCatalog
  selected: DetectionSample
  output: DetectionOutput
  onSelect: (id: string) => void
  onOutput: (output: DetectionOutput) => void
}) {
  const [search, setSearch] = useState("")
  const filtered = useMemo(
    () => filterDetectionSamples(catalog.detection_samples, search),
    [catalog.detection_samples, search],
  )
  const rawEvidence = catalog.raw_log_samples.find((sample) => selected.primary_raw_sample_ids.includes(sample.id))
    ?? catalog.raw_log_samples[0]
  const outputValue = output === "native" ? selected.native_alarm : selected.normalized_detection
  const outputTitle = output === "native" ? "Native OCI alarm JSON" : "Normalized SIEM detection JSON"

  return (
    <section className="grid min-h-0 flex-1 gap-3 xl:grid-cols-[260px_minmax(0,1fr)_300px]">
      <aside className="console-rail flex min-h-[420px] flex-col overflow-hidden xl:min-h-0">
        <div className="border-b border-border/70 p-3">
          <div className="mb-2.5 flex items-center justify-between">
            <span className="text-sm font-semibold">Top 10 security use cases</span>
            <span className="font-mono text-[11px] text-muted-foreground">curated</span>
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search use cases"
              className="h-9 bg-surface-sunken/50 pl-8 text-sm"
            />
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-2">
          {filtered.map((detection, index) => {
            const active = detection.id === selected.id
            return (
              <button
                key={detection.id}
                type="button"
                data-testid="detection-sample-row"
                aria-label={detection.display_title}
                aria-pressed={active}
                onClick={() => onSelect(detection.id)}
                className={`group flex w-full gap-2 border-b border-border/60 px-2.5 py-3 text-left transition-colors ${
                  active ? "border-l-2 border-l-primary bg-primary/8" : "border-l-2 border-l-transparent hover:bg-accent/45"
                }`}
              >
                <span className={`w-5 shrink-0 font-mono text-xs font-semibold ${active ? "text-primary" : "text-muted-foreground"}`}>
                  {index + 1}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-xs font-medium leading-4">{detection.display_title}</span>
                  <span className="mt-1 block text-[10px] text-muted-foreground">
                    <span className={severityClass(detection.severity)}>{detection.severity}</span>
                    {" · "}{detection.metric_name}
                  </span>
                </span>
                <ChevronRight className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
              </button>
            )
          })}
        </div>
      </aside>

      <section className="console-panel flex min-h-[620px] min-w-0 flex-col overflow-hidden xl:min-h-0">
        <header className="flex flex-wrap items-center gap-3 border-b border-border/70 bg-surface-raised/60 px-3 py-2.5">
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-sm font-semibold">Raw events → detection signal</h2>
            <p className="truncate text-[11px] text-muted-foreground">{selected.display_title}</p>
          </div>
          <JsonActions
            value={outputValue}
            jsonFilename={downloadFilename("detection", `${selected.id}-${output}`, "json")}
            jsonl={serializeDetectionJsonl(catalog.detection_samples, output)}
            jsonlFilename={`oci-log-detection-${output}-all-use-cases.jsonl`}
            copyLabel="Copy detection"
          />
        </header>
        <div className="flex flex-wrap items-center gap-2 border-b border-border/70 bg-surface-sunken/35 px-3 py-2">
          <span className="mr-auto text-[11px] text-muted-foreground">
            {selected.primary_raw_sample_ids.length} source format{selected.primary_raw_sample_ids.length === 1 ? "" : "s"} · {selected.severity}
          </span>
          <button
            type="button"
            onClick={() => onOutput("normalized")}
            aria-pressed={output === "normalized"}
            className={`rounded-md px-2.5 py-1.5 text-[11px] font-medium ${output === "normalized" ? "bg-primary/15 text-primary ring-1 ring-primary/40" : "text-muted-foreground hover:text-foreground"}`}
          >
            Normalized SIEM JSON
          </button>
          <button
            type="button"
            onClick={() => onOutput("native")}
            aria-pressed={output === "native"}
            className={`rounded-md px-2.5 py-1.5 text-[11px] font-medium ${output === "native" ? "bg-primary/15 text-primary ring-1 ring-primary/40" : "text-muted-foreground hover:text-foreground"}`}
          >
            Native OCI alarm
          </button>
        </div>
        <div className="grid min-h-0 flex-1 gap-px bg-border/70 lg:grid-cols-[minmax(0,0.9fr)_2rem_minmax(0,1.1fr)]">
          <div className="flex min-h-[320px] min-w-0 flex-col bg-surface-raised">
            <div className="flex items-center justify-between border-b border-border/70 px-3 py-2 text-xs font-semibold">
              <span>Raw OCI events</span>
              <span className="font-normal text-muted-foreground">Representative {rawEvidence.service}</span>
            </div>
            <JsonViewer value={rawEvidence.event} testId="raw-evidence-output" className="flex-1" />
          </div>
          <div className="hidden items-center justify-center bg-surface-raised lg:flex" aria-hidden="true">
            <span className="flex size-8 items-center justify-center rounded-full border border-primary/50 bg-primary/10 text-primary">
              <ArrowRight className="size-4" />
            </span>
          </div>
          <div className="flex min-h-[320px] min-w-0 flex-col bg-surface-raised">
            <div className="flex items-center justify-between border-b border-border/70 px-3 py-2 text-xs font-semibold">
              <span>{outputTitle}</span>
              <span className="font-normal text-muted-foreground">{selected.metric_name}</span>
            </div>
            <JsonViewer value={outputValue} className="flex-1" />
          </div>
        </div>
      </section>

      <aside className="console-rail min-h-[420px] overflow-auto p-4 xl:min-h-0" data-testid="forwarding-paths">
        <h2 className="border-b border-border/70 pb-3 text-sm font-semibold">Forwarding paths</h2>
        <section className="py-4">
          <h3 className="mb-3 text-xs font-semibold">Native OCI path</h3>
          <ForwardingPath labels={catalog.comparison.native_path} />
        </section>
        <section className="border-t border-border/70 py-4">
          <h3 className="mb-3 text-xs font-semibold">Normalized path</h3>
          <ForwardingPath labels={catalog.comparison.normalized_path} normalized />
        </section>
        <section className="border-t border-border/70 py-4">
          <h3 className="mb-3 text-xs font-semibold">Why analyze first</h3>
          <ul className="space-y-2 text-[11px] leading-4 text-muted-foreground">
            {catalog.comparison.advantages.map((advantage) => (
              <li key={advantage} className="flex gap-2">
                <span className="mt-1 text-severity-ok">✓</span>
                <span>{advantage}</span>
              </li>
            ))}
          </ul>
        </section>
        <div className="rounded-md border border-primary/35 bg-primary/5 p-3 text-[11px] leading-4 text-primary">
          <AlertTriangle className="mb-2 size-4" />
          {catalog.comparison.caution}
        </div>
        <div className="mt-4 flex items-start gap-2 border-t border-border/70 pt-4 text-[10px] leading-4 text-muted-foreground">
          <Filter className="mt-0.5 size-3.5 shrink-0 text-severity-info" />
          Normalized detections are project-defined. Native Logan rules post metrics consumed by OCI Monitoring alarms.
        </div>
      </aside>
    </section>
  )
}
