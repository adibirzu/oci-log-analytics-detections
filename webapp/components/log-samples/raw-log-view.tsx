"use client"

import {
  Braces,
  ChevronRight,
  CloudCog,
  Container,
  ExternalLink,
  FileJson2,
  FunctionSquare,
  Network,
  Search,
  Shield,
  ShieldCheck,
  Waypoints,
} from "lucide-react"
import { useMemo, useState } from "react"

import { Input } from "@/components/ui/input"
import {
  downloadFilename,
  filterRawSamples,
  serializeRawJsonl,
} from "@/lib/log-samples-data"
import type { RawLogSample } from "@/lib/siem-log-examples-contract"
import { JsonActions, JsonViewer, StatusDot } from "./log-samples-shared"

const serviceIcons = {
  oci_audit: ShieldCheck,
  vcn_flow: Waypoints,
  load_balancer_access: Network,
  waf: Shield,
  network_firewall_threat: Container,
  api_gateway_access: CloudCog,
  functions_invoke: FunctionSquare,
  cloud_guard_raw: ShieldCheck,
  object_storage_access: Braces,
  custom_application: FileJson2,
} as const

const coverageLabels = {
  envelope: "Envelope represented today",
  payload: "Payload represented today",
  custom: "Custom dataset represented today",
  gap: "New parser sample",
} as const

export function RawLogView({
  samples,
  selected,
  onSelect,
  placeholderDescription,
}: {
  samples: RawLogSample[]
  selected: RawLogSample
  onSelect: (id: string) => void
  placeholderDescription: string
}) {
  const [search, setSearch] = useState("")
  const filtered = useMemo(() => filterRawSamples(samples, search), [samples, search])
  const envelopeKeys = Object.keys(selected.event).filter((key) => key !== "data")
  const payload = selected.event.data
  const payloadKeys = payload && typeof payload === "object" && !Array.isArray(payload)
    ? Object.keys(payload)
    : []

  return (
    <section className="grid min-h-0 flex-1 gap-3 xl:grid-cols-[280px_minmax(0,1fr)_300px]">
      <aside className="console-rail flex min-h-[360px] flex-col overflow-hidden xl:min-h-0">
        <div className="border-b border-border/70 p-3">
          <div className="mb-2.5 flex items-center justify-between">
            <span className="text-sm font-semibold">Service formats</span>
            <span className="font-mono text-[11px] text-muted-foreground">{samples.length} formats</span>
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search formats"
              className="h-9 bg-surface-sunken/50 pl-8 text-sm"
            />
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-2">
          {filtered.map((sample) => {
            const Icon = serviceIcons[sample.id as keyof typeof serviceIcons] ?? FileJson2
            const active = selected.id === sample.id
            return (
              <button
                key={sample.id}
                type="button"
                data-testid="raw-sample-row"
                aria-label={`${sample.service} ${sample.category}`}
                aria-pressed={active}
                onClick={() => onSelect(sample.id)}
                className={`group flex w-full items-center gap-3 border-b border-border/60 px-2.5 py-3 text-left transition-colors first:rounded-t-md last:rounded-b-md ${
                  active
                    ? "border-l-2 border-l-primary bg-primary/8"
                    : "border-l-2 border-l-transparent hover:bg-accent/45"
                }`}
              >
                <Icon className={`size-4 shrink-0 ${active ? "text-primary" : "text-muted-foreground"}`} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium">{sample.service}</span>
                  <span className="block truncate text-[11px] text-muted-foreground">{sample.category}</span>
                </span>
                <ChevronRight className="size-3.5 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
              </button>
            )
          })}
          {!filtered.length ? (
            <p className="p-4 text-center text-xs text-muted-foreground">No service formats match that search.</p>
          ) : null}
        </div>
      </aside>

      <section className="console-panel flex min-h-[560px] min-w-0 flex-col overflow-hidden xl:min-h-0">
        <header className="flex flex-wrap items-center gap-3 border-b border-border/70 bg-surface-raised/60 px-3 py-2.5">
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-sm font-semibold">{selected.service} — {selected.category}</h2>
            <p className="truncate text-[11px] text-muted-foreground">{selected.envelope_type}</p>
          </div>
          <JsonActions
            value={selected.event}
            jsonFilename={downloadFilename("raw", selected.id, "json")}
            jsonl={serializeRawJsonl(samples)}
            jsonlFilename="oci-log-raw-all-services.jsonl"
          />
        </header>
        <JsonViewer value={selected.event} className="flex-1" />
        <footer className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border/70 bg-surface-raised/60 px-4 py-2.5 text-[11px] text-muted-foreground">
          <span className="inline-flex items-center gap-2"><StatusDot /> Official OCI format</span>
          <span className="inline-flex items-center gap-2"><StatusDot /> Placeholder-safe</span>
          <span className="inline-flex items-center gap-2"><StatusDot /> Schema validated</span>
        </footer>
      </section>

      <aside className="console-rail min-h-[360px] overflow-auto p-4 xl:min-h-0" aria-label="Parser contract">
        <h2 className="border-b border-border/70 pb-3 text-sm font-semibold">Parser contract</h2>
        <div className="space-y-4 py-4 text-xs">
          <section>
            <h3 className="mb-2 font-semibold text-primary">Envelope</h3>
            <p className="mb-2 text-muted-foreground">{selected.envelope_type}</p>
            <ul className="space-y-1 font-mono text-[11px] text-foreground/85">
              {envelopeKeys.map((key) => <li key={key}>{key}</li>)}
            </ul>
          </section>
          <section className="border-t border-border/70 pt-4">
            <h3 className="mb-2 font-semibold text-primary">Service payload</h3>
            <p className="mb-2 text-muted-foreground">Required parser anchors in <code className="text-foreground">data</code></p>
            <ul className="space-y-1 font-mono text-[11px] text-foreground/85">
              {payloadKeys.slice(0, 14).map((key) => <li key={key}>{key}</li>)}
            </ul>
          </section>
          <section className="border-t border-border/70 pt-4">
            <h3 className="mb-2 font-semibold text-primary">Placeholder policy</h3>
            <p className="leading-5 text-muted-foreground">{placeholderDescription}</p>
            <code className="mt-2 block text-[11px] text-foreground">Example: &lt;TENANCY_OCID&gt;</code>
          </section>
          <section className="border-t border-border/70 pt-4">
            <h3 className="mb-2 font-semibold text-severity-ok">Repository coverage</h3>
            <p className="text-muted-foreground">{coverageLabels[selected.repository_coverage]}</p>
            {selected.repository_dataset ? (
              <code className="mt-2 block break-all text-[11px] text-foreground/80">{selected.repository_dataset}</code>
            ) : null}
          </section>
          <a
            href={selected.official_doc_url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center justify-between border-t border-border/70 pt-4 font-medium text-severity-info hover:text-foreground"
            aria-label="Official source"
          >
            Official source
            <ExternalLink className="size-3.5" />
          </a>
        </div>
      </aside>
    </section>
  )
}
