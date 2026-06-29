"use client"

import { AlertTriangle, FileJson2 } from "lucide-react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { useCallback, useMemo } from "react"

import {
  type DetectionOutput,
  type LogSamplesTab,
  parseLogSamplesState,
} from "@/lib/log-samples-data"
import type { SiemLogExamplesCatalog } from "@/lib/siem-log-examples-contract"
import { BenefitsView } from "./benefits-view"
import { DetectionView } from "./detection-view"
import { RawLogView } from "./raw-log-view"

const tabLabels: Record<LogSamplesTab, string> = {
  raw: "Raw service logs",
  detections: "Logan detections",
  benefits: "Why pre-analyze",
}

export function LogSamplesWorkspace({
  catalog,
  error,
}: {
  catalog: SiemLogExamplesCatalog | null
  error: string | null
}) {
  const searchParams = useSearchParams()
  const pathname = usePathname()
  const router = useRouter()

  const state = useMemo(
    () => parseLogSamplesState(
      new URLSearchParams(searchParams.toString()),
      catalog?.raw_log_samples.map((sample) => sample.id) ?? [],
      catalog?.detection_samples.map((sample) => sample.id) ?? [],
    ),
    [catalog, searchParams],
  )

  const updateUrl = useCallback((next: { tab?: LogSamplesTab; sampleId?: string; output?: DetectionOutput }) => {
    const params = new URLSearchParams(searchParams.toString())
    params.set("view", "log-samples")
    if (next.tab) params.set("tab", next.tab)
    if (next.sampleId) params.set("sample", next.sampleId)
    if (next.output) params.set("output", next.output)
    router.replace(`${pathname}?${params.toString()}`, { scroll: false })
  }, [pathname, router, searchParams])

  if (!catalog) {
    return (
      <main className="console-atmosphere flex min-h-[calc(100vh-60px)] items-center justify-center p-6">
        <div className="console-panel max-w-lg p-6 text-center">
          <AlertTriangle className="mx-auto size-6 text-severity-critical" />
          <h1 className="mt-3 text-lg font-semibold">Log sample artifact unavailable</h1>
          <p className="mt-2 text-sm text-muted-foreground">{error ?? "The generated artifact could not be loaded."}</p>
        </div>
      </main>
    )
  }

  const rawSelected = catalog.raw_log_samples.find((sample) => sample.id === state.sampleId) ?? catalog.raw_log_samples[0]
  const detectionSelected = catalog.detection_samples.find((sample) => sample.id === state.sampleId) ?? catalog.detection_samples[0]

  const selectTab = (tab: LogSamplesTab) => {
    const sampleId = tab === "detections" ? catalog.detection_samples[0].id : catalog.raw_log_samples[0].id
    updateUrl({ tab, sampleId, output: "normalized" })
  }

  return (
    <main
      className="console-atmosphere min-h-[calc(100vh-60px)] overflow-hidden p-3 sm:p-4"
      data-testid="log-samples-workspace"
    >
      <div className="mx-auto flex min-h-[calc(100vh-92px)] max-w-[1680px] flex-col">
        <section className="console-panel surface-grain flex flex-wrap items-center gap-4 px-5 py-4">
          <span className="flex size-11 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-[0_8px_24px_-12px_hsl(var(--primary)/0.8)]">
            <FileJson2 className="size-5" />
          </span>
          <div className="min-w-0">
            <h1 className="font-display text-xl font-semibold tracking-tight sm:text-2xl">OCI Log Sample Library</h1>
            <p className="mt-1 text-xs text-muted-foreground sm:text-sm">Parser-ready OCI service events with safe placeholders.</p>
          </div>
          <div className="ml-auto hidden text-right text-[11px] text-muted-foreground md:block">
            <div>Generated artifact</div>
            <div className="mt-0.5 font-mono">{catalog.generated_at}</div>
          </div>
        </section>

        <nav className="mt-2 flex items-center gap-1 rounded-panel border border-border bg-surface-raised/85 p-1.5" aria-label="Log sample modes">
          {(Object.keys(tabLabels) as LogSamplesTab[]).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => selectTab(tab)}
              aria-pressed={state.tab === tab}
              className={`rounded-md px-3 py-2 text-xs font-medium transition-colors ${
                state.tab === tab
                  ? "bg-primary/15 text-primary shadow-sm ring-1 ring-inset ring-primary/35"
                  : "text-muted-foreground hover:bg-accent/40 hover:text-foreground"
              }`}
            >
              {tabLabels[tab]}
            </button>
          ))}
        </nav>

        <div className="mt-2 flex min-h-0 flex-1">
          {state.tab === "raw" ? (
            <RawLogView
              samples={catalog.raw_log_samples}
              selected={rawSelected}
              onSelect={(sampleId) => updateUrl({ tab: "raw", sampleId })}
              placeholderDescription={catalog.placeholder_policy.description}
            />
          ) : null}
          {state.tab === "detections" ? (
            <DetectionView
              catalog={catalog}
              selected={detectionSelected}
              output={state.output}
              onSelect={(sampleId) => updateUrl({ tab: "detections", sampleId })}
              onOutput={(output) => updateUrl({ tab: "detections", sampleId: detectionSelected.id, output })}
            />
          ) : null}
          {state.tab === "benefits" ? <BenefitsView catalog={catalog} /> : null}
        </div>
      </div>
    </main>
  )
}
