import { Database } from "lucide-react"

import type { DerivedMetadata, MetadataTab } from "./forge-workbench-data"
import { lineCount } from "./forge-workbench-data"

export function EditorFrame({
  value,
  onChange,
  readOnly = false,
  label,
  placeholder,
  wrapLines = false,
  testId,
}: {
  value: string
  onChange?: (value: string) => void
  readOnly?: boolean
  label: string
  placeholder?: string
  wrapLines?: boolean
  testId?: string
}) {
  const lines = Math.max(1, lineCount(value))

  return (
    <div className="grid min-h-0 flex-1 grid-cols-[3rem_minmax(0,1fr)] overflow-hidden bg-[hsl(var(--code-bg))]">
      <div className="select-none overflow-hidden border-r border-border/70 bg-surface-sunken/60 px-2 py-4 text-right font-mono text-[11px] leading-6 text-muted-foreground/70 tabular-nums">
        {Array.from({ length: lines }, (_, index) => (
          <div key={index}>{index + 1}</div>
        ))}
      </div>
      {onChange ? (
        <textarea
          value={value}
          onChange={(event) => onChange(event.target.value)}
          spellCheck={false}
          wrap="off"
          readOnly={readOnly}
          className="min-h-[280px] flex-1 resize-none overflow-auto whitespace-pre bg-transparent p-4 font-mono text-[13px] leading-6 text-foreground caret-primary outline-none placeholder:text-muted-foreground/60"
          aria-label={label}
          data-testid={testId}
          placeholder={placeholder}
        />
      ) : (
        <pre
          className={`min-h-[280px] flex-1 overflow-auto bg-transparent p-4 font-mono text-[13px] leading-6 text-foreground ${
            wrapLines ? "whitespace-pre-wrap break-words" : "whitespace-pre"
          }`}
          aria-label={label}
          data-testid={testId}
        >
          {value || <span className="text-muted-foreground/55">{placeholder}</span>}
        </pre>
      )}
    </div>
  )
}

export function MetadataTabs({
  active,
  onChange,
  counts,
}: {
  active: MetadataTab
  onChange: (tab: MetadataTab) => void
  counts: Record<MetadataTab, number | undefined>
}) {
  const tabs: Array<{ id: MetadataTab; label: string }> = [
    { id: "mitre", label: "MITRE" },
    { id: "stig", label: "STIG" },
    { id: "fields", label: "Field map" },
    { id: "sources", label: "Log sources" },
    { id: "metadata", label: "Metadata" },
    { id: "sample", label: "Sample event" },
  ]

  return (
    <div
      role="tablist"
      aria-label="Conversion intelligence"
      className="flex min-w-0 gap-1 overflow-x-auto border-b border-border/70 bg-surface-sunken/50 px-2 py-2"
    >
      {tabs.map((tab) => {
        const isActive = active === tab.id
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(tab.id)}
            className={`group inline-flex h-8 shrink-0 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium transition-colors duration-150 ${
              isActive
                ? "bg-primary/15 text-primary ring-1 ring-inset ring-primary/40"
                : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
            }`}
          >
            {tab.label}
            {typeof counts[tab.id] === "number" ? (
              <span
                className={`rounded px-1.5 py-0.5 font-mono text-[10px] tabular-nums ${
                  isActive ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                }`}
              >
                {counts[tab.id]}
              </span>
            ) : null}
          </button>
        )
      })}
    </div>
  )
}

export function MetadataPanel({ tab, metadata }: { tab: MetadataTab; metadata: DerivedMetadata }) {
  if (tab === "mitre") {
    return metadata.mitre.length ? (
      <div className="grid gap-2 sm:grid-cols-2">
        {metadata.mitre.map((item) => (
          <div
            key={item.id}
            className="rounded-md border border-border/70 bg-surface-sunken/40 p-3 transition-colors hover:border-primary/40"
          >
            <div className="font-mono text-xs text-primary">{item.id}</div>
            <div className="mt-1 text-sm font-medium text-foreground">{item.name}</div>
            <div className="mt-1 text-xs text-muted-foreground">{item.tactic}</div>
          </div>
        ))}
      </div>
    ) : (
      <EmptyState label="No MITRE techniques mapped for this query yet." />
    )
  }

  if (tab === "stig") {
    return metadata.stig.length ? (
      <div className="grid gap-2">
        {metadata.stig.map((item) => (
          <div
            key={item.id}
            className="grid gap-2 rounded-md border border-border/70 bg-surface-sunken/40 p-3 sm:grid-cols-[90px_1fr_auto]"
          >
            <code className="text-xs text-primary">{item.id}</code>
            <span className="text-sm">{item.title}</span>
            <span className="rounded border border-border-strong/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              {item.severity}
            </span>
          </div>
        ))}
      </div>
    ) : (
      <EmptyState label="No STIG controls tied to this detection." />
    )
  }

  if (tab === "fields") {
    return metadata.fields.length ? (
      <div className="overflow-auto rounded-md border border-border/70">
        <table className="w-full min-w-[560px] text-left text-xs">
          <thead className="bg-surface-sunken/60 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">Source field</th>
              <th className="px-3 py-2 font-medium">OCI Log Analytics field</th>
              <th className="px-3 py-2 font-medium">Mapping note</th>
            </tr>
          </thead>
          <tbody>
            {metadata.fields.map((item) => (
              <tr key={`${item.source}-${item.oci}`} className="border-t border-border/60 transition-colors hover:bg-accent/40">
                <td className="px-3 py-2 font-mono text-foreground">{item.source}</td>
                <td className="px-3 py-2 font-mono text-primary">{item.oci}</td>
                <td className="px-3 py-2 text-muted-foreground">{item.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <EmptyState label="No field map entries available." />
    )
  }

  if (tab === "sources") {
    return (
      <div className="grid gap-2">
        {metadata.logSources.map((item) => (
          <div
            key={item.name}
            className="flex items-center gap-3 rounded-md border border-border/70 bg-surface-sunken/40 p-3"
          >
            <span className="flex size-8 items-center justify-center rounded-md bg-primary/12 text-primary">
              <Database className="size-4" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium text-foreground">{item.name}</div>
              <div className="text-xs text-muted-foreground">{item.events}</div>
            </div>
            <span className="rounded border border-border-strong/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              {item.status}
            </span>
          </div>
        ))}
      </div>
    )
  }

  if (tab === "metadata") {
    return (
      <dl className="grid gap-y-2 text-sm sm:grid-cols-[140px_1fr]">
        {metadata.metadata.map((item) => (
          <div key={item.label} className="contents">
            <dt className="eyebrow self-center text-[10px]">{item.label}</dt>
            <dd className="min-w-0 break-words font-mono text-xs text-foreground">{item.value}</dd>
          </div>
        ))}
      </dl>
    )
  }

  return (
    <pre className="overflow-auto rounded-md border border-border/70 bg-[hsl(var(--code-bg))] p-3 font-mono text-xs leading-5 text-foreground">
      {JSON.stringify(
        Object.fromEntries(metadata.sampleEvent.map((item) => [item.field, item.value])),
        null,
        2,
      )}
    </pre>
  )
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="rounded-md border border-dashed border-border-strong/60 bg-surface-sunken/30 p-4 text-sm text-muted-foreground">
      {label}
    </div>
  )
}
