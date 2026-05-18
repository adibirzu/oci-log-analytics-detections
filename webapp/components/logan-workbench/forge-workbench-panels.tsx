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
}: {
  value: string
  onChange?: (value: string) => void
  readOnly?: boolean
  label: string
  placeholder?: string
  wrapLines?: boolean
}) {
  const lines = Math.max(1, lineCount(value))

  return (
    <div className="grid min-h-0 flex-1 grid-cols-[44px_minmax(0,1fr)] overflow-hidden bg-background/90">
      <div className="select-none overflow-hidden border-r bg-muted/35 px-2 py-4 text-right font-mono text-[11px] leading-6 text-muted-foreground">
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
          className="min-h-[300px] flex-1 resize-none overflow-auto whitespace-pre bg-transparent p-4 font-mono text-[13px] leading-6 outline-none placeholder:text-muted-foreground"
          aria-label={label}
          placeholder={placeholder}
        />
      ) : (
        <pre
          className={`min-h-[300px] flex-1 overflow-auto bg-transparent p-4 font-mono text-[13px] leading-6 ${
            wrapLines ? "whitespace-pre-wrap break-words" : "whitespace-pre"
          }`}
          aria-label={label}
        >
          {value || placeholder}
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
    <div className="flex min-w-0 gap-1 overflow-x-auto border-b bg-muted/20 px-2 py-2">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`inline-flex h-8 shrink-0 items-center gap-1 rounded-md px-2.5 text-xs font-medium transition ${
            active === tab.id ? "bg-[#c74634] text-white" : "text-muted-foreground hover:bg-muted hover:text-foreground"
          }`}
        >
          {tab.label}
          {typeof counts[tab.id] === "number" ? (
            <span className="rounded bg-background/25 px-1.5 py-0.5 font-mono text-[10px]">{counts[tab.id]}</span>
          ) : null}
        </button>
      ))}
    </div>
  )
}

export function MetadataPanel({ tab, metadata }: { tab: MetadataTab; metadata: DerivedMetadata }) {
  if (tab === "mitre") {
    return metadata.mitre.length ? (
      <div className="grid gap-2 sm:grid-cols-2">
        {metadata.mitre.map((item) => (
          <div key={item.id} className="rounded-md border bg-background/60 p-3">
            <div className="font-mono text-xs text-[#c74634]">{item.id}</div>
            <div className="mt-1 text-sm font-medium">{item.name}</div>
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
          <div key={item.id} className="grid gap-2 rounded-md border bg-background/60 p-3 sm:grid-cols-[90px_1fr_auto]">
            <code className="text-xs text-[#c74634]">{item.id}</code>
            <span className="text-sm">{item.title}</span>
            <span className="rounded border px-2 py-0.5 text-xs uppercase">{item.severity}</span>
          </div>
        ))}
      </div>
    ) : (
      <EmptyState label="No STIG controls tied to this detection." />
    )
  }

  if (tab === "fields") {
    return metadata.fields.length ? (
      <div className="overflow-auto rounded-md border">
        <table className="w-full min-w-[560px] text-left text-xs">
          <thead className="bg-muted/60 text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">Source field</th>
              <th className="px-3 py-2 font-medium">OCI Log Analytics field</th>
              <th className="px-3 py-2 font-medium">Mapping note</th>
            </tr>
          </thead>
          <tbody>
            {metadata.fields.map((item) => (
              <tr key={`${item.source}-${item.oci}`} className="border-t">
                <td className="px-3 py-2 font-mono">{item.source}</td>
                <td className="px-3 py-2 font-mono text-[#c74634]">{item.oci}</td>
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
          <div key={item.name} className="flex items-center gap-3 rounded-md border bg-background/60 p-3">
            <Database className="size-4 text-[#c74634]" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{item.name}</div>
              <div className="text-xs text-muted-foreground">{item.events}</div>
            </div>
            <span className="rounded border px-2 py-0.5 text-xs">{item.status}</span>
          </div>
        ))}
      </div>
    )
  }

  if (tab === "metadata") {
    return (
      <dl className="grid gap-2 text-sm sm:grid-cols-[140px_1fr]">
        {metadata.metadata.map((item) => (
          <div key={item.label} className="contents">
            <dt className="font-mono text-xs uppercase text-muted-foreground">{item.label}</dt>
            <dd className="min-w-0 break-words">{item.value}</dd>
          </div>
        ))}
      </dl>
    )
  }

  return (
    <pre className="overflow-auto rounded-md border bg-background/70 p-3 font-mono text-xs leading-5">
      {JSON.stringify(
        Object.fromEntries(metadata.sampleEvent.map((item) => [item.field, item.value])),
        null,
        2,
      )}
    </pre>
  )
}

function EmptyState({ label }: { label: string }) {
  return <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">{label}</div>
}
