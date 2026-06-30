"use client"

import { Check, Copy, Download } from "lucide-react"
import { useCallback, useState } from "react"

import { Button } from "@/components/ui/button"
import { serializeJson } from "@/lib/log-samples-data"

function JsonLine({ line }: { line: string }) {
  const keyed = line.match(/^(\s*)("(?:[^"\\]|\\.)+")(\s*:\s*)(.*)$/)
  if (!keyed) return <span className="text-foreground/80">{line || " "}</span>

  const [, indent, key, separator, value] = keyed
  const valueClass = value.startsWith('"')
    ? "text-severity-ok"
    : /^(true|false|null)[,]?$/.test(value)
      ? "text-severity-info"
      : /^-?\d/.test(value)
        ? "text-severity-medium"
        : "text-foreground/80"

  return (
    <>
      <span>{indent}</span>
      <span className="text-primary">{key}</span>
      <span className="text-muted-foreground">{separator}</span>
      <span className={valueClass}>{value}</span>
    </>
  )
}

export function JsonViewer({ value, testId = "json-output", className = "" }: { value: unknown; testId?: string; className?: string }) {
  const lines = serializeJson(value).split("\n")
  return (
    <div
      className={`min-h-0 overflow-auto bg-[hsl(var(--code-bg))] font-mono text-[11px] leading-5 sm:text-xs ${className}`}
      data-testid={testId}
      aria-label="JSON sample"
    >
      <pre className="min-w-max py-3">
        {lines.map((line, index) => (
          <span key={`${index}-${line.slice(0, 20)}`} className="grid grid-cols-[3rem_minmax(0,1fr)] px-3">
            <span className="select-none border-r border-border/60 pr-3 text-right text-muted-foreground/55 tabular-nums">
              {index + 1}
            </span>
            <code className="whitespace-pre pl-3"><JsonLine line={line} /></code>
          </span>
        ))}
      </pre>
    </div>
  )
}

function saveText(contents: string, filename: string, type: string) {
  const blob = new Blob([contents], { type })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export function JsonActions({
  value,
  jsonFilename,
  jsonl,
  jsonlFilename,
  copyLabel = "Copy JSON",
}: {
  value: unknown
  jsonFilename: string
  jsonl: string
  jsonlFilename: string
  copyLabel?: string
}) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(async () => {
    await navigator.clipboard.writeText(serializeJson(value))
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1500)
  }, [value])

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <Button variant="outline" size="sm" className="h-8" onClick={copy} aria-label={copyLabel}>
        {copied ? <Check className="size-3.5 text-severity-ok" /> : <Copy className="size-3.5" />}
        {copied ? "Copied" : copyLabel}
      </Button>
      <Button
        variant="outline"
        size="sm"
        className="h-8"
        onClick={() => saveText(`${serializeJson(value)}\n`, jsonFilename, "application/json")}
        aria-label="Download JSON"
      >
        <Download className="size-3.5" />
        Download JSON
      </Button>
      <Button
        variant="outline"
        size="sm"
        className="h-8"
        onClick={() => saveText(jsonl, jsonlFilename, "application/x-ndjson")}
        aria-label="Download JSONL"
      >
        <Download className="size-3.5" />
        Download JSONL
      </Button>
    </div>
  )
}

export function StatusDot({ className = "text-severity-ok" }: { className?: string }) {
  return <span className={`inline-block size-1.5 rounded-full bg-current ${className}`} aria-hidden="true" />
}
