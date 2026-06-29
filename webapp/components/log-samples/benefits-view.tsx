import { AlertTriangle, ArrowRight, Braces, Database, Filter, GitBranch, ShieldCheck } from "lucide-react"

import type { SiemLogExamplesCatalog } from "@/lib/siem-log-examples-contract"

function Flow({ labels, normalized = false }: { labels: string[]; normalized?: boolean }) {
  const icons = normalized ? [Filter, Braces, ShieldCheck] : [Database, GitBranch, ShieldCheck]
  return (
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
      {labels.map((label, index) => {
        const Icon = icons[index] ?? Database
        return (
          <div key={label} className="contents">
            <div className="flex flex-1 items-center gap-3 rounded-md border border-border/70 bg-surface-sunken/55 p-3">
              <Icon className={`size-4 shrink-0 ${normalized ? "text-severity-ok" : "text-severity-info"}`} />
              <span className="text-xs font-medium">{label}</span>
            </div>
            {index < labels.length - 1 ? <ArrowRight className="mx-auto size-4 rotate-90 text-muted-foreground sm:rotate-0" /> : null}
          </div>
        )
      })}
    </div>
  )
}

export function BenefitsView({ catalog }: { catalog: SiemLogExamplesCatalog }) {
  return (
    <section className="console-panel min-h-0 flex-1 overflow-auto p-5 sm:p-7">
      <div className="mx-auto max-w-6xl">
        <div className="max-w-3xl">
          <h2 className="font-display text-2xl font-semibold tracking-tight sm:text-3xl">Why analyze in Logan first</h2>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            Keep OCI-native parsing, correlation, and detection close to the source, then send a smaller and more consistent security signal to the downstream SIEM.
          </p>
        </div>

        <div className="mt-7 grid gap-4 lg:grid-cols-2">
          <section className="rounded-panel border border-border bg-surface-raised/65 p-5">
            <h3 className="text-sm font-semibold">Native OCI detection path</h3>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Detection rules post metrics. OCI Monitoring evaluates those metrics and emits a documented alarm message.
            </p>
            <div className="mt-4"><Flow labels={catalog.comparison.native_path} /></div>
          </section>
          <section className="rounded-panel border border-border bg-surface-raised/65 p-5">
            <h3 className="text-sm font-semibold">Normalized SIEM path</h3>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              A project-defined event contract carries rule, entity, MITRE, evidence, and OCI context in one predictable shape.
            </p>
            <div className="mt-4"><Flow labels={catalog.comparison.normalized_path} normalized /></div>
          </section>
        </div>

        <div className="mt-4 grid gap-px overflow-hidden rounded-panel border border-border bg-border md:grid-cols-4">
          {[
            ["Reduce noise", "Apply detection logic before low-value records reach the expensive downstream index."],
            ["Normalize fields", "Give SIEM parsers one stable detection contract across different OCI service payloads."],
            ["Correlate context", "Join identities, network flows, WAF activity, and cloud actions before forwarding."],
            ["Preserve evidence", "Reference the source formats and retain raw records in OCI for investigation."],
          ].map(([title, description]) => (
            <section key={title} className="bg-surface-raised p-4">
              <h3 className="text-xs font-semibold text-primary">{title}</h3>
              <p className="mt-2 text-[11px] leading-5 text-muted-foreground">{description}</p>
            </section>
          ))}
        </div>

        <div className="mt-4 grid gap-4 lg:grid-cols-[1fr_1.3fr]">
          <section className="rounded-panel border border-severity-info/35 bg-severity-info/5 p-4">
            <h3 className="text-sm font-semibold text-severity-info">No universal native SIEM event</h3>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">
              The native alarm JSON and the normalized detection JSON are intentionally shown as separate contracts. Transport-specific batching can add another outer wrapper.
            </p>
          </section>
          <section className="flex items-start gap-3 rounded-panel border border-primary/35 bg-primary/5 p-4">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-primary" />
            <div>
              <h3 className="text-sm font-semibold text-primary">Forensic and compliance boundary</h3>
              <p className="mt-2 text-xs leading-5 text-muted-foreground">{catalog.comparison.caution}</p>
            </div>
          </section>
        </div>
      </div>
    </section>
  )
}
