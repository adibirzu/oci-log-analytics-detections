"use client"

import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardList,
  Download,
  ExternalLink,
  FileStack,
  LayoutDashboard,
  ListChecks,
  PackageCheck,
  ShieldCheck,
  UploadCloud,
} from "lucide-react"
import { useState } from "react"

import { Button } from "@/components/ui/button"
import type { DeploymentContentSummary } from "@/lib/deployment-content"

const resourceManagerUrl = "https://cloud.oracle.com/resourcemanager/stacks"
const stackSourceUrl = "https://github.com/adibirzu/oci-log-analytics-detections/tree/main/stack"
const staticExport = process.env.NEXT_PUBLIC_FORGE_STATIC_EXPORT === "1"

function CountRow({ icon: Icon, label, value }: { icon: typeof FileStack; label: string; value: number }) {
  return (
    <div className="flex items-center justify-between border-b border-border/70 py-3 last:border-b-0">
      <div className="flex items-center gap-3 text-sm text-muted-foreground">
        <Icon className="size-4 text-severity-info" />
        <span>{label}</span>
      </div>
      <span className="font-mono text-base font-semibold text-foreground">{value.toLocaleString("en-US")}</span>
    </div>
  )
}

function FlowStep({ number, icon: Icon, title, detail, last = false }: {
  number: string
  icon: typeof Download
  title: string
  detail: string
  last?: boolean
}) {
  return (
    <div className="flex min-w-0 flex-1 items-start gap-3">
      <div className="flex size-8 shrink-0 items-center justify-center rounded-full border border-severity-info/50 bg-severity-info/10 font-mono text-xs font-semibold text-severity-info">
        {number}
      </div>
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-sm font-semibold"><Icon className="size-4 text-muted-foreground" />{title}</div>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</p>
      </div>
      {!last ? <ArrowRight className="mt-2 hidden size-4 shrink-0 text-muted-foreground xl:block" /> : null}
    </div>
  )
}

export function DeploymentWorkspace({ summary, error }: { summary: DeploymentContentSummary | null; error: string | null }) {
  const [acknowledged, setAcknowledged] = useState(false)
  const packageHref = staticExport ? stackSourceUrl : "/api/forge/deployment-package"

  return (
    <main className="console-atmosphere min-h-[calc(100vh-60px)] overflow-auto p-3 sm:p-4" data-testid="deployment-workspace">
      <div className="mx-auto max-w-[1500px] space-y-3">
        <section className="px-2 py-4 sm:px-5 sm:py-7">
          <h1 className="font-display text-2xl font-semibold tracking-tight sm:text-3xl">Deploy detection content to OCI Log Analytics</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-muted-foreground">
            This project converts and curates security detections, parser examples, saved searches, and dashboards for OCI Log Analytics. Resource Manager applies only the selected package to the OCI compartment you choose.
          </p>
        </section>

        <section className="console-panel grid overflow-hidden lg:grid-cols-[minmax(0,1fr)_minmax(300px,0.48fr)]">
          <div className="p-5 sm:p-6">
            <div className="flex items-start gap-4">
              <span className="flex size-11 shrink-0 items-center justify-center rounded-lg bg-severity-info/10 text-severity-info ring-1 ring-inset ring-severity-info/30"><FileStack className="size-5" /></span>
              <div>
                <h2 className="text-lg font-semibold">Resource Manager stack</h2>
                <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">
                  Download the generated package, create a stack in OCI Resource Manager, review its plan, and apply it in your selected compartment. Forge never receives your OCI credentials.
                </p>
              </div>
            </div>
            <div className="mt-5 border-t border-border/70 pt-4">
              <h3 className="text-sm font-semibold">Deployment guardrails</h3>
              <ul className="mt-3 space-y-2 text-xs leading-5 text-muted-foreground">
                <li className="flex gap-2"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-severity-ok" />Review the Terraform plan before apply; it can create or update Log Analytics content and declared supporting resources.</li>
                <li className="flex gap-2"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-severity-ok" />The selected OCI compartment, IAM policies, and Log Analytics service state remain under your control in the OCI Console.</li>
                <li className="flex gap-2"><ShieldCheck className="mt-0.5 size-4 shrink-0 text-severity-ok" />Raw logs are not exported by this workflow; the package contains rules, dashboard definitions, deployment code, and metadata.</li>
              </ul>
            </div>
          </div>
          <div className="border-t border-border/70 bg-surface-sunken/40 p-5 lg:border-l lg:border-t-0 sm:p-6">
            <label className="flex cursor-pointer items-start gap-3 rounded-md border border-border/80 bg-surface-raised/50 p-3 text-xs leading-5 text-muted-foreground">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(event) => setAcknowledged(event.target.checked)}
                className="mt-1 size-4 accent-[hsl(var(--primary))]"
              />
              <span>I understand that an apply affects my selected OCI compartment and requires the appropriate IAM permissions.</span>
            </label>
            <div className="mt-4 grid gap-2">
              <Button asChild className={`h-11 justify-center text-white ${acknowledged ? "" : "pointer-events-none opacity-50"}`}>
                <a
                  href={resourceManagerUrl}
                  target="_blank"
                  rel="noreferrer"
                  aria-disabled={!acknowledged}
                  tabIndex={acknowledged ? undefined : -1}
                ><UploadCloud className="size-4" />Open OCI Resource Manager<ExternalLink className="size-4" /></a>
              </Button>
              <Button asChild variant="outline" className="h-10 justify-center">
                <a href={packageHref} target={staticExport ? "_blank" : undefined} rel={staticExport ? "noreferrer" : undefined}>
                  <Download className="size-4" />{staticExport ? "View stack source" : "Download ORM package"}
                </a>
              </Button>
              <a className="mt-2 inline-flex items-center justify-center gap-2 text-xs font-medium text-severity-info hover:text-foreground" href="#deployment-contents">
                What gets deployed <ArrowRight className="size-3.5" />
              </a>
            </div>
          </div>
        </section>

        <section id="deployment-contents" className="grid gap-3 lg:grid-cols-2">
          <div className="console-panel p-5">
            <div className="flex items-center gap-3"><ClipboardList className="size-5 text-severity-info" /><h2 className="text-base font-semibold">Content included</h2></div>
            {summary ? (
              <div className="mt-3">
                <CountRow icon={FileStack} label="Detection query artifacts" value={summary.rules} />
                <CountRow icon={LayoutDashboard} label="Dashboards" value={summary.dashboards} />
                <CountRow icon={ListChecks} label="Dashboard saved searches" value={summary.savedSearches} />
              </div>
            ) : <p className="mt-4 text-sm text-muted-foreground">{error ?? "Deployment inventory is unavailable."}</p>}
          </div>
          <div className="console-panel p-5">
            <div className="flex items-center gap-3"><PackageCheck className="size-5 text-severity-ok" /><h2 className="text-base font-semibold">Before you run</h2></div>
            <ul className="mt-4 space-y-3 text-sm text-muted-foreground">
              {[
                "Select the intended OCI compartment.",
                "Confirm the required IAM policies and Log Analytics service access.",
                "Review every planned change in Resource Manager.",
                "Apply only after the plan matches your intended scope.",
              ].map((item) => <li key={item} className="flex gap-3"><CheckCircle2 className="mt-0.5 size-4 shrink-0 text-severity-ok" />{item}</li>)}
            </ul>
          </div>
        </section>

        <section className="console-panel p-5 sm:p-6">
          <h2 className="text-base font-semibold">How the deployment works</h2>
          <div className="mt-5 flex flex-col gap-5 xl:flex-row xl:items-start">
            <FlowStep number="1" icon={Download} title="Download package" detail="Get the Terraform stack and generated detection content." />
            <FlowStep number="2" icon={UploadCloud} title="Create stack in OCI" detail="Upload the package in Resource Manager while signed in to your tenancy." />
            <FlowStep number="3" icon={ClipboardList} title="Review plan" detail="Verify the exact resources and content that OCI will create or update." />
            <FlowStep number="4" icon={CheckCircle2} title="Apply to compartment" detail="Run the approved plan against the selected OCI compartment." last />
          </div>
        </section>

        <section className="flex items-start gap-3 rounded-panel border border-primary/45 bg-primary/5 p-4 text-sm leading-6">
          <AlertTriangle className="mt-0.5 size-5 shrink-0 text-primary" />
          <p><span className="font-semibold text-primary">Important:</span> the Resource Manager apply is a privileged OCI action. This workspace prepares the package and sends you to the OCI Console; it does not bypass review, IAM, or tenancy controls.</p>
        </section>
      </div>
    </main>
  )
}
