"use client"

import Image from "next/image"
import { ChevronsLeft, ChevronsRight, Github, LayoutGrid } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { useSidebar } from "@/components/ui/sidebar"

const repositoryUrl = "https://github.com/adibirzu/oci-log-analytics-detections"

export function DashboardHeader() {
  const { toggleSidebar, state } = useSidebar()

  return (
    <header className="sticky top-0 z-10 flex h-[60px] items-center gap-4 border-b bg-background/80 backdrop-blur-sm px-6">
      <div className="flex items-center gap-3">
        <Image src="/octo-logo.png" width={34} height={34} alt="OCTO" className="h-9 w-9 object-contain" priority />
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon" className="md:hidden" onClick={toggleSidebar}>
                <LayoutGrid className="size-5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Toggle Sidebar</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon" className="hidden md:inline-flex" onClick={toggleSidebar}>
                {state === "expanded" ? <ChevronsLeft className="size-5" /> : <ChevronsRight className="size-5" />}
              </Button>
            </TooltipTrigger>
            <TooltipContent>{state === "expanded" ? "Collapse Sidebar" : "Expand Sidebar"}</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-center gap-3">
          <div className="hidden min-w-0 sm:block">
            <div className="truncate text-sm font-semibold">OCL Forge</div>
            <div className="truncate text-xs text-muted-foreground">Query conversion workbench</div>
          </div>
          <div className="truncate text-sm font-medium">OCI Log Analytics QL</div>
        </div>
      </div>
      <Button asChild variant="outline" size="sm">
        <a href={repositoryUrl} target="_blank" rel="noreferrer">
          <Github className="size-4" />
          Repo
        </a>
      </Button>
    </header>
  )
}
