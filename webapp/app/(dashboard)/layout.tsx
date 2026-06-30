import type React from "react"
import { Suspense } from "react"

import { AppSidebar } from "@/components/app-sidebar"
import { DashboardHeader } from "@/components/dashboard-header"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <SidebarProvider defaultOpen>
      <div className="flex min-h-screen w-full bg-background">
        <Suspense fallback={null}>
          <AppSidebar />
        </Suspense>
        <SidebarInset>
          <div className="flex min-w-0 flex-col">
            <Suspense fallback={<div className="h-[60px] border-b border-border bg-surface-sunken" />}>
              <DashboardHeader />
            </Suspense>
            {children}
          </div>
        </SidebarInset>
      </div>
    </SidebarProvider>
  )
}
