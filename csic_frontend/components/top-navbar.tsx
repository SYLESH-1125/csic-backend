"use client"

import { LogOut, Shield } from "lucide-react"
import { Button } from "@/components/ui/button"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { useApp } from "@/lib/app-context"

const pageLabels: Record<string, string> = {
  dashboard: "Dashboard",
  ingestion: "Phase 1 — Ingestion / Injection Control",
  ledger: "Phase 1 — Ingestion / Ledger View",
  quarantine: "Phase 1 — Ingestion / Quarantine Center",
  audit: "Phase 1 — Ingestion / Audit Trails",
  health: "Phase 1 — Ingestion / System Health",
  parsing: "Phase 2 — Parsing & Normalization",
  phase3: "Phase 3 — Hot & Cold Storage",
  phase4: "Phase 4 — Querying & Analytics",
  settings: "Settings",
}

export function TopNavbar() {
  const { currentPage, officerName, logout } = useApp()

  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-card px-4">
      <div className="flex items-center gap-3">
        <SidebarTrigger className="text-foreground" />
        <div className="hidden h-6 w-px bg-border sm:block" />
        <div className="hidden flex-col gap-0 sm:flex">
          <h2 className="text-sm font-semibold text-foreground">
            {pageLabels[currentPage] || "Dashboard"}
          </h2>
          <p className="text-[10px] text-muted-foreground">
            National Forensic Log Intelligence Platform
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="hidden items-center gap-2 md:flex">
          <span className="relative flex size-2">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-75" />
            <span className="relative inline-flex size-2 rounded-full bg-success" />
          </span>
          <span className="text-xs text-success font-medium">Session Active</span>
        </div>

        <div className="hidden h-6 w-px bg-border md:block" />

        <div className="hidden items-center gap-2 lg:flex">
          <div className="flex size-7 items-center justify-center border border-primary/20 bg-primary/5">
            <Shield className="size-3.5 text-primary" />
          </div>
          <div className="flex flex-col">
            <span className="text-xs font-medium text-foreground">{officerName}</span>
            <span className="text-[10px] text-muted-foreground">Level-5 Clearance</span>
          </div>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => logout()}
          className="h-8 gap-1.5 border-border text-xs text-foreground hover:bg-destructive/5 hover:text-destructive hover:border-destructive/30"
        >
          <LogOut className="size-3.5" />
          <span className="hidden sm:inline">Logout</span>
        </Button>
      </div>
    </header>
  )
}
