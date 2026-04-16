"use client"

import { useState } from "react"
import { LogOut, Shield, User } from "lucide-react"
import { useApp } from "@/lib/app-context"
import { cn } from "@/lib/utils"

const pageLabels: Record<string, string> = {
  dashboard: "Main Dashboard",
  ingestion: "Phase 1 — Ingestion / Injection Control",
  ledger: "Phase 1 — Ingestion / Ledger View",
  quarantine: "Phase 1 — Ingestion / Quarantine Center",
  audit: "Phase 1 — Ingestion / Audit Trails",
  health: "Phase 1 — Ingestion / System Health",
  parsing: "Phase 2 — Parsing & Normalization",
  phase3: "Phase 3 — Hot & Cold Storage",
  settings: "Settings",
}

export function TopNavbar({ className }: { className?: string }) {
  const { currentPage, officerName, logout } = useApp()
  const [dropdownOpen, setDropdownOpen] = useState(false)

  const new_ = "National Forensic Log Intelligence Platform"

  return (
    <header
      style={{ height: "80px", minHeight: "80px", backgroundColor: "#fafaf9", borderBottom: "1px solid #e2e8f0" }}
      className={cn("flex shrink-0 w-full items-center justify-between px-8 lg:px-12 m-0 z-30 transition-all", className)}
    >

      <div className="flex items-center pl-2 lg:pl-4">
        <div className="hidden flex-col gap-1 sm:flex">
          <h2 style={{ color: "#0f172a" }} className="text-2xl font-extrabold tracking-tight">
            {pageLabels[currentPage] || "Main Dashboard"}
          </h2>
          <p style={{ color: "#64748b" }} className="text-xs uppercase tracking-widest font-bold">
            {new_}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-8 lg:gap-10">

        <div className="hidden items-center gap-3 md:flex mr-4">
          <span className="relative flex size-3">
            <span style={{ backgroundColor: "#34d399" }} className="absolute inline-flex size-full animate-ping rounded-full opacity-75" />
            <span style={{ backgroundColor: "#10b981" }} className="relative inline-flex size-3 rounded-full" />
          </span>
          <span style={{ backgroundColor: "#ecfdf5", color: "#047857", border: "1px solid #a7f3d0" }} className="text-sm font-bold px-4 py-2 rounded-full shadow-sm">
            Session Active
          </span>
        </div>

        <div style={{ backgroundColor: "#e2e8f0" }} className="hidden h-10 w-px md:block" />

        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            style={{ backgroundColor: "#ffffff", border: "1px solid #e2e8f0" }}
            className="flex h-12 w-12 items-center justify-center rounded-full hover:bg-slate-50 transition-all shadow-sm"
          >
            <User style={{ color: "#9333ea" }} className="size-6" />
          </button>

          {dropdownOpen && (
            <div style={{ backgroundColor: "#ffffff", border: "1px solid #e2e8f0" }} className="absolute right-0 mt-4 w-72 rounded-3xl shadow-xl p-3 z-50">

              <div className="px-4 py-4 flex items-center gap-4 border-b border-slate-100 mb-3">
                <div style={{ backgroundColor: "#faf5ff", border: "1px solid #e9d5ff" }} className="flex size-12 items-center justify-center rounded-full shrink-0">
                  <Shield style={{ color: "#9333ea" }} className="size-6" />
                </div>
                <div className="flex flex-col gap-0.5">
                  <span style={{ color: "#0f172a" }} className="text-base font-bold">{officerName}</span>
                  <span style={{ color: "#64748b" }} className="text-[11px] font-bold uppercase tracking-wider">Level-5 Clearance</span>
                </div>
              </div>

              <button
                onClick={() => {
                  setDropdownOpen(false)
                  logout()
                }}
                style={{ backgroundColor: "#fff1f2", color: "#e11d48" }}
                className="flex w-full items-center gap-3 px-4 py-3 text-base font-bold hover:opacity-80 rounded-xl transition-all"
              >
                <LogOut className="size-5" />
                Logout
              </button>
            </div>
          )}
        </div>

      </div>
    </header>
  )
}