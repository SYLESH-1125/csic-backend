"use client"

import React from "react"
import { AppProvider, useApp } from "@/lib/app-context"
import { LoginPage } from "@/components/login-page"
import { RegisterPage } from "@/components/register-page"
import { AppSidebar } from "@/components/app-sidebar"
import { TopNavbar } from "@/components/top-navbar"
import { DashboardPage } from "@/components/dashboard-page"
import { IngestionPage } from "@/components/ingestion-page"
import { LedgerPage } from "@/components/ledger-page"
import { QuarantinePage } from "@/components/quarantine-page"
import { AuditPage } from "@/components/audit-page"
import { HealthPage } from "@/components/health-page"
import { SettingsPage } from "@/components/settings-page"
import { ParsingPage } from "@/components/parsing-page"
import { Phase3Page } from "@/components/phase3-page"
import { Phase4Page } from "@/components/phase4-page"
import { Phase5Page } from "@/components/phase5-page"
import { Phase6Page } from "@/components/phase6-page"
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar"
import { ScrollArea } from "@/components/ui/scroll-area"

function AppContent() {
  const { isAuthenticated, currentPage } = useApp()
  const [mounted, setMounted] = React.useState(false)

  React.useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-muted">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  if (!isAuthenticated) {
    if (currentPage === "register") {
      return <RegisterPage />
    }
    return <LoginPage />
  }

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <TopNavbar />
        <ScrollArea className="flex-1">
          <main>
            {currentPage === "dashboard" && <DashboardPage />}
            {currentPage === "ingestion" && <IngestionPage />}
            {currentPage === "parsing" && <ParsingPage />}
            {currentPage === "phase3" && <Phase3Page />}
            {currentPage === "phase4" && <Phase4Page />}
            {currentPage === "phase5" && <Phase5Page />}
            {currentPage === "phase6" && <Phase6Page />}
            {currentPage === "ledger" && <LedgerPage />}
            {currentPage === "quarantine" && <QuarantinePage />}
            {currentPage === "audit" && <AuditPage />}
            {currentPage === "health" && <HealthPage />}
            {currentPage === "settings" && <SettingsPage />}
          </main>
        </ScrollArea>
      </SidebarInset>
    </SidebarProvider>
  )
}

export default function Page() {
  return (
    <AppProvider>
      <AppContent />
    </AppProvider>
  )
}
