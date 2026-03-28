"use client"

import { useState } from "react"
import {
  LayoutDashboard,
  Upload,
  BookOpen,
  ShieldAlert,
  ClipboardList,
  Activity,
  Shield,
  ChevronDown,
  ChevronRight,
  Workflow,
  Database,
  ScanSearch,
  Bot,
  FileText,
} from "lucide-react"
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarFooter,
  SidebarSeparator,
} from "@/components/ui/sidebar"
import { useApp } from "@/lib/app-context"

type Page =
  | "dashboard"
  | "ingestion"
  | "parsing"
  | "phase3"
  | "phase4"
  | "phase5"
  | "phase6"
  | "ledger"
  | "quarantine"
  | "audit"
  | "health"
  | "settings"

const ingestionSubItems: { id: Page; label: string; icon: typeof Upload }[] = [
  { id: "ingestion", label: "Injection Control", icon: Upload },
  { id: "ledger", label: "Ledger View", icon: BookOpen },
  { id: "quarantine", label: "Quarantine Center", icon: ShieldAlert },
  { id: "audit", label: "Audit Trails", icon: ClipboardList },
  { id: "health", label: "System Health", icon: Activity },
]

const parsingSubItems: { id: Page; label: string; icon: typeof Upload }[] = [
  { id: "parsing", label: "Parsing Pipeline", icon: Workflow },
]

const phase3SubItems: { id: Page; label: string; icon: typeof Upload }[] = [
  { id: "phase3", label: "Hot/Cold DB", icon: Database },
]

const phase4SubItems: { id: Page; label: string; icon: typeof Upload }[] = [
  { id: "phase4", label: "Analytics & Detection", icon: ScanSearch },
]

const phase5SubItems: { id: Page; label: string; icon: typeof Upload }[] = [
  { id: "phase5", label: "Agent Triage", icon: Bot },
]

const phase6SubItems: { id: Page; label: string; icon: typeof Upload }[] = [
  { id: "phase6", label: "Reporting Phase", icon: FileText },
]

export function AppSidebar() {
  const { currentPage, setCurrentPage } = useApp()
  const [ingestionOpen, setIngestionOpen] = useState(
    ingestionSubItems.some((item) => item.id === currentPage)
  )
  const [parsingOpen, setParsingOpen] = useState(currentPage === "parsing")
  const [phase3Open, setPhase3Open] = useState(currentPage === "phase3")
  const [phase4Open, setPhase4Open] = useState(currentPage === "phase4")
  const [phase5Open, setPhase5Open] = useState(currentPage === "phase5")
  const [phase6Open, setPhase6Open] = useState(currentPage === "phase6")

  const isIngestionSection = ingestionSubItems.some((item) => item.id === currentPage)
  const isParsingSection = currentPage === "parsing"
  const isPhase3Section = currentPage === "phase3"
  const isPhase4Section = currentPage === "phase4"
  const isPhase5Section = currentPage === "phase5"
  const isPhase6Section = currentPage === "phase6"

  return (
    <Sidebar variant="sidebar" collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex size-8 shrink-0 items-center justify-center border border-primary bg-primary/10">
            <Shield className="size-4 text-primary" />
          </div>
          <div className="flex flex-col gap-0 group-data-[collapsible=icon]:hidden">
            <span className="text-xs font-bold tracking-wider text-foreground uppercase">NFLIP</span>
            <span className="text-[9px] text-muted-foreground leading-tight">Forensic Intelligence</span>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
            Security Protocol Phases
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {/* Dashboard - top level */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  isActive={currentPage === "dashboard"}
                  onClick={() => setCurrentPage("dashboard")}
                  tooltip="Dashboard"
                  className={
                    currentPage === "dashboard"
                      ? "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
                      : "text-foreground hover:bg-muted"
                  }
                >
                  <LayoutDashboard className="size-4" />
                  <span>Main Dashboard</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              {/* Ingestion Phase - collapsible parent */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setIngestionOpen(!ingestionOpen)
                    if (!isIngestionSection) {
                      setCurrentPage("ingestion")
                    }
                  }}
                  tooltip="Ingestion Phase"
                  className={
                    isIngestionSection
                      ? "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
                      : "text-foreground hover:bg-muted"
                  }
                >
                  <Shield className="size-4" />
                  <span className="flex-1">Ingestion Phase</span>
                  {ingestionOpen ? (
                    <ChevronDown className="size-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="size-3.5 text-muted-foreground" />
                  )}
                </SidebarMenuButton>
              </SidebarMenuItem>

              {/* Sub-items */}
              {ingestionOpen &&
                ingestionSubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => setCurrentPage(item.id)}
                      tooltip={item.label}
                      className={`pl-8 ${
                        currentPage === item.id
                          ? "bg-primary/5 text-primary font-medium"
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      }`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

              {/* Parsing Phase - collapsible parent */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setParsingOpen(!parsingOpen)
                    if (!isParsingSection) {
                      setCurrentPage("parsing")
                    }
                  }}
                  tooltip="Parsing Phase"
                  className={
                    isParsingSection
                      ? "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
                      : "text-foreground hover:bg-muted"
                  }
                >
                  <Workflow className="size-4" />
                  <span className="flex-1">Parsing Phase</span>
                  {parsingOpen ? (
                    <ChevronDown className="size-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="size-3.5 text-muted-foreground" />
                  )}
                </SidebarMenuButton>
              </SidebarMenuItem>

              {/* Parsing Sub-items */}
              {parsingOpen &&
                parsingSubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => setCurrentPage(item.id)}
                      tooltip={item.label}
                      className={`pl-8 ${
                        currentPage === item.id
                          ? "bg-primary/5 text-primary font-medium"
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      }`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

              {/* Phase 3 - collapsible parent */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setPhase3Open(!phase3Open)
                    if (!isPhase3Section) setCurrentPage("phase3")
                  }}
                  tooltip="Phase 3"
                  className={
                    isPhase3Section
                      ? "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
                      : "text-foreground hover:bg-muted"
                  }
                >
                  <Database className="size-4" />
                  <span className="flex-1">Data Storage Phase</span>
                  {phase3Open ? (
                    <ChevronDown className="size-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="size-3.5 text-muted-foreground" />
                  )}
                </SidebarMenuButton>
              </SidebarMenuItem>

              {phase3Open &&
                phase3SubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => setCurrentPage(item.id)}
                      tooltip={item.label}
                      className={`pl-8 ${
                        currentPage === item.id
                          ? "bg-primary/5 text-primary font-medium"
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      }`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

              {/* Phase 5 - collapsible parent */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setPhase5Open(!phase5Open)
                    if (!isPhase5Section) setCurrentPage("phase5")
                  }}
                  tooltip="Phase 5"
                  className={
                    isPhase5Section
                      ? "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
                      : "text-foreground hover:bg-muted"
                  }
                >
                  <Bot className="size-4" />
                  <span className="flex-1">AI Analyser Phase</span>
                  {phase5Open ? (
                    <ChevronDown className="size-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="size-3.5 text-muted-foreground" />
                  )}
                </SidebarMenuButton>
              </SidebarMenuItem>

              {phase5Open &&
                phase5SubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => setCurrentPage(item.id)}
                      tooltip={item.label}
                      className={`pl-8 ${
                        currentPage === item.id
                          ? "bg-primary/5 text-primary font-medium"
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      }`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

                {/* Phase 4 - collapsible parent */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setPhase4Open(!phase4Open)
                    if (!isPhase4Section) setCurrentPage("phase4")
                  }}
                  tooltip="Phase 4"
                  className={
                    isPhase4Section
                      ? "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
                      : "text-foreground hover:bg-muted"
                  }
                >
                  <ScanSearch className="size-4" />
                  <span className="flex-1">Querying Phase</span>
                  {phase4Open ? (
                    <ChevronDown className="size-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="size-3.5 text-muted-foreground" />
                  )}
                </SidebarMenuButton>
              </SidebarMenuItem>

              {phase4Open &&
                phase4SubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => setCurrentPage(item.id)}
                      tooltip={item.label}
                      className={`pl-8 ${
                        currentPage === item.id
                          ? "bg-primary/5 text-primary font-medium"
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      }`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}


              {/* Phase 6 - collapsible parent */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setPhase6Open(!phase6Open)
                    if (!isPhase6Section) setCurrentPage("phase6")
                  }}
                  tooltip="Phase 6"
                  className={
                    isPhase6Section
                      ? "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
                      : "text-foreground hover:bg-muted"
                  }
                >
                  <FileText className="size-4" />
                  <span className="flex-1">Reporting Phase</span>
                  {phase6Open ? (
                    <ChevronDown className="size-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="size-3.5 text-muted-foreground" />
                  )}
                </SidebarMenuButton>
              </SidebarMenuItem>

              {phase6Open &&
                phase6SubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => setCurrentPage(item.id)}
                      tooltip={item.label}
                      className={`pl-8 ${
                        currentPage === item.id
                          ? "bg-primary/5 text-primary font-medium"
                          : "text-muted-foreground hover:bg-muted hover:text-foreground"
                      }`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarSeparator />

      <SidebarFooter className="px-4 py-3">
        <div className="flex flex-col gap-1 group-data-[collapsible=icon]:hidden">
          <p className="text-[9px] font-medium tracking-wider text-muted-foreground uppercase">
            Classification
          </p>
          <p className="text-[10px] font-bold tracking-wider text-destructive uppercase">
            Restricted
          </p>
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}
