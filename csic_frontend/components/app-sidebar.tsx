"use client"

import { useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
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
  Settings,
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
import type { ShellPage } from "@/lib/app-navigation"
import { useShellNavigate } from "@/lib/use-shell-navigate"

const ingestionSubItems: { id: ShellPage; label: string; icon: typeof Upload }[] = [
  { id: "ingestion", label: "Injection Control", icon: Upload },
  { id: "ledger", label: "Ledger View", icon: BookOpen },
  { id: "quarantine", label: "Quarantine Center", icon: ShieldAlert },
  { id: "audit", label: "Audit Trails", icon: ClipboardList },
  { id: "health", label: "System Health", icon: Activity },
]

const parsingSubItems: { id: ShellPage; label: string; icon: typeof Upload }[] = [
  { id: "parsing", label: "Parsing Pipeline", icon: Workflow },
]

const phase3SubItems: { id: ShellPage; label: string; icon: typeof Upload }[] = [
  { id: "phase3", label: "Hot/Cold DB", icon: Database },
]

const phase4SubItems: { id: ShellPage; label: string; icon: typeof Upload }[] = [
  { id: "phase4", label: "Analytics & Detection", icon: ScanSearch },
]

function PhaseNumber({ n }: { n: number }) {
  return (
    <span className="flex size-[18px] shrink-0 items-center justify-center rounded-full bg-primary/10 text-[9px] font-bold text-primary leading-none">
      {n}
    </span>
  )
}

export function AppSidebar() {
  const { currentPage } = useApp()
  const { go } = useShellNavigate()
  const router = useRouter()
  const searchParams = useSearchParams()

  const [ingestionOpen, setIngestionOpen] = useState(
    ingestionSubItems.some((item) => item.id === currentPage)
  )
  const [parsingOpen, setParsingOpen] = useState(currentPage === "parsing")
  const [phase3Open, setPhase3Open] = useState(currentPage === "phase3")
  const [phase4Open, setPhase4Open] = useState(currentPage === "phase4")

  const isIngestionSection = ingestionSubItems.some((item) => item.id === currentPage)
  const isParsingSection = currentPage === "parsing"
  const isPhase3Section = currentPage === "phase3"
  const isPhase4Section = currentPage === "phase4"

  const activeStyle = "bg-primary/10 text-primary font-medium border-l-2 border-primary rounded-none"
  const defaultStyle = "text-foreground hover:bg-muted"
  const subActiveStyle = "bg-primary/5 text-primary font-medium"
  const subDefaultStyle = "text-muted-foreground hover:bg-muted hover:text-foreground"

  return (
    <Sidebar variant="sidebar" collapsible="icon">
      <SidebarHeader className="border-b border-sidebar-border px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex size-8 shrink-0 items-center justify-center rounded-md border border-primary bg-primary/10">
            <Shield className="size-4 text-primary" />
          </div>
          <div className="flex flex-col gap-0 group-data-[collapsible=icon]:hidden">
            <span className="text-xs font-bold tracking-wider text-foreground uppercase">NFLIP</span>
            <span className="text-[9px] text-muted-foreground leading-tight">Forensic Intelligence</span>
          </div>
        </div>
      </SidebarHeader>

      <SidebarContent>
        {/* ── Overview ─────────────────────────────────────────── */}
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  isActive={currentPage === "dashboard"}
                  onClick={() => go("dashboard")}
                  tooltip="Dashboard"
                  className={currentPage === "dashboard" ? activeStyle : defaultStyle}
                >
                  <LayoutDashboard className="size-4" />
                  <span>Dashboard</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarSeparator />

        {/* ── Pipeline Phases ──────────────────────────────────── */}
        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase">
            Pipeline Phases
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>

              {/* ── Phase 1: Ingestion ── */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setIngestionOpen(!ingestionOpen)
                    if (!isIngestionSection) go("ingestion")
                  }}
                  tooltip="Phase 1 — Ingestion"
                  className={isIngestionSection ? activeStyle : defaultStyle}
                >
                  <PhaseNumber n={1} />
                  <span className="flex-1">Ingestion</span>
                  {ingestionOpen
                    ? <ChevronDown className="size-3.5 text-muted-foreground" />
                    : <ChevronRight className="size-3.5 text-muted-foreground" />}
                </SidebarMenuButton>
              </SidebarMenuItem>
              {ingestionOpen &&
                ingestionSubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => go(item.id)}
                      tooltip={item.label}
                      className={`pl-9 ${currentPage === item.id ? subActiveStyle : subDefaultStyle}`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

              {/* ── Phase 2: Parsing ── */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setParsingOpen(!parsingOpen)
                    if (!isParsingSection) go("parsing")
                  }}
                  tooltip="Phase 2 — Parsing"
                  className={isParsingSection ? activeStyle : defaultStyle}
                >
                  <PhaseNumber n={2} />
                  <span className="flex-1">Parsing</span>
                  {parsingOpen
                    ? <ChevronDown className="size-3.5 text-muted-foreground" />
                    : <ChevronRight className="size-3.5 text-muted-foreground" />}
                </SidebarMenuButton>
              </SidebarMenuItem>
              {parsingOpen &&
                parsingSubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => go(item.id)}
                      tooltip={item.label}
                      className={`pl-9 ${currentPage === item.id ? subActiveStyle : subDefaultStyle}`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

              {/* ── Phase 3: Storage ── */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setPhase3Open(!phase3Open)
                    if (!isPhase3Section) go("phase3")
                  }}
                  tooltip="Phase 3 — Storage"
                  className={isPhase3Section ? activeStyle : defaultStyle}
                >
                  <PhaseNumber n={3} />
                  <span className="flex-1">Data Storage</span>
                  {phase3Open
                    ? <ChevronDown className="size-3.5 text-muted-foreground" />
                    : <ChevronRight className="size-3.5 text-muted-foreground" />}
                </SidebarMenuButton>
              </SidebarMenuItem>
              {phase3Open &&
                phase3SubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => go(item.id)}
                      tooltip={item.label}
                      className={`pl-9 ${currentPage === item.id ? subActiveStyle : subDefaultStyle}`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

              {/* ── Phase 4: Querying ── */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => {
                    setPhase4Open(!phase4Open)
                    if (!isPhase4Section) go("phase4")
                  }}
                  tooltip="Phase 4 — Querying"
                  className={isPhase4Section ? activeStyle : defaultStyle}
                >
                  <PhaseNumber n={4} />
                  <span className="flex-1">Querying</span>
                  {phase4Open
                    ? <ChevronDown className="size-3.5 text-muted-foreground" />
                    : <ChevronRight className="size-3.5 text-muted-foreground" />}
                </SidebarMenuButton>
              </SidebarMenuItem>
              {phase4Open &&
                phase4SubItems.map((item) => (
                  <SidebarMenuItem key={item.id}>
                    <SidebarMenuButton
                      isActive={currentPage === item.id}
                      onClick={() => go(item.id)}
                      tooltip={item.label}
                      className={`pl-9 ${currentPage === item.id ? subActiveStyle : subDefaultStyle}`}
                    >
                      <item.icon className="size-3.5" />
                      <span className="text-[13px]">{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}

              {/* ── Phase 5: Operation Room (full-page route) ── */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  onClick={() => router.push("/operation-room")}
                  tooltip="Phase 5 — Operation Room"
                  className={defaultStyle}
                >
                  <PhaseNumber n={5} />
                  <span className="flex-1">Operation Room</span>
                  <ChevronRight className="size-3.5 text-muted-foreground" />
                </SidebarMenuButton>
              </SidebarMenuItem>

            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarSeparator />

        {/* ── Settings ─────────────────────────────────────────── */}
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  isActive={currentPage === "settings"}
                  onClick={() => go("settings")}
                  tooltip="Settings"
                  className={currentPage === "settings" ? activeStyle : defaultStyle}
                >
                  <Settings className="size-4" />
                  <span>Settings</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border px-4 py-3">
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
