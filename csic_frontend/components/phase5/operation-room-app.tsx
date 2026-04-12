"use client"

import { useEffect } from "react"
import { useSearchParams } from "next/navigation"

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { PHASE5_QUERY, PHASE5_SECTIONS, type Phase5SectionId } from "@/lib/phase5-routes"
import { usePhase5Nav } from "@/lib/use-phase5-nav"
import { Phase5OverviewSection } from "@/components/phase5/sections/overview-section"
import { Phase5CasesSection } from "@/components/phase5/sections/cases-section"
import { Phase5EvidenceSection } from "@/components/phase5/sections/evidence-section"
import { Phase5ApiSection } from "@/components/phase5/sections/phase5-api-section"

export function OperationRoomApp() {
  const searchParams = useSearchParams()
  const { section, caseId, setPhase5Route } = usePhase5Nav()

  useEffect(() => {
    if (!searchParams.has(PHASE5_QUERY)) {
      setPhase5Route("overview", caseId)
    }
  }, [searchParams, setPhase5Route, caseId])

  const onSelectCase = (id: string, next: Phase5SectionId = "evidence") => {
    setPhase5Route(next, id)
  }

  const goCases = () => setPhase5Route("cases", null)

  return (
    <div className="flex flex-col gap-4 p-6 min-h-full">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Phase 5 — Operation Room</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Investigation workspace wired into NFLIP. Tabs update the URL (<code className="text-xs">?phase5=…</code>
          {", "}
          <code className="text-xs">case=…</code>) for bookmarking.
        </p>
      </div>

      <Tabs value={section} onValueChange={(v) => setPhase5Route(v as Phase5SectionId, caseId)} className="gap-4">
        <TabsList className="flex w-full flex-wrap h-auto justify-start gap-1 bg-muted/50 p-1">
          {PHASE5_SECTIONS.map((s) => (
            <TabsTrigger key={s.id} value={s.id} className="text-xs sm:text-sm">
              {s.label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <Phase5OverviewSection />
        </TabsContent>

        <TabsContent value="cases" className="mt-4">
          <Phase5CasesSection activeCaseId={caseId} onSelectCase={onSelectCase} />
        </TabsContent>

        <TabsContent value="evidence" className="mt-4">
          <Phase5EvidenceSection caseId={caseId} onNeedCase={goCases} />
        </TabsContent>

        <TabsContent value="timeline" className="mt-4">
          <Phase5ApiSection
            title="Timeline"
            description="GET timeline index for the active case (first page of data)."
            fetchPath="/api/cases/{case_id}/timeline"
            caseId={caseId}
            onNeedCase={goCases}
          />
        </TabsContent>

        <TabsContent value="workflow" className="mt-4">
          <Phase5ApiSection
            title="Workflow"
            description="GET supported execution modes for this case’s workflow runner."
            fetchPath="/api/cases/{case_id}/workflow/execution-modes"
            caseId={caseId}
            onNeedCase={goCases}
          />
        </TabsContent>

        <TabsContent value="studio" className="mt-4">
          <Phase5ApiSection
            title="Studio"
            description="Lightweight studio health check for the active case (requires studio routes)."
            fetchPath="/api/v4/studio/cases/{case_id}/health"
            caseId={caseId}
            onNeedCase={goCases}
          />
        </TabsContent>
      </Tabs>
    </div>
  )
}
