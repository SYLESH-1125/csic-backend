"use client"

import { Card, CardContent } from "@/components/ui/card"

export function Phase5Page() {
  return (
    <div className="p-6">
      <div className="mb-4">
        <div className="text-sm font-semibold">Phase 5 — Agent Triage</div>
        <div className="text-xs text-muted-foreground">
          Phase 5 backend agents live under app/phase5/. UI wiring will connect here next.
        </div>
      </div>

      <Card className="border border-border">
        <CardContent className="p-4">
          <div className="text-xs text-muted-foreground">
            No Phase 5 API routes are exposed in the backend app yet.
          </div>
        </CardContent>
      </Card>
    </div>
  )
}



