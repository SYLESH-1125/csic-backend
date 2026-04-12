"use client"

import { useCallback, useEffect, useState } from "react"
import { FolderOpen, Loader2, Plus } from "lucide-react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { phase5Fetch, type Phase5CaseSummary } from "@/lib/phase5-api"
import type { Phase5SectionId } from "@/lib/phase5-routes"

interface CasesSectionProps {
  activeCaseId: string | null
  onSelectCase: (caseId: string, nextSection?: Phase5SectionId) => void
}

export function Phase5CasesSection({ activeCaseId, onSelectCase }: CasesSectionProps) {
  const [rows, setRows] = useState<Phase5CaseSummary[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [title, setTitle] = useState("")

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const list = await phase5Fetch<Phase5CaseSummary[]>("/api/cases")
      setRows(Array.isArray(list) ? list : [])
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load cases")
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const createCase = async () => {
    const t = title.trim()
    if (!t) return
    setCreating(true)
    setError(null)
    try {
      const created = await phase5Fetch<Phase5CaseSummary>("/api/cases", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: t,
          description: "",
          classification: "UNCLASSIFIED",
          priority: "MEDIUM",
          lead_investigator: "analyst",
          suspects: [],
          investigation_reason: "",
          log_sources: [],
          scope: [],
        }),
      })
      setTitle("")
      await load()
      if (created?.case_id) onSelectCase(created.case_id, "evidence")
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed")
    } finally {
      setCreating(false)
    }
  }

  if (loading && rows === null) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground py-8">
        <Loader2 className="size-4 animate-spin" />
        Loading cases…
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6 max-w-5xl">
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <FolderOpen className="size-5 text-primary" />
            <CardTitle className="text-base">New case</CardTitle>
          </div>
          <CardDescription>Creates a vault-backed case via POST /api/cases.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col sm:flex-row gap-3 sm:items-end">
          <div className="flex-1 space-y-2">
            <Label htmlFor="or-case-title">Title</Label>
            <Input
              id="or-case-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Case title"
              onKeyDown={(e) => e.key === "Enter" && void createCase()}
            />
          </div>
          <Button disabled={creating || !title.trim()} onClick={() => void createCase()}>
            <Plus className="size-4 mr-1" />
            {creating ? "Creating…" : "Create"}
          </Button>
        </CardContent>
      </Card>

      {error && (
        <Alert variant="destructive">
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">All cases</CardTitle>
          <CardDescription>Select a row to set the active case for evidence and timeline.</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead className="text-right">Evidence</TableHead>
                <TableHead className="text-right w-[120px]">Open</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!rows?.length ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-sm text-muted-foreground py-8 text-center">
                    No cases yet. Create one above.
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((r) => (
                  <TableRow
                    key={r.case_id}
                    className={activeCaseId === r.case_id ? "bg-primary/5" : undefined}
                  >
                    <TableCell className="font-mono text-xs">{r.case_id}</TableCell>
                    <TableCell className="text-sm">{r.title}</TableCell>
                    <TableCell className="text-xs">{r.status}</TableCell>
                    <TableCell className="text-xs">{r.priority}</TableCell>
                    <TableCell className="text-right text-xs">{r.evidence_count ?? 0}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="outline" size="sm" onClick={() => onSelectCase(r.case_id, "evidence")}>
                        Evidence
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
