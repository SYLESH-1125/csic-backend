"use client"

import { useCallback, useEffect, useState } from "react"
import { FileStack, Loader2 } from "lucide-react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { phase5Fetch } from "@/lib/phase5-api"

interface EvidenceSectionProps {
  caseId: string | null
  onNeedCase: () => void
}

interface EvidenceRow {
  hash_id?: string
  artefact_name?: string
  artefact_type?: string
  hash_algorithm?: string
  hash_value?: string
  record_count?: number
  byte_size?: number
  created_at?: string
}

function rowKey(row: EvidenceRow, index: number): string {
  return row.hash_id ?? `${index}`
}

export function Phase5EvidenceSection({ caseId, onNeedCase }: EvidenceSectionProps) {
  const [rows, setRows] = useState<EvidenceRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    if (!caseId) {
      setRows(null)
      return
    }
    setLoading(true)
    setError(null)
    try {
      const data = await phase5Fetch<unknown>(`/api/cases/${encodeURIComponent(caseId)}/evidence`)
      const list = Array.isArray(data) ? data : (data as { items?: unknown })?.items
      setRows(Array.isArray(list) ? (list as EvidenceRow[]) : [])
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load evidence")
      setRows([])
    } finally {
      setLoading(false)
    }
  }, [caseId])

  useEffect(() => {
    void load()
  }, [load])

  if (!caseId) {
    return (
      <Card className="max-w-xl border-dashed">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <FileStack className="size-5 text-primary" />
            Evidence
          </CardTitle>
          <CardDescription>
            Select a case first (Cases tab), or pick a row and use “Evidence”.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="secondary" onClick={onNeedCase}>
            Go to cases
          </Button>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="flex flex-col gap-4 max-w-5xl">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">Evidence</h2>
          <p className="text-sm text-muted-foreground font-mono text-xs mt-0.5">case_id: {caseId}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          Refresh
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription className="text-xs">{error}</AlertDescription>
        </Alert>
      )}

      {loading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
          <Loader2 className="size-4 animate-spin" />
          Loading evidence…
        </div>
      )}

      {!loading && rows && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Artefact</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Hash</TableHead>
                  <TableHead className="text-right">Records</TableHead>
                  <TableHead className="text-right">Bytes</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {!rows.length ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-sm text-muted-foreground py-8">
                      No evidence hashes yet for this case.
                    </TableCell>
                  </TableRow>
                ) : (
                  rows.map((row, i) => (
                    <TableRow key={rowKey(row, i)}>
                      <TableCell className="text-sm max-w-[200px] truncate" title={row.artefact_name}>
                        {row.artefact_name ?? "—"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{row.artefact_type ?? "—"}</TableCell>
                      <TableCell className="font-mono text-[10px] max-w-[280px] truncate" title={row.hash_value}>
                        {row.hash_algorithm ? `${row.hash_algorithm}:` : ""}
                        {row.hash_value ?? "—"}
                      </TableCell>
                      <TableCell className="text-right text-xs">{row.record_count ?? "—"}</TableCell>
                      <TableCell className="text-right text-xs">{row.byte_size ?? "—"}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
