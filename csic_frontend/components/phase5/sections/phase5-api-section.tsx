"use client"

import { useCallback, useEffect, useState } from "react"
import { Loader2 } from "lucide-react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { phase5Fetch } from "@/lib/phase5-api"

interface Phase5ApiSectionProps {
  title: string
  description: string
  /** Relative to phase5 mount, e.g. `/api/cases/foo/timeline` */
  fetchPath: string | null
  caseId: string | null
  onNeedCase: () => void
  missingCaseMessage?: string
}

export function Phase5ApiSection({
  title,
  description,
  fetchPath,
  caseId,
  onNeedCase,
  missingCaseMessage = "Choose a case on the Cases tab first.",
}: Phase5ApiSectionProps) {
  const [raw, setRaw] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const path =
    fetchPath && caseId
      ? fetchPath.replace("{case_id}", encodeURIComponent(caseId))
      : null

  const load = useCallback(async () => {
    if (!path) {
      setRaw(null)
      return
    }
    setLoading(true)
    setError(null)
    try {
      const data = await phase5Fetch<unknown>(path)
      setRaw(JSON.stringify(data, null, 2))
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed")
      setRaw(null)
    } finally {
      setLoading(false)
    }
  }, [path])

  useEffect(() => {
    void load()
  }, [load])

  if (!caseId) {
    return (
      <Card className="max-w-xl border-dashed">
        <CardHeader>
          <CardTitle className="text-base">{title}</CardTitle>
          <CardDescription>{missingCaseMessage}</CardDescription>
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
          <h2 className="text-base font-semibold">{title}</h2>
          <p className="text-sm text-muted-foreground">{description}</p>
          <p className="text-xs font-mono text-muted-foreground mt-1">{path}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading || !path}>
          Refresh
        </Button>
      </div>
      {error && (
        <Alert variant="destructive">
          <AlertDescription className="text-xs whitespace-pre-wrap break-all">{error}</AlertDescription>
        </Alert>
      )}
      {loading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
          <Loader2 className="size-4 animate-spin" />
          Loading…
        </div>
      )}
      {!loading && raw && (
        <Card>
          <CardContent className="p-4">
            <pre className="text-xs overflow-auto max-h-[min(70vh,480px)] whitespace-pre-wrap break-all">
              {raw}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
