"use client"

import { useEffect, useState } from "react"
import { ExternalLink, Loader2, Server } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { getApiBaseUrl } from "@/lib/public-env"
import { phase5Url, type Phase5Health, getPhase5MountBase } from "@/lib/phase5-api"

type HealthState = "loading" | "ok" | "error"

export function Phase5OverviewSection() {
  const apiBase = getApiBaseUrl()
  const mount = getPhase5MountBase()
  const healthUrl = phase5Url("/api/health")
  const docsUrl = `${apiBase}/docs`
  const [health, setHealth] = useState<HealthState>("loading")
  const [detail, setDetail] = useState<string>("")

  useEffect(() => {
    let cancelled = false
    fetch(healthUrl, { cache: "no-store" })
      .then(async (r) => {
        if (cancelled) return
        if (r.ok) {
          const j = (await r.json().catch(() => ({}))) as Phase5Health
          setHealth("ok")
          setDetail(j.service ? `${j.status ?? "ok"} — ${j.service}` : (j.status ?? "ok"))
        } else {
          setHealth("error")
          setDetail(`${r.status} ${r.statusText}`)
        }
      })
      .catch((e: unknown) => {
        if (cancelled) return
        setHealth("error")
        setDetail(e instanceof Error ? e.message : "Request failed")
      })
    return () => {
      cancelled = true
    }
  }, [healthUrl])

  return (
    <div className="flex flex-col gap-6 max-w-4xl">
      <div>
        <h2 className="text-base font-semibold tracking-tight">Operation Room overview</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Backend APIs are mounted at <code className="rounded bg-muted px-1 py-px text-xs">{mount}</code> (e.g.{" "}
          <code className="rounded bg-muted px-1 py-px text-xs">/api/phase5/api/health</code>). Use the sidebar
          or top tabs for cases, evidence, and workflow UIs.
        </p>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Server className="size-5 text-primary" />
            <CardTitle className="text-base">Backend status</CardTitle>
          </div>
          <CardDescription>Reachability of the Operation Room sub-application.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {health === "loading" && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Checking {healthUrl}…
            </div>
          )}
          {health === "ok" && (
            <Alert className="border-emerald-500/30 bg-emerald-500/5">
              <AlertTitle className="text-emerald-900 dark:text-emerald-100">Operation Room reachable</AlertTitle>
              <AlertDescription className="text-xs">{detail || "OK"}</AlertDescription>
            </Alert>
          )}
          {health === "error" && (
            <Alert variant="destructive">
              <AlertTitle>Not mounted or dependencies missing</AlertTitle>
              <AlertDescription className="text-xs space-y-2">
                <p>{detail}</p>
                <p>
                  Install Python deps for Phase 5 and restart the API, e.g.{" "}
                  <code className="rounded bg-muted px-1 py-px">
                    pip install -r app/phase_5_CISC/operation-room/backend/requirements.txt
                  </code>
                </p>
              </AlertDescription>
            </Alert>
          )}
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" asChild>
              <a href={docsUrl} target="_blank" rel="noopener noreferrer">
                Open API docs <ExternalLink className="size-3.5 ml-1" />
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href={healthUrl} target="_blank" rel="noopener noreferrer">
                Raw health JSON <ExternalLink className="size-3.5 ml-1" />
              </a>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
