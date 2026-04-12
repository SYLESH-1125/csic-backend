"use client"

import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { ExternalLink } from "lucide-react"

import { Button } from "@/components/ui/button"
import { PHASE6_PATH_QUERY } from "@/lib/phase6-routes"

/**
 * Phase 6 — Operation Room runs **inside this Next app** on port 3000 under `/operation-room`
 * (and `/cases/...` via middleware rewrite). Same source tree as
 * `app/phase_5_CISC/operation-room/frontend`; no second dev server.
 */
export function Phase6Page() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const raw = searchParams.get(PHASE6_PATH_QUERY)

  const openOperationRoom = () => {
    if (raw) {
      try {
        const path = decodeURIComponent(raw.trim())
        const normalized = path.startsWith("/") ? path : `/${path}`
        router.push(normalized.startsWith("/cases") ? normalized : `/cases${normalized}`)
        return
      } catch {
        /* fall through */
      }
    }
    router.push("/operation-room")
  }

  return (
    <div className="flex flex-col gap-4 p-4 sm:p-6">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Phase 6 — Operation Room</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          The Operation Room UI is compiled into this app. Use{" "}
          <strong className="text-foreground">Enter Operation Room</strong> to open it on the same port
          (routes such as <code className="rounded bg-muted px-1 text-xs">/cases/…</code> and{" "}
          <code className="rounded bg-muted px-1 text-xs">/operation-room</code>
          ). The API is proxied to your Forensic Engine (set{" "}
          <code className="text-xs">OPROOM_BACKEND_ORIGIN</code> / <code className="text-xs">NEXT_PUBLIC_API_URL</code>{" "}
          in <code className="text-xs">.env.local</code>, default <code className="text-xs">…/api/phase5</code>).
        </p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button type="button" onClick={openOperationRoom}>
          Enter Operation Room
        </Button>
        <Button type="button" variant="outline" asChild>
          <Link href="/operation-room">Open /operation-room</Link>
        </Button>
        <Button type="button" variant="outline" asChild>
          <Link href="/cases/new">New case</Link>
        </Button>
        <Button type="button" variant="ghost" size="sm" asChild>
          <a href="/operation-room" target="_blank" rel="noopener noreferrer">
            <ExternalLink className="mr-1.5 inline size-3.5" />
            Open in new tab
          </a>
        </Button>
      </div>
    </div>
  )
}
