"use client"

import { useCallback, useMemo } from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { APP_PAGE_QUERY } from "@/lib/app-navigation"
import {
  PHASE5_CASE_QUERY,
  PHASE5_QUERY,
  parsePhase5Section,
  type Phase5SectionId,
} from "@/lib/phase5-routes"

export function usePhase5Nav() {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  const section = useMemo(
    () => parsePhase5Section(searchParams.get(PHASE5_QUERY)),
    [searchParams]
  )
  const caseId = searchParams.get(PHASE5_CASE_QUERY)

  const setPhase5Route = useCallback(
    (nextSection: Phase5SectionId, nextCaseId?: string | null) => {
      const next = new URLSearchParams(searchParams.toString())
      next.set(APP_PAGE_QUERY, "phase5")
      next.set(PHASE5_QUERY, nextSection)
      if (nextCaseId) next.set(PHASE5_CASE_QUERY, nextCaseId)
      else next.delete(PHASE5_CASE_QUERY)
      const q = next.toString()
      router.replace(q ? `${pathname}?${q}` : pathname)
    },
    [pathname, router, searchParams]
  )

  return { section, caseId, setPhase5Route }
}
