"use client"

import { useCallback } from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { useApp } from "@/lib/app-context"
import type { ShellPage } from "@/lib/app-navigation"
import { APP_PAGE_QUERY } from "@/lib/app-navigation"
import { PHASE5_CASE_QUERY, PHASE5_QUERY, type Phase5SectionId } from "@/lib/phase5-routes"

/**
 * Keeps the address bar in sync with the NFLIP shell: `?page=…`, and Operation Room `?phase5=…&case=…`.
 */
export function useShellNavigate() {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const { setCurrentPage } = useApp()

  const replaceQuery = useCallback(
    (mutate: (next: URLSearchParams) => void) => {
      const next = new URLSearchParams(searchParams.toString())
      mutate(next)
      const q = next.toString()
      router.replace(q ? `${pathname}?${q}` : pathname)
    },
    [pathname, router, searchParams]
  )

  const go = useCallback(
    (page: ShellPage) => {
      setCurrentPage(page)
      replaceQuery((next) => {
        next.set(APP_PAGE_QUERY, page)
        if (page !== "phase5") {
          next.delete(PHASE5_QUERY)
          next.delete(PHASE5_CASE_QUERY)
        }
      })
    },
    [replaceQuery, setCurrentPage]
  )

  const goPhase5 = useCallback(
    (section: Phase5SectionId, caseId?: string | null) => {
      setCurrentPage("phase5")
      replaceQuery((next) => {
        next.set(APP_PAGE_QUERY, "phase5")
        next.set(PHASE5_QUERY, section)
        if (caseId) next.set(PHASE5_CASE_QUERY, caseId)
        else next.delete(PHASE5_CASE_QUERY)
      })
    },
    [replaceQuery, setCurrentPage]
  )

  return { go, goPhase5 }
}
