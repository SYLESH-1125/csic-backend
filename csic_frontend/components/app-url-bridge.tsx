"use client"

import { useEffect } from "react"
import { useSearchParams } from "next/navigation"
import { useApp } from "@/lib/app-context"
import { APP_PAGE_QUERY, parseShellPage } from "@/lib/app-navigation"
import { PHASE5_QUERY } from "@/lib/phase5-routes"

/**
 * Hydrates `currentPage` from the URL on load and when the query string changes.
 * `?phase5=…` forces Operation Room; otherwise `?page=dashboard|ingestion|…` selects the shell view.
 */
export function AppUrlBridge() {
  const searchParams = useSearchParams()
  const { setCurrentPage, isAuthenticated } = useApp()

  useEffect(() => {
    if (!isAuthenticated) return
    const pageParam = searchParams.get(APP_PAGE_QUERY)
    if (searchParams.has(PHASE5_QUERY) && pageParam !== "phase6") {
      setCurrentPage("phase5")
      return
    }
    const shell = parseShellPage(pageParam)
    if (shell) setCurrentPage(shell)
  }, [isAuthenticated, searchParams, setCurrentPage])

  return null
}
