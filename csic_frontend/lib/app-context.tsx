"use client"

import React, { createContext, useContext, useState, useCallback, useEffect } from "react"
import { authService } from "./auth-service"

type Page =
  | "login"
  | "register"
  | "dashboard"
  | "ingestion"
  | "parsing"
  | "phase3"
  | "phase4"
  | "phase5"
  | "phase6"
  | "ledger"
  | "quarantine"
  | "audit"
  | "health"
  | "settings"

interface AppContextType {
  currentPage: Page
  setCurrentPage: (page: Page) => void
  isAuthenticated: boolean
  user: { id: string; email: string; full_name: string | null; is_admin: boolean } | null
  register: (email: string, password: string, fullName?: string) => Promise<void>
  login: (email: string, password: string, otp?: string) => Promise<void>
  logout: () => Promise<void>
  officerName: string
}

const AppContext = createContext<AppContextType | null>(null)

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [currentPage, setCurrentPage] = useState<Page>("login")
  const [authState, setAuthState] = useState(authService.getState())

  useEffect(() => {
    const unsubscribe = authService.subscribe((state) => {
      setAuthState(state)
      if (!state.isAuthenticated) {
        setCurrentPage("login")
      } else if (currentPage === "login") {
        setCurrentPage("dashboard")
      }
    })

    // Check if user is already authenticated
    if (authState.isAuthenticated && currentPage === "login") {
      setCurrentPage("dashboard")
    }

    return () => {
      unsubscribe()
    }
  }, [currentPage, authState.isAuthenticated])

  const register = useCallback(async (email: string, password: string, fullName?: string) => {
    try {
      await authService.register({ email, password, full_name: fullName })
      // After registration, automatically log in
      await authService.login({ email, password })
      setCurrentPage("dashboard")
    } catch (error) {
      throw error
    }
  }, [])

  const login = useCallback(async (email: string, password: string, otp?: string) => {
    try {
      await authService.login({ email, password, otp })
      setCurrentPage("dashboard")
    } catch (error) {
      throw error
    }
  }, [])

  const logout = useCallback(async () => {
    await authService.logout()
    setCurrentPage("login")
  }, [])

  return (
    <AppContext.Provider
      value={{
        currentPage,
        setCurrentPage,
        isAuthenticated: authState.isAuthenticated,
        user: authState.user,
        register,
        login,
        logout,
        officerName: authState.user?.full_name || "Dir. Rajesh Kumar, IPS",
      }}
    >
      {children}
    </AppContext.Provider>
  )
}

export function useApp() {
  const context = useContext(AppContext)
  if (!context) throw new Error("useApp must be used within AppProvider")
  return context
}
