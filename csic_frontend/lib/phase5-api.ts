import { getApiBaseUrl } from "@/lib/public-env"

/** Mounted Operation Room app base: `{api}/api/phase5` (no trailing slash). */
export function getPhase5MountBase(): string {
  return `${getApiBaseUrl()}/api/phase5`
}

/** Path after mount, e.g. `/api/cases` → full URL under phase5. */
export function phase5Url(path: string): string {
  const base = getPhase5MountBase()
  const p = path.startsWith("/") ? path : `/${path}`
  return `${base}${p}`
}

export async function phase5Fetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(phase5Url(path), {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers as Record<string, string>),
    },
    cache: "no-store",
  })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(text || `${res.status} ${res.statusText}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export interface Phase5CaseSummary {
  case_id: string
  title: string
  priority: string
  status: string
  lead_investigator: string
  created_at: string
  evidence_count?: number
}

export interface Phase5Health {
  status?: string
  service?: string
}
