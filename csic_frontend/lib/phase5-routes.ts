/** Query param `phase5` — Operation Room section (shareable deep links). */
export const PHASE5_QUERY = "phase5" as const
export const PHASE5_CASE_QUERY = "case" as const

export type Phase5SectionId =
  | "overview"
  | "cases"
  | "evidence"
  | "timeline"
  | "workflow"
  | "studio"

export const PHASE5_SECTIONS: { id: Phase5SectionId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "cases", label: "Cases" },
  { id: "evidence", label: "Evidence" },
  { id: "timeline", label: "Timeline" },
  { id: "workflow", label: "Workflow" },
  { id: "studio", label: "Studio" },
]

export function parsePhase5Section(raw: string | null): Phase5SectionId {
  const allowed = new Set(PHASE5_SECTIONS.map((s) => s.id))
  if (raw && allowed.has(raw as Phase5SectionId)) return raw as Phase5SectionId
  return "overview"
}
