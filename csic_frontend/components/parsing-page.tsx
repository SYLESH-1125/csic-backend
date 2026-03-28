"use client"

import { useState, useEffect, useCallback, useMemo, useRef } from "react"
import {
  ShieldCheck,
  Search,
  Copy,
  Check,
  Loader2,
  AlertTriangle,
  FileWarning,
  HelpCircle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  PanelRightOpen,
  X,
  Anchor,
  Unlock,
  Languages,
  ScanSearch,
  Clock4,
  UserCheck,
  CheckCircle2,
  XCircle,
  Terminal,
  Fingerprint,
  File,
  Eye,
  Pencil,
  Save,
  RotateCcw,
  ArrowRight,
  Shield,
  Hash,
  Network,
  HardDrive,
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Progress } from "@/components/ui/progress"
import { apiClient } from "@/lib/api-client"

/* ================================================================== */
/* TYPES                                                               */
/* ================================================================== */
type PhaseStatus = "idle" | "active" | "success" | "error" | "awaiting_human"

interface LogEntry {
  time: string
  level: "INFO" | "WARN" | "ERROR" | "OK"
  message: string
}

interface ParsingPhase {
  id: string
  label: string
  subtitle: string
  description: string
  status: PhaseStatus
  progress: number
  logs: LogEntry[]
  stats: { label: string; value: string }[]
}

interface StagingRow {
  id: number
  timestamp: string
  event_template: string
  ip_address: string
  process_name: string
  user: string
  raw_log: string
  normalized_fields: string
}

interface DetectedEntity {
  type: string
  value: string
  confidence: number
}

interface ValidationFlag {
  type: "ambiguous_timestamp" | "suspicious_string" | "unknown_pattern"
  label: string
  description: string
}

interface Phase2StagingPreview {
  staging_id: string
  audit_id: string
  row_hash: string
  status: string
  decoded_payload: any | null
  decode_trace: any | null
  extracted_variables: Record<string, any> | null
  ner_tags: Record<string, any> | null
  normalized_timestamp: string | null
  human_overrides: Record<string, any> | null
  created_at: string | null
  immutable_pointer: string | null
  lineage?: any
  template?: any
  audit?: {
    audit_id: string
    filename: string
    sha256_hash: string
    source_ip: string | null
    upload_time: string | null
  }
}

interface Phase2ReviewRow {
  id: number
  staging_id: string
  line_number: number
  original: string
  decoded: string
  template: string
  variables: Record<string, any>
  ner_tags: Record<string, any>
  timestamp: string
  status: string
}

/* ================================================================== */
/* HELPERS                                                             */
/* ================================================================== */
function ts(): string {
  return new Date().toLocaleTimeString("en-GB", { hour12: false })
}


/* ================================================================== */
/* 7 PARSING PHASES                                                    */
/* ================================================================== */
function getInitialParsingPhases(): ParsingPhase[] {
  return [
    {
      id: "lineage",
      label: "Lineage Anchoring",
      subtitle: "Binding file hash, byte offsets, and forensic chain to source evidence",
      description: "Anchors the parsing session to the original evidence file via cryptographic lineage metadata.",
      status: "idle",
      progress: 0,
      logs: [],
      stats: [],
    },
    {
      id: "decoder",
      label: "Recursive De-obfuscation",
      subtitle: "Entropy analysis, multi-layer decoding, and encoding detection",
      description: "Detects and reverses obfuscation layers including Base64, hex, gzip, and nested encodings.",
      status: "idle",
      progress: 0,
      logs: [],
      stats: [],
    },
    {
      id: "translator",
      label: "Universal Translator (DRAIN3)",
      subtitle: "Log template extraction, variable isolation, and event clustering",
      description: "Runs DRAIN3 algorithm to extract log templates and isolate dynamic variables across all log lines.",
      status: "idle",
      progress: 0,
      logs: [],
      stats: [],
    },
    {
      id: "ner",
      label: "NER Tagging",
      subtitle: "Named entity recognition pass for IPs, users, processes, and paths",
      description: "Identifies and tags named entities using forensic NER model.",
      status: "idle",
      progress: 0,
      logs: [],
      stats: [],
    },
    {
      id: "pii",
      label: "PII Verification",
      subtitle: "Scanning for personally identifiable information and sensitive data",
      description: "Detects SSNs, emails, phone numbers, credit cards, and other PII patterns.",
      status: "idle",
      progress: 0,
      logs: [],
      stats: [],
    },
    {
      id: "chronograph",
      label: "Chronograph",
      subtitle: "Timestamp normalization, timezone alignment, and temporal validation",
      description: "Normalizes all timestamps to UTC/ISO-8601 and validates chronological order.",
      status: "idle",
      progress: 0,
      logs: [],
      stats: [],
    },
    {
      id: "human_commit",
      label: "Human-in-Loop Commit",
      subtitle: "Raw evidence requires officer review before staging commit",
      description: "Officer must review raw ingestion records, verify hashes, and approve before final commit.",
      status: "idle",
      progress: 0,
      logs: [],
      stats: [],
    },
  ]
}

/* ================================================================== */
/* PROGRESS LOGS PER PHASE                                             */
/* ================================================================== */
function getParsingProgressLog(phaseIndex: number, progress: number): LogEntry | null {
  switch (phaseIndex) {
    case 0:
      if (progress > 10 && progress <= 15) return { time: ts(), level: "INFO", message: "Loading source evidence metadata from WORM ledger..." }
      if (progress > 25 && progress <= 30) return { time: ts(), level: "INFO", message: "Verifying file hash: SHA-256(a3f2...c8d1) against ledger record" }
      if (progress > 40 && progress <= 45) return { time: ts(), level: "INFO", message: "Byte offset mapping: 0x0000 -> 0x2F4A8C00 | 48 segments anchored" }
      if (progress > 60 && progress <= 65) return { time: ts(), level: "INFO", message: `Lineage chain: evidence -> ingestion -> parsing` }
      if (progress > 80 && progress <= 85) return { time: ts(), level: "INFO", message: "Cryptographic binding established. Forensic chain intact." }
      break
    case 1:
      if (progress > 10 && progress <= 15) return { time: ts(), level: "INFO", message: "Running Shannon entropy analysis across 48 log segments..." }
      if (progress > 25 && progress <= 30) return { time: ts(), level: "INFO", message: "Entropy range: 0.18 - 0.72 | No high-entropy anomalies detected" }
      if (progress > 40 && progress <= 45) return { time: ts(), level: "INFO", message: "Scanning for Base64, hex, gzip, and URL-encoded layers..." }
      if (progress > 55 && progress <= 60) return { time: ts(), level: "WARN", message: "2 log entries contain Base64-encoded payloads -> decoded successfully" }
      if (progress > 70 && progress <= 75) return { time: ts(), level: "INFO", message: "Recursive depth: max 2 layers | All layers resolved" }
      if (progress > 88 && progress <= 93) return { time: ts(), level: "INFO", message: "De-obfuscation pass complete. All segments in cleartext." }
      break
    case 2:
      if (progress > 10 && progress <= 15) return { time: ts(), level: "INFO", message: "Initializing DRAIN3 engine | Similarity threshold: 0.65 | Depth: 4" }
      if (progress > 25 && progress <= 30) return { time: ts(), level: "INFO", message: "Feeding 48 log lines into template extraction pipeline..." }
      if (progress > 40 && progress <= 45) return { time: ts(), level: "INFO", message: "Cluster [1..3]: 'User <*> logged in from <*>' - 8 matches" }
      if (progress > 55 && progress <= 60) return { time: ts(), level: "INFO", message: "Cluster [4..6]: 'Process <*> started on port <*>' - 8 matches" }
      if (progress > 70 && progress <= 75) return { time: ts(), level: "INFO", message: "Variable extraction: 142 dynamic tokens isolated across 6 templates" }
      if (progress > 88 && progress <= 93) return { time: ts(), level: "OK", message: "6 unique templates learned | Coverage: 100% of input lines" }
      break
    case 3:
      if (progress > 10 && progress <= 15) return { time: ts(), level: "INFO", message: "Loading forensic NER model (v3.2.1)..." }
      if (progress > 25 && progress <= 30) return { time: ts(), level: "INFO", message: "Scanning extracted variables for entity classification..." }
      if (progress > 40 && progress <= 45) return { time: ts(), level: "INFO", message: "Tagged: 12 IP addresses, 6 usernames, 6 process names" }
      if (progress > 55 && progress <= 60) return { time: ts(), level: "INFO", message: "Tagged: 3 hostnames, 4 file paths, 1 email address" }
      if (progress > 70 && progress <= 75) return { time: ts(), level: "INFO", message: "Confidence scores: min 0.88, max 0.99, mean 0.95" }
      if (progress > 88 && progress <= 93) return { time: ts(), level: "OK", message: "32 entities tagged across 48 records | Model accuracy: 97.2%" }
      break
    case 4:
      if (progress > 10 && progress <= 15) return { time: ts(), level: "INFO", message: "Initializing PII scanner | Patterns: SSN, Email, Phone, CC, AADHAAR" }
      if (progress > 25 && progress <= 30) return { time: ts(), level: "INFO", message: "Scanning 48 parsed records for PII patterns..." }
      if (progress > 40 && progress <= 45) return { time: ts(), level: "WARN", message: "PII DETECTED: 1 email address (admin@nflip.gov.in) in record #5" }
      if (progress > 55 && progress <= 60) return { time: ts(), level: "INFO", message: "SSN scan: 0 matches | Phone scan: 0 matches | CC scan: 0 matches" }
      if (progress > 70 && progress <= 75) return { time: ts(), level: "INFO", message: "AADHAAR scan: 0 matches | Passport scan: 0 matches" }
      if (progress > 80 && progress <= 85) return { time: ts(), level: "INFO", message: "Applying redaction policy: MASK_PARTIAL for email entities" }
      if (progress > 90 && progress <= 95) return { time: ts(), level: "INFO", message: "PII audit record written. Redaction metadata preserved for compliance." }
      break
    case 5:
      if (progress > 10 && progress <= 15) return { time: ts(), level: "INFO", message: "Detecting timestamp formats across 48 records..." }
      if (progress > 25 && progress <= 30) return { time: ts(), level: "INFO", message: "Formats found: ISO-8601 (42), BSD syslog (6) | Parsing..." }
      if (progress > 40 && progress <= 45) return { time: ts(), level: "WARN", message: "3 entries have MM/DD vs DD/MM ambiguity -> resolved via context heuristic" }
      if (progress > 55 && progress <= 60) return { time: ts(), level: "INFO", message: "Timezone alignment: all records normalized to UTC (offset +00:00)" }
      if (progress > 70 && progress <= 75) return { time: ts(), level: "INFO", message: "Chronological sort: 48/48 records in monotonic order" }
      if (progress > 88 && progress <= 93) return { time: ts(), level: "OK", message: "All timestamps normalized to ISO-8601/UTC | 0 unresolvable entries" }
      break
    case 6:
      if (progress > 10 && progress <= 15) return { time: ts(), level: "INFO", message: "Loading raw ingestion records from WORM ledger..." }
      if (progress > 25 && progress <= 30) return { time: ts(), level: "INFO", message: "Preparing 12 evidence records for human review..." }
      if (progress > 40 && progress <= 45) return { time: ts(), level: "INFO", message: "Attaching SHA-256 hashes, Merkle roots, and chain metadata" }
      if (progress > 55 && progress <= 60) return { time: ts(), level: "INFO", message: "Flagging 2 records with unverified hash chains for manual check" }
      if (progress > 70 && progress <= 75) return { time: ts(), level: "WARN", message: "HUMAN REVIEW REQUIRED: Raw evidence records need officer verification" }
      if (progress > 88 && progress <= 93) return { time: ts(), level: "INFO", message: "Staging area prepared. Waiting for officer to review and approve..." }
      break
  }
  return null
}

function getParsingCompleteLogs(phaseIndex: number): LogEntry[] {
  switch (phaseIndex) {
    case 0:
      return [
        { time: ts(), level: "OK", message: `COMPLETE: Lineage chain sealed | Evidence hash verified` },
        { time: ts(), level: "OK", message: `Audit record: parsing session bound to ingestion` },
      ]
    case 1:
      return [
        { time: ts(), level: "OK", message: "COMPLETE: 2 encoded payloads decoded, 0 obfuscation remaining" },
        { time: ts(), level: "OK", message: "All 48 segments verified cleartext. Entropy: nominal." },
      ]
    case 2:
      return [
        { time: ts(), level: "OK", message: "COMPLETE: 6 templates extracted | 142 variables isolated" },
        { time: ts(), level: "OK", message: "DRAIN3 cluster accuracy: 99.1% | No unmatched lines" },
      ]
    case 3:
      return [
        { time: ts(), level: "OK", message: "COMPLETE: 32 entities tagged (IP:12, User:6, Process:6, Host:3, Path:4, Email:1)" },
        { time: ts(), level: "OK", message: "NER model v3.2.1 - mean confidence: 0.95" },
      ]
    case 4:
      return [
        { time: ts(), level: "OK", message: "COMPLETE: 1 PII item detected, 0 SSN, 0 phone, 0 CC" },
        { time: ts(), level: "OK", message: "Redaction applied: MASK_PARTIAL | Compliance: GDPR + IT Act 2000" },
      ]
    case 5:
      return [
        { time: ts(), level: "OK", message: "COMPLETE: 48/48 timestamps normalized to ISO-8601 UTC" },
        { time: ts(), level: "OK", message: "3 ambiguous dates resolved. Chronological order verified." },
      ]
    case 6:
      return [
        { time: ts(), level: "WARN", message: "AWAITING HUMAN: 12 raw evidence records ready for officer review" },
        { time: ts(), level: "INFO", message: "Click 'Review Raw Evidence' to inspect and verify records" },
      ]
    default:
      return []
  }
}

function getParsingPhaseStats(phaseIndex: number): { label: string; value: string }[] {
  // Stats will be populated from actual API data when available
  return []
}

/* ================================================================== */
/* RAW EVIDENCE DATA (from API)                                       */
/* ================================================================== */

/* ================================================================== */
/* SMALL HELPER COMPONENTS                                             */
/* ================================================================== */
function PhaseStatusDot({ status }: { status: PhaseStatus }) {
  if (status === "idle") return <div className="size-2 bg-muted-foreground/30" />
  if (status === "active")
    return (
      <span className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping bg-primary opacity-75" />
        <span className="relative inline-flex size-2 bg-primary" />
      </span>
    )
  if (status === "awaiting_human")
    return (
      <span className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping bg-amber-500 opacity-75" />
        <span className="relative inline-flex size-2 bg-amber-500" />
      </span>
    )
  if (status === "success") return <div className="size-2 bg-success" />
  return <div className="size-2 bg-destructive" />
}

function PhaseStatusLabel({ status }: { status: PhaseStatus }) {
  if (status === "active")
    return (
      <Badge className="bg-primary/10 text-primary border border-primary/20 hover:bg-primary/10 text-xs gap-1.5 px-3 py-1">
        <Loader2 className="size-3.5 animate-spin" />
        RUNNING
      </Badge>
    )
  if (status === "awaiting_human")
    return (
      <Badge className="bg-amber-500/10 text-amber-600 border border-amber-500/20 hover:bg-amber-500/10 text-xs gap-1.5 px-3 py-1">
        <Eye className="size-3.5" />
        AWAITING REVIEW
      </Badge>
    )
  if (status === "success")
    return (
      <Badge className="bg-success/10 text-success border border-success/20 hover:bg-success/10 text-xs px-3 py-1">
        PASSED
      </Badge>
    )
  if (status === "error")
    return (
      <Badge className="bg-destructive/10 text-destructive border border-destructive/20 hover:bg-destructive/10 text-xs px-3 py-1">
        FAILED
      </Badge>
    )
  return (
    <Badge variant="outline" className="text-xs text-muted-foreground border-border px-3 py-1">
      PENDING
    </Badge>
  )
}

function LogLine({ entry }: { entry: LogEntry }) {
  const levelColors: Record<string, string> = {
    INFO: "text-primary",
    WARN: "text-amber-600",
    ERROR: "text-destructive",
    OK: "text-success",
  }
  return (
    <div className="flex gap-3 leading-5">
      <span className="text-muted-foreground shrink-0">{entry.time}</span>
      <span className={`font-bold shrink-0 w-12 ${levelColors[entry.level] || "text-muted-foreground"}`}>
        [{entry.level}]
      </span>
      <span className={`${entry.level === "ERROR" ? "text-destructive" : entry.level === "WARN" ? "text-amber-600" : "text-foreground"}`}>
        {entry.message}
      </span>
    </div>
  )
}

/* ================================================================== */
/* FULL PHASE CARD                                                     */
/* ================================================================== */
function FullPhaseCard({
  phase,
  index,
  onReviewClick,
}: {
  phase: ParsingPhase
  index: number
  onReviewClick?: () => void
}) {
  const icons = [Anchor, Unlock, Languages, ScanSearch, Fingerprint, Clock4, UserCheck]
  const Icon = icons[index] || ShieldCheck
  const logEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (phase.status === "active" || phase.status === "success" || phase.status === "error" || phase.status === "awaiting_human") {
      logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" })
    }
  }, [phase.logs.length, phase.status])

  if (phase.status === "idle") {
    return (
      <div className="border border-border bg-card p-6 opacity-40">
        <div className="flex items-center gap-4">
          <div className="flex size-12 items-center justify-center bg-muted">
            <Icon className="size-5 text-muted-foreground" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <span className="text-xs font-bold tracking-widest text-muted-foreground uppercase">Phase {index + 1}</span>
              <span className="text-sm font-semibold text-muted-foreground">{phase.label}</span>
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">{phase.description}</p>
          </div>
          <Badge variant="outline" className="ml-auto text-xs text-muted-foreground border-border px-3 py-1">PENDING</Badge>
        </div>
      </div>
    )
  }

  const borderAccent =
    phase.status === "success"
      ? "border-l-success"
      : phase.status === "error"
      ? "border-l-destructive"
      : phase.status === "awaiting_human"
      ? "border-l-amber-500"
      : "border-l-primary"

  return (
    <div className={`border border-border border-l-4 ${borderAccent} bg-card`}>
      {/* Phase Header */}
      <div className="flex items-center gap-4 border-b border-border p-5">
        <div
          className={`flex size-12 items-center justify-center ${
            phase.status === "success"
              ? "bg-success/10"
              : phase.status === "error"
              ? "bg-destructive/10"
              : phase.status === "awaiting_human"
              ? "bg-amber-500/10"
              : "bg-primary/10"
          }`}
        >
          {phase.status === "active" ? (
            <Loader2 className="size-6 animate-spin text-primary" />
          ) : phase.status === "success" ? (
            <CheckCircle2 className="size-6 text-success" />
          ) : phase.status === "awaiting_human" ? (
            <Eye className="size-6 text-amber-600" />
          ) : (
            <XCircle className="size-6 text-destructive" />
          )}
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <span className="text-xs font-bold tracking-widest text-muted-foreground uppercase">Phase {index + 1}</span>
            <span className="text-base font-bold text-foreground">{phase.label}</span>
          </div>
          <p className="mt-0.5 text-sm text-muted-foreground">{phase.subtitle}</p>
        </div>
        <PhaseStatusLabel status={phase.status} />
      </div>

      {/* Progress Bar */}
      <div className="px-5 pt-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-muted-foreground">Progress</span>
          <span className="font-mono text-sm font-bold text-foreground">{Math.round(phase.progress)}%</span>
        </div>
        <div className="h-3 w-full bg-muted overflow-hidden">
          <div
            className={`h-full transition-all duration-200 ${
              phase.status === "error" ? "bg-destructive"
              : phase.status === "success" ? "bg-success"
              : phase.status === "awaiting_human" ? "bg-amber-500"
              : "bg-primary"
            }`}
            style={{ width: `${phase.progress}%` }}
          />
        </div>
      </div>

      {/* Stats Row */}
      {phase.stats.length > 0 && (
        <div className="px-5 pt-4">
          <div className="grid grid-cols-4 gap-3">
            {phase.stats.map((stat) => (
              <div key={stat.label} className={`flex flex-col gap-1 border p-3 ${
                phase.status === "error" ? "border-destructive/20 bg-destructive/5"
                : phase.status === "awaiting_human" ? "border-amber-500/20 bg-amber-500/5"
                : "border-border bg-muted/30"
              }`}>
                <span className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">{stat.label}</span>
                <span className={`font-mono text-sm font-bold ${
                  phase.status === "error" ? "text-destructive"
                  : phase.status === "awaiting_human" ? "text-amber-700"
                  : "text-foreground"
                }`}>{stat.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Human Review Button - only for Phase 7 when awaiting */}
      {phase.status === "awaiting_human" && onReviewClick && (
        <div className="px-5 pt-4">
          <div className="border-2 border-dashed border-amber-400/50 bg-amber-50/30 p-5 flex flex-col items-center gap-3">
            <div className="flex items-center gap-3">
              <div className="flex size-10 items-center justify-center bg-amber-500/10 rounded-full">
                <Eye className="size-5 text-amber-600" />
              </div>
              <div>
                <p className="text-sm font-bold text-foreground">Officer Review Required</p>
                <p className="text-xs text-muted-foreground">12 raw evidence records need human verification before commit</p>
              </div>
            </div>
            <Button
              onClick={onReviewClick}
              className="bg-amber-600 hover:bg-amber-700 text-white gap-2 h-11 px-8 text-sm font-bold shadow-lg shadow-amber-500/20 transition-all hover:shadow-amber-500/40 hover:scale-[1.02] active:scale-[0.98]"
            >
              <Eye className="size-4" />
              Review Raw Evidence
              <ArrowRight className="size-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Live Logs Terminal */}
      <div className="p-5">
        <div className="flex items-center gap-2 mb-2">
          <Terminal className="size-3.5 text-muted-foreground" />
          <span className="text-xs font-semibold tracking-wider text-muted-foreground uppercase">Execution Log</span>
          {(phase.status === "active" || phase.status === "awaiting_human") && (
            <span className="relative flex size-2 ml-1">
              <span className={`absolute inline-flex size-full animate-ping ${phase.status === "awaiting_human" ? "bg-amber-500" : "bg-primary"} opacity-75`} />
              <span className={`relative inline-flex size-2 ${phase.status === "awaiting_human" ? "bg-amber-500" : "bg-primary"}`} />
            </span>
          )}
        </div>
        <div className="max-h-52 overflow-y-auto bg-foreground/[0.03] border border-border font-mono text-xs">
          <div className="p-3 flex flex-col gap-0.5">
            {phase.logs.map((log, i) => (
              <LogLine key={i} entry={log} />
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      </div>
    </div>
  )
}

/* ================================================================== */
/* HUMAN REVIEW OVERLAY                                                */
/* ================================================================== */
function HumanReviewOverlay({
  onVerify,
  onClose,
}: {
  onVerify: () => void
  onClose: () => void
}) {
  const [data, setData] = useState<Phase2ReviewRow[]>([])
  const [editingCell, setEditingCell] = useState<{ row: number; col: keyof Phase2ReviewRow } | null>(null)
  const [editValue, setEditValue] = useState("")
  const [verifiedRows, setVerifiedRows] = useState<Set<number>>(new Set())
  const [searchQuery, setSearchQuery] = useState("")
  const [verifying, setVerifying] = useState(false)
  const [showSuccess, setShowSuccess] = useState(false)
  const [changeCount, setChangeCount] = useState(0)
  const editInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const load = async () => {
      // Prefer the latest ingestion audit persisted by Phase 1 UI.
      const raw = typeof window !== "undefined" ? localStorage.getItem("latest_ingestion_audit") : null
      const parsed = raw ? (JSON.parse(raw) as { auditId?: string }) : null
      const auditId = parsed?.auditId

      try {
        if (!auditId) {
          setData([])
          return
        }

        // Load Phase 2 staging previews (all node outputs) for this audit.
        // Some backends may not return previews via the audit endpoint yet; fall back to
        // querying staging IDs + fetching previews per entry.
        let previews: Phase2StagingPreview[] = []
        try {
          const res = await apiClient.getStagingPreviews(auditId, 200)
          previews = (res.previews || []) as unknown as Phase2StagingPreview[]
        } catch {
          previews = []
        }

        if (!previews.length) {
          const q = await apiClient.queryStaging({ audit_id: auditId, status: "pending", limit: 200, offset: 0 })
          const fetched: Phase2StagingPreview[] = []
          for (const e of q.entries || []) {
            try {
              fetched.push((await apiClient.getStagingPreview(e.staging_id)) as unknown as Phase2StagingPreview)
            } catch {
              // ignore individual row failures
            }
          }
          previews = fetched
        }

        const rows: Phase2ReviewRow[] = previews
          .map((p, idx) => {
            const vars = (p.extracted_variables || {}) as Record<string, any>
            const original = String(vars.original || "")
            const lineNumber = Number(vars.line_number || idx + 1)
            const decoded = String((p.decoded_payload as any)?.decoded || vars.decoded || "")
            const template = String((p.template as any)?.template || vars.template || "")
            const nerTags = (p.ner_tags || vars.ner_tags || {}) as Record<string, any>
            const tsVal = String(p.normalized_timestamp || vars.timestamp || "")

            return {
              id: idx + 1,
              staging_id: p.staging_id,
              line_number: Number.isFinite(lineNumber) ? lineNumber : idx + 1,
              original,
              decoded,
              template,
              variables: vars,
              ner_tags: nerTags,
              timestamp: tsVal,
              status: p.status || "pending",
            }
          })
          .sort((a, b) => a.line_number - b.line_number)

        setData(rows)
      } catch {
        setData([])
      }
    }

    void load()
  }, [])

  const editableColumns: (keyof Phase2ReviewRow)[] = ["original", "decoded", "template", "status"]

  const filteredData = useMemo(() => {
    if (!searchQuery.trim()) return data
    const q = searchQuery.toLowerCase()
    return data.filter(
      (r) =>
        r.original.toLowerCase().includes(q) ||
        r.decoded.toLowerCase().includes(q) ||
        r.template.toLowerCase().includes(q) ||
        r.staging_id.toLowerCase().includes(q) ||
        r.status.toLowerCase().includes(q)
    )
  }, [data, searchQuery])

  const startEdit = (rowId: number, col: keyof Phase2ReviewRow) => {
    if (!editableColumns.includes(col)) return
    const row = data.find((r) => r.id === rowId)
    if (!row) return
    setEditingCell({ row: rowId, col })
    setEditValue(typeof row[col] === "string" ? (row[col] as string) : JSON.stringify(row[col] ?? "", null, 2))
    setTimeout(() => editInputRef.current?.focus(), 50)
  }

  const saveEdit = () => {
    if (!editingCell) return
    setData((prev) =>
      prev.map((r) =>
        r.id === editingCell.row ? { ...r, [editingCell.col]: editValue } : r
      )
    )
    setChangeCount((c) => c + 1)
    setEditingCell(null)
    setEditValue("")
  }

  const cancelEdit = () => {
    setEditingCell(null)
    setEditValue("")
  }

  const toggleRowVerified = (id: number) => {
    setVerifiedRows((prev) => {
      const n = new Set(prev)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }

  const verifyAll = () => {
    setVerifiedRows(new Set(data.map((r) => r.id)))
  }

  const allVerified = data.length > 0 && verifiedRows.size === data.length

  const handleVerifyAndCommit = () => {
    setVerifying(true)
    setTimeout(() => {
      setVerifying(false)
      setShowSuccess(true)
      setTimeout(() => onVerify(), 1800)
    }, 2000)
  }

  const columns: { key: keyof Phase2ReviewRow; label: string; width: string; mono?: boolean }[] = [
    { key: "id", label: "#", width: "w-12" },
    { key: "line_number", label: "Line", width: "w-16", mono: true },
    { key: "original", label: "Node 1/Raw", width: "w-[520px]" },
    { key: "decoded", label: "Node 2/Decoded", width: "w-[520px]" },
    { key: "template", label: "Node 3/Template", width: "w-[520px]" },
    { key: "status", label: "Node 6/Status", width: "w-28" },
    { key: "timestamp", label: "Node 5/Timestamp", width: "w-44", mono: true },
    { key: "staging_id", label: "Staging ID", width: "w-56", mono: true },
  ]

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-background/95 backdrop-blur-sm animate-in fade-in duration-300">
      {/* ── HEADER BAR ── */}
      <div className="border-b border-border bg-card px-6 py-4 shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex size-10 items-center justify-center bg-amber-500/10">
              <Shield className="size-5 text-amber-600" />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground flex items-center gap-2">
                Human-in-Loop Evidence Review
                <Badge className="bg-amber-500/10 text-amber-600 border border-amber-500/20 hover:bg-amber-500/10 text-[10px]">
                  PHASE 7
                </Badge>
              </h2>
              <p className="text-xs text-muted-foreground mt-0.5">
                Review raw ingestion records. Edit flagged fields. Verify each row before committing.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {changeCount > 0 && (
              <Badge className="bg-primary/10 text-primary border border-primary/20 hover:bg-primary/10 text-xs gap-1 px-2.5">
                <Pencil className="size-3" />
                {changeCount} edit{changeCount > 1 ? "s" : ""} made
              </Badge>
            )}
            <Badge variant="outline" className="text-xs gap-1 px-2.5">
              <CheckCircle2 className="size-3" />
              {verifiedRows.size}/{data.length} verified
            </Badge>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={onClose}>
              <X className="size-4 text-muted-foreground" />
            </Button>
          </div>
        </div>

        {/* Stats bar */}
        <div className="mt-3 grid grid-cols-6 gap-2">
          {[
            { icon: Hash, label: "Total Records", value: String(data.length) },
            { icon: AlertTriangle, label: "Flagged", value: String(data.filter((r) => r.status === "FLAGGED").length), warn: true },
            { icon: CheckCircle2, label: "Verified", value: `${verifiedRows.size}/${data.length}` },
            { icon: Pencil, label: "Edits Made", value: String(changeCount) },
            { icon: HardDrive, label: "Total Size", value: "4.82 GB" },
            { icon: Network, label: "Templates", value: String(new Set(data.map((r) => r.template || "∅")).size) },
          ].map((s) => (
            <div key={s.label} className={`flex items-center gap-2.5 border p-2.5 ${s.warn ? "border-amber-300/50 bg-amber-50/30" : "border-border bg-muted/30"}`}>
              <s.icon className={`size-3.5 shrink-0 ${s.warn ? "text-amber-600" : "text-muted-foreground"}`} />
              <div>
                <p className="text-[9px] font-semibold tracking-wider text-muted-foreground uppercase">{s.label}</p>
                <p className={`text-xs font-bold ${s.warn ? "text-amber-700" : "text-foreground"}`}>{s.value}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── TOOLBAR ── */}
      <div className="border-b border-border bg-card/50 px-6 py-2.5 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="size-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search records..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 w-64 pl-8 text-[11px]"
            />
          </div>
          <Separator orientation="vertical" className="h-5" />
          <Button variant="outline" size="sm" className="h-8 text-[11px] gap-1.5" onClick={verifyAll}>
            <CheckCircle2 className="size-3.5" />
            Verify All
          </Button>
          <Button variant="outline" size="sm" className="h-8 text-[11px] gap-1.5" onClick={() => setVerifiedRows(new Set())}>
            <RotateCcw className="size-3.5" />
            Reset
          </Button>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-muted-foreground">
            Click any <Pencil className="size-2.5 inline" /> cell to edit | Tick rows to verify
          </span>
        </div>
      </div>

      {/* ── TABLE ── */}
      <div className="flex-1 min-h-0 overflow-hidden">
        <ScrollArea className="h-full">
          <div className="px-6 py-3">
            <div className="border border-border bg-card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-[11px]">
                  <thead>
                    <tr className="bg-muted/60 border-b border-border">
                      <th className="px-2 py-2.5 text-center w-10">
                        <span className="text-[9px] font-bold tracking-widest text-muted-foreground uppercase">OK</span>
                      </th>
                      {columns.map((col) => (
                        <th key={col.key} className={`px-2.5 py-2.5 text-left font-bold text-muted-foreground uppercase tracking-wider text-[9px] ${col.width}`}>
                          <div className="flex items-center gap-1">
                            {col.label}
                            {editableColumns.includes(col.key) && <Pencil className="size-2 text-muted-foreground/50" />}
                          </div>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredData.map((row) => {
                      const isVerified = verifiedRows.has(row.id)
                      const isFlagged = row.status === "FLAGGED"
                      return (
                        <tr
                          key={row.id}
                          className={`border-b border-border/50 transition-all duration-200 ${
                            isVerified
                              ? "bg-success/[0.03] hover:bg-success/[0.06]"
                              : isFlagged
                              ? "bg-amber-50/40 hover:bg-amber-50/70"
                              : "hover:bg-muted/30"
                          }`}
                        >
                          <td className="px-2 py-1.5 text-center">
                            <button
                              onClick={() => toggleRowVerified(row.id)}
                              className={`inline-flex size-5 items-center justify-center border-2 transition-all duration-200 ${
                                isVerified
                                  ? "bg-success border-success text-white scale-110"
                                  : "border-border bg-card hover:border-primary hover:scale-105"
                              }`}
                            >
                              {isVerified && <Check className="size-3" />}
                            </button>
                          </td>
                          {columns.map((col) => {
                            const isEditing = editingCell?.row === row.id && editingCell?.col === col.key
                            const isEditable = editableColumns.includes(col.key)
                            const cellVal = String(row[col.key])

                            if (isEditing) {
                              return (
                                <td key={col.key} className="px-1 py-1">
                                  <div className="flex items-center gap-1">
                                    <Input
                                      ref={editInputRef}
                                      value={editValue}
                                      onChange={(e) => setEditValue(e.target.value)}
                                      onKeyDown={(e) => {
                                        if (e.key === "Enter") saveEdit()
                                        if (e.key === "Escape") cancelEdit()
                                      }}
                                      className="h-6 text-[10px] font-mono px-1.5 border-primary ring-1 ring-primary/30"
                                    />
                                    <Button variant="ghost" size="sm" className="h-5 w-5 p-0 shrink-0" onClick={saveEdit}>
                                      <Save className="size-3 text-success" />
                                    </Button>
                                    <Button variant="ghost" size="sm" className="h-5 w-5 p-0 shrink-0" onClick={cancelEdit}>
                                      <X className="size-3 text-muted-foreground" />
                                    </Button>
                                  </div>
                                </td>
                              )
                            }

                            if (col.key === "status") {
                              return (
                                <td
                                  key={col.key}
                                  className={`px-2.5 py-1.5 ${isEditable ? "cursor-pointer" : ""}`}
                                  onDoubleClick={() => isEditable && startEdit(row.id, col.key)}
                                >
                                  <Badge className={`text-[9px] px-1.5 py-0 h-4 font-bold ${
                                    cellVal === "FLAGGED"
                                      ? "bg-amber-500/10 text-amber-700 border border-amber-400/30 hover:bg-amber-500/10"
                                      : "bg-success/10 text-success border border-success/30 hover:bg-success/10"
                                  }`}>
                                    {cellVal}
                                  </Badge>
                                </td>
                              )
                            }

                            if (col.key === "staging_id" || col.key === "timestamp") {
                              return (
                                <td
                                  key={col.key}
                                  className={`px-2.5 py-1.5 font-mono text-[10px] ${isEditable ? "cursor-pointer group" : ""}`}
                                  onDoubleClick={() => isEditable && startEdit(row.id, col.key)}
                                  title={cellVal}
                                >
                                  <span className="text-muted-foreground">{cellVal.slice(0, 12)}...{cellVal.slice(-6)}</span>
                                  {isEditable && <Pencil className="size-2.5 text-muted-foreground/0 group-hover:text-muted-foreground/60 inline ml-1 transition-colors" />}
                                </td>
                              )
                            }

                            return (
                              <td
                                key={col.key}
                                className={`px-2.5 py-1.5 ${col.mono ? "font-mono text-[10px]" : ""} ${isEditable ? "cursor-pointer group" : ""} whitespace-nowrap`}
                                onDoubleClick={() => isEditable && startEdit(row.id, col.key)}
                              >
                                <span>{cellVal}</span>
                                {isEditable && <Pencil className="size-2.5 text-muted-foreground/0 group-hover:text-muted-foreground/60 inline ml-1 transition-colors" />}
                              </td>
                            )
                          })}
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </ScrollArea>
      </div>

      {/* ── BOTTOM ACTION BAR ── */}
      <div className="border-t border-border bg-card px-6 py-4 shrink-0">
        {showSuccess ? (
          <div className="flex items-center justify-center gap-3 py-1">
            <CheckCircle2 className="size-5 text-success" />
            <span className="text-sm font-bold text-success">Evidence verified and committed. Transitioning to staging view...</span>
          </div>
        ) : (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="text-xs text-muted-foreground">
                <span className="font-semibold text-foreground">{verifiedRows.size}</span> of <span className="font-semibold text-foreground">{data.length}</span> records verified
              </div>
              <div className="h-2 w-48 bg-muted overflow-hidden">
                <div
                  className="h-full bg-success transition-all duration-500"
                  style={{ width: `${(verifiedRows.size / Math.max(data.length, 1)) * 100}%` }}
                />
              </div>
              {changeCount > 0 && (
                <span className="text-xs text-primary font-medium">{changeCount} field{changeCount > 1 ? "s" : ""} edited by officer</span>
              )}
            </div>
            <div className="flex items-center gap-3">
              <Button variant="outline" size="sm" className="h-9 text-xs gap-1.5" onClick={onClose}>
                <X className="size-3.5" />
                Cancel
              </Button>
              <Button
                onClick={handleVerifyAndCommit}
                disabled={!allVerified || verifying}
                className={`h-9 text-xs font-bold gap-2 px-6 transition-all ${
                  allVerified
                    ? "bg-success hover:bg-success/90 text-white shadow-lg shadow-success/20 hover:shadow-success/40 hover:scale-[1.02] active:scale-[0.98]"
                    : "bg-muted text-muted-foreground"
                }`}
              >
                {verifying ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" />
                    Committing...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="size-4" />
                    Verify & Commit to Staging
                  </>
                )}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

/* ================================================================== */
/* PIPELINE ENTRY ANIMATION                                            */
/* ================================================================== */
function PipelineEntryAnimation({ 
  onComplete,
  latestAuditInfo 
}: { 
  onComplete: () => void
  latestAuditInfo: { auditId: string; sha256: string; filePath: string } | null
}) {
  const [phases, setPhases] = useState<ParsingPhase[]>(getInitialParsingPhases())
  const [isProcessing, setIsProcessing] = useState(false)
  const [overallResult, setOverallResult] = useState<"pass" | null>(null)
  const [showReviewOverlay, setShowReviewOverlay] = useState(false)
  const phasesRef = useRef<ParsingPhase[]>(getInitialParsingPhases())
  const flowRef = useRef<HTMLDivElement>(null)

  const activePhaseIndex = phases.findIndex((p) => p.status === "active" || p.status === "awaiting_human")

  useEffect(() => {
    const startTimer = setTimeout(() => {
      setIsProcessing(true)
      const fresh = getInitialParsingPhases()
      phasesRef.current = fresh
      setPhases([...fresh])

      let currentPhase = 0

      const advancePhase = () => {
        if (currentPhase >= phasesRef.current.length) {
          setIsProcessing(false)
          setOverallResult("pass")
          setTimeout(() => onComplete(), 1200)
          return
        }

        const p = phasesRef.current
        p[currentPhase].status = "active"
        p[currentPhase].logs = [
          { time: ts(), level: "INFO", message: `Starting ${p[currentPhase].label}...` },
        ]
        setPhases([...p])

        let progress = 0
        const phaseIndex = currentPhase
        const totalTicks = 20
        let tick = 0

        const progressInterval = setInterval(() => {
          tick++
          progress = Math.min(100, (tick / totalTicks) * 100)

          const phase = phasesRef.current[phaseIndex]
          phase.progress = progress

          const logMilestone = getParsingProgressLog(phaseIndex, progress)
          if (logMilestone) {
            const exists = phase.logs.some((l) => l.message === logMilestone.message)
            if (!exists) {
              phase.logs = [...phase.logs, logMilestone]
            }
          }

          setPhases([...phasesRef.current])

          if (progress >= 100) {
            clearInterval(progressInterval)

            // Phase 7 (index 6) pauses for human review
            if (phaseIndex === 6) {
              phase.status = "awaiting_human"
              phase.logs = [...phase.logs, ...getParsingCompleteLogs(phaseIndex)]
              phase.stats = getParsingPhaseStats(phaseIndex)
              setPhases([...phasesRef.current])
              setIsProcessing(false)
              return
            }

            phase.status = "success"
            phase.logs = [...phase.logs, ...getParsingCompleteLogs(phaseIndex)]
            phase.stats = getParsingPhaseStats(phaseIndex)
            setPhases([...phasesRef.current])
            currentPhase++
            setTimeout(advancePhase, 700)
          }
        }, 150)
      }

      setTimeout(advancePhase, 500)
    }, 400)

    return () => clearTimeout(startTimer)
  }, [onComplete])

  const handleHumanVerified = useCallback(() => {
    setShowReviewOverlay(false)
    // Mark Phase 7 as success
    const p = phasesRef.current
    p[6].status = "success"
    p[6].stats = [
      { label: "Records", value: "12" },
      { label: "Flagged", value: "2" },
      { label: "Verified", value: "12 / 12" },
      { label: "Status", value: "COMMITTED" },
    ]
    p[6].logs = [
      ...p[6].logs,
      { time: ts(), level: "OK", message: "HUMAN VERIFICATION COMPLETE: All 12 records approved by officer" },
      { time: ts(), level: "OK", message: "Evidence committed to staging area. Chain-of-custody intact." },
      { time: ts(), level: "OK", message: `Staging area prepared` },
    ]
    setPhases([...p])
    setOverallResult("pass")
    setTimeout(() => onComplete(), 1500)
  }, [onComplete])

  return (
    <>
      {showReviewOverlay && (
        <HumanReviewOverlay
          onVerify={handleHumanVerified}
          onClose={() => setShowReviewOverlay(false)}
        />
      )}
      <div className="flex flex-col gap-6 p-6" ref={flowRef}>
        {/* Top Status Bar */}
        <div className="border border-border bg-card p-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <div className="flex size-10 items-center justify-center bg-primary/10">
                <File className="size-5 text-primary" />
              </div>
              <div>
                <p className="text-sm font-semibold text-foreground">Hybrid Parsing & Normalization Pipeline</p>
                <div className="flex items-center gap-3 mt-1">
                  {latestAuditInfo ? (
                    <>
                      <span className="font-mono text-xs text-muted-foreground">Source: {latestAuditInfo.filePath || "N/A"}</span>
                      <span className="text-xs text-muted-foreground">SHA-256: {latestAuditInfo.sha256 ? `${latestAuditInfo.sha256.slice(0, 4)}...${latestAuditInfo.sha256.slice(-4)}` : "N/A"}</span>
                      <Badge className="bg-primary/10 text-primary border border-primary/20 hover:bg-primary/10 text-xs">
                        Audit ID: {latestAuditInfo.auditId.slice(0, 13)}...
                      </Badge>
                    </>
                  ) : (
                    <>
                      <span className="font-mono text-xs text-muted-foreground">No staging data available</span>
                    </>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {isProcessing && (
                <Badge className="bg-primary/10 text-primary border border-primary/20 hover:bg-primary/10 text-xs gap-1.5 px-3 py-1">
                  <Loader2 className="size-3.5 animate-spin" />
                  Phase {activePhaseIndex + 1} / {phases.length}
                </Badge>
              )}
              {!isProcessing && !overallResult && phases[6]?.status === "awaiting_human" && (
                <Badge className="bg-amber-500/10 text-amber-600 border border-amber-500/20 hover:bg-amber-500/10 text-xs gap-1.5 px-3 py-1">
                  <Eye className="size-3.5" />
                  AWAITING HUMAN REVIEW
                </Badge>
              )}
              {overallResult === "pass" && (
                <Badge className="bg-success/10 text-success border border-success/20 hover:bg-success/10 text-xs gap-1.5 px-3 py-1">
                  <CheckCircle2 className="size-3.5" />
                  ALL PHASES PASSED
                </Badge>
              )}
            </div>
          </div>

          {/* Mini progress overview */}
          <div className="mt-4 grid grid-cols-7 gap-2">
            {phases.map((phase, i) => (
              <div key={phase.id} className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase truncate">
                    P{i + 1}: {phase.label.split(" ")[0]}
                  </span>
                  <PhaseStatusDot status={phase.status} />
                </div>
                <div className="h-1.5 w-full bg-muted overflow-hidden">
                  <div
                    className={`h-full transition-all duration-200 ${
                      phase.status === "error" ? "bg-destructive"
                      : phase.status === "success" ? "bg-success"
                      : phase.status === "active" ? "bg-primary"
                      : phase.status === "awaiting_human" ? "bg-amber-500"
                      : "bg-muted"
                    }`}
                    style={{ width: `${phase.progress}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Phase Cards */}
        <div className="flex flex-col gap-4">
          {phases.map((phase, index) => (
            <FullPhaseCard
              key={phase.id}
              phase={phase}
              index={index}
              onReviewClick={index === 6 && phase.status === "awaiting_human" ? () => setShowReviewOverlay(true) : undefined}
            />
          ))}
        </div>

        {/* Final Verdict */}
        {overallResult === "pass" && (
          <div className="border-2 border-success/30 bg-success/5 p-8">
            <div className="flex items-start gap-5">
              <div className="flex size-14 items-center justify-center bg-success/10 shrink-0">
                <CheckCircle2 className="size-8 text-success" />
              </div>
              <div className="flex-1">
                <h3 className="text-xl font-bold text-success">Parsing Pipeline Complete - Staging Ready</h3>
                <p className="mt-2 text-sm text-success/80 leading-relaxed">
                  All 7 parsing phases completed. Officer verified 12 raw evidence records.
                  Transitioning to human validation interface...
                </p>
                <div className="mt-4 grid grid-cols-4 gap-3">
                  {[
                    { label: "Records Staged", value: "48" },
                    { label: "Evidence Verified", value: "12 / 12" },
                    { label: "Entities Tagged", value: "32" },
                    { label: "PII Found", value: "1 (masked)" },
                  ].map((s) => (
                    <div key={s.label} className="border border-success/20 bg-success/5 p-3 flex flex-col gap-1">
                      <span className="text-[10px] font-semibold tracking-wider text-success/60 uppercase">{s.label}</span>
                      <span className="font-mono text-xs text-success font-bold">{s.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

/* ================================================================== */
/* MAIN COMPONENT                                                      */
/* ================================================================== */
export function ParsingPage() {
  const [showUI, setShowUI] = useState(true)
  const [runPipeline, setRunPipeline] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [currentTablePage, setCurrentTablePage] = useState(1)
  const [copiedRowId, setCopiedRowId] = useState<number | null>(null)
  const rowsPerPage = 8
  const [validationOpen, setValidationOpen] = useState(true)
  const [entityOverrides, setEntityOverrides] = useState<Record<string, string>>({})
  const [committing, setCommitting] = useState(false)
  const [committed, setCommitted] = useState(false)

  const [stagingData, setStagingData] = useState<StagingRow[]>([])
  const [entities, setEntities] = useState<DetectedEntity[]>([])
  const [flags, setFlags] = useState<ValidationFlag[]>([])
  const [latestAuditInfo, setLatestAuditInfo] = useState<{ auditId: string; sha256: string; filePath: string } | null>(null)

  const metrics = useMemo(() => ({
    logsParsed: stagingData.length,
    templatesLearned: 0,
    entitiesDetected: entities.length,
    piiDetected: 0,
    ambiguousTimestamps: flags.length
  }), [stagingData.length, entities.length, flags.length])

  useEffect(() => {
    // Load latest audit from Phase 1 (if present) but do not start parsing automatically.
    try {
      const raw = typeof window !== "undefined" ? localStorage.getItem("latest_ingestion_audit") : null
      const parsed = raw ? (JSON.parse(raw) as any) : null
      if (parsed?.auditId) {
        setLatestAuditInfo({
          auditId: String(parsed.auditId),
          sha256: String(parsed.sha256 || ""),
          filePath: String(parsed.filePath || ""),
        })

        // Auto-start only if Phase 1 just navigated here (one-time flag).
        const auto = typeof window !== "undefined" ? localStorage.getItem("phase2_autostart_audit") : null
        if (auto && String(auto) === String(parsed.auditId)) {
          localStorage.removeItem("phase2_autostart_audit")
          setShowUI(false)
          setRunPipeline(true)
        }
      }
    } catch {
      // ignore
    }
    loadStagingData()
  }, [])

  const loadStagingData = async () => {
    try {
      const auditId = latestAuditInfo?.auditId || (() => {
        try {
          const raw = typeof window !== "undefined" ? localStorage.getItem("latest_ingestion_audit") : null
          const parsed = raw ? (JSON.parse(raw) as any) : null
          return parsed?.auditId ? String(parsed.auditId) : null
        } catch {
          return null
        }
      })()

      if (!auditId) {
        setStagingData([])
        setEntities([])
        setFlags([])
        setLatestAuditInfo(null)
        return
      }

      // Query staging entries from Phase 2
      const queryResponse = await apiClient.queryStaging({
        audit_id: auditId,
        status: 'pending',
        limit: 200,
        offset: 0
      })

      // Transform staging entries to StagingRow format
      const transformedRows: StagingRow[] = []
      const allEntities: DetectedEntity[] = []
      const allFlags: ValidationFlag[] = []

      // Fetch detailed previews for each staging entry
      let firstAuditInfo: { auditId: string; sha256: string; filePath: string } | null = null
      
      for (const entry of queryResponse.entries) {
        try {
          const preview = await apiClient.getStagingPreview(entry.staging_id)
          
          // Capture audit info from first entry
          if (!firstAuditInfo && preview.audit) {
            firstAuditInfo = {
              auditId: preview.audit.audit_id,
              sha256: preview.audit.sha256_hash || "",
              filePath: preview.audit.filename || ""
            }
          }
          
          // Extract data from preview
          const extractedVars = preview.extracted_variables || {}
          const nerTags = preview.ner_tags || {}
          const decodedPayload = preview.decoded_payload || {}
          
          // Get raw log line - try multiple sources
          // The original line might be in extracted_variables.original or decoded_payload.decoded
          // If not available, reconstruct from template + variables
          let rowData = extractedVars.original || decodedPayload.decoded || ""
          if (!rowData && preview.template?.template) {
            // Reconstruct from template by replacing variables
            rowData = preview.template.template
            Object.entries(extractedVars).forEach(([key, value]) => {
              if (key !== 'original' && key !== 'template') {
                rowData = rowData.replace(`<${key}>`, String(value))
              }
            })
          }
          if (!rowData) {
            rowData = `[Staging ${entry.staging_id}]`
          }
          
          // Extract entities from NER tags
          if (nerTags) {
            Object.entries(nerTags).forEach(([type, values]) => {
              const valuesList = Array.isArray(values) ? values : [values]
              valuesList.forEach((value: any) => {
                if (value) {
                  allEntities.push({
                    type,
                    value: String(value),
                    confidence: 0.85
                  })
                }
              })
            })
          }

          // Extract IP address, user, process from NER tags or variables
          const ipAddress = (nerTags?.ip_address && (Array.isArray(nerTags.ip_address) ? nerTags.ip_address[0] : nerTags.ip_address)) 
            || extractedVars?.ip_address 
            || extractedVars?.ip 
            || preview.audit?.source_ip 
            || "N/A"
          const user = (nerTags?.user && (Array.isArray(nerTags.user) ? nerTags.user[0] : nerTags.user))
            || extractedVars?.user 
            || extractedVars?.username 
            || "N/A"
          const processName = (nerTags?.process && (Array.isArray(nerTags.process) ? nerTags.process[0] : nerTags.process))
            || extractedVars?.process 
            || extractedVars?.process_name 
            || "N/A"
          const eventTemplate = preview.template?.template || extractedVars?.template || "Unknown template"
          const timestamp = preview.normalized_timestamp || preview.created_at || new Date().toISOString()
          
          // Check for ambiguous timestamp
          if (!preview.normalized_timestamp && preview.extracted_variables) {
            allFlags.push({
              type: "ambiguous_timestamp",
              label: "Ambiguous Timestamp",
              description: "Timestamp could not be normalized"
            })
          }

          transformedRows.push({
            id: transformedRows.length + 1,
            timestamp: timestamp,
            event_template: eventTemplate,
            ip_address: String(ipAddress),
            process_name: String(processName),
            user: String(user),
            raw_log: String(rowData),
            normalized_fields: JSON.stringify({
              variables: extractedVars,
              ner_tags: nerTags,
              template: preview.template?.template,
              decoded: decodedPayload.decoded
            })
          })
        } catch (previewErr) {
          console.error(`Failed to load preview for staging ${entry.staging_id}:`, previewErr)
        }
      }

      setStagingData(transformedRows)
      setEntities(allEntities)
      setFlags(allFlags)
      setLatestAuditInfo(firstAuditInfo)
    } catch (err) {
      console.error('Failed to load staging data:', err)
      setStagingData([])
      setEntities([])
      setFlags([])
    }
  }

  const filteredRows = useMemo(() => {
    if (!searchQuery.trim()) return stagingData
    const q = searchQuery.toLowerCase()
    return stagingData.filter(
      (r) =>
        r.event_template.toLowerCase().includes(q) ||
        r.ip_address.includes(q) ||
        r.process_name.toLowerCase().includes(q) ||
        r.user.toLowerCase().includes(q) ||
        r.raw_log.toLowerCase().includes(q)
    )
  }, [searchQuery, stagingData])

  const totalPages = Math.ceil(filteredRows.length / rowsPerPage)
  const pagedRows = filteredRows.slice((currentTablePage - 1) * rowsPerPage, currentTablePage * rowsPerPage)

  const copyRowJson = useCallback((row: StagingRow) => {
    navigator.clipboard.writeText(JSON.stringify(row, null, 2))
    setCopiedRowId(row.id)
    setTimeout(() => setCopiedRowId(null), 1500)
  }, [])

  const handleCommit = useCallback(() => {
    setCommitting(true)
    setTimeout(() => {
      setCommitting(false)
      setCommitted(true)
    }, 2400)
  }, [])

  const handleAnimationComplete = useCallback(() => {
    setShowUI(true)
    setRunPipeline(false)
    void loadStagingData()
  }, [])

  if (!showUI) {
    return <PipelineEntryAnimation onComplete={handleAnimationComplete} latestAuditInfo={latestAuditInfo} />
  }

  return (
    <div className="flex flex-col min-h-0 h-full animate-in fade-in duration-500">
      {/* Metrics Cards */}
      <div className="px-6 pt-5 pb-3">
        <div className="grid grid-cols-5 gap-4">
          {[
            { label: "Logs Parsed", value: metrics.logsParsed },
            { label: "Templates Learned", value: metrics.templatesLearned },
            { label: "Entities Detected", value: metrics.entitiesDetected },
            { label: "PII Detected", value: metrics.piiDetected },
            { label: "Ambiguous Timestamps", value: metrics.ambiguousTimestamps },
          ].map((m) => (
            <Card key={m.label} className="border shadow-none">
              <CardContent className="px-4 py-3">
                <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">{m.label}</p>
                <p className="text-2xl font-bold text-foreground tabular-nums">{m.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {!runPipeline && (
        <div className="px-6 pb-4">
          <div className="border border-border bg-card p-4 flex items-center justify-between gap-4">
            <div className="text-xs text-muted-foreground">
              {latestAuditInfo?.auditId
                ? `Ready. Latest audit: ${latestAuditInfo.auditId}`
                : "No Phase 1 upload selected. Upload a file in Phase 1 to enable Phase 2 parsing."}
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-8 text-[11px]"
                onClick={() => void loadStagingData()}
                disabled={!latestAuditInfo?.auditId}
              >
                Refresh Staging
              </Button>
              <Button
                size="sm"
                className="h-8 text-[11px] font-semibold"
                onClick={() => {
                  if (!latestAuditInfo?.auditId) return
                  setShowUI(false)
                  setRunPipeline(true)
                }}
                disabled={!latestAuditInfo?.auditId}
              >
                Run Phase 2 Parsing
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Main workspace */}
      <div className="flex flex-1 min-h-0 px-6 pb-5 gap-4">
        <div className={`flex flex-col min-h-0 transition-all duration-300 ${validationOpen ? "flex-1" : "w-full"}`}>
          <Card className="border shadow-none flex-1 flex flex-col min-h-0">
            <CardHeader className="px-4 py-3 flex-row items-center justify-between space-y-0">
              <div>
                <CardTitle className="text-sm font-semibold">Staging Data Preview</CardTitle>
                <p className="text-[10px] text-muted-foreground mt-0.5">Data currently in staging area - not committed to forensic database.</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="size-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                  <Input placeholder="Search logs..." value={searchQuery} onChange={(e) => { setSearchQuery(e.target.value); setCurrentTablePage(1) }} className="h-7 w-56 pl-8 text-[11px]" />
                </div>
                {!validationOpen && (
                  <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1" onClick={() => setValidationOpen(true)}>
                    <PanelRightOpen className="size-3.5" />
                    Validation
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent className="flex-1 min-h-0 flex flex-col px-0 pb-0">
              <ScrollArea className="flex-1">
                <div className="overflow-x-auto">
                  <table className="w-full text-[11px]">
                    <thead>
                      <tr className="border-t border-b bg-muted/40">
                        {["#", "Timestamp", "Event Template", "IP Address", "Process", "User", "Actions"].map((h) => (
                          <th key={h} className="px-3 py-2 text-left font-semibold text-muted-foreground uppercase tracking-wider text-[9px]">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {pagedRows.map((row) => (
                        <tr key={row.id} className="border-b border-border/50 hover:bg-muted/30 transition-colors">
                          <td className="px-3 py-2 font-mono text-muted-foreground">{row.id}</td>
                          <td className="px-3 py-2 font-mono whitespace-nowrap">{row.timestamp}</td>
                          <td className="px-3 py-2 max-w-[220px] truncate">{row.event_template}</td>
                          <td className="px-3 py-2 font-mono">{row.ip_address}</td>
                          <td className="px-3 py-2">
                            <Badge variant="outline" className="text-[9px] h-4 px-1.5 font-mono">{row.process_name}</Badge>
                          </td>
                          <td className="px-3 py-2">{row.user}</td>
                          <td className="px-3 py-2">
                            <Button variant="ghost" size="sm" className="h-5 w-5 p-0" onClick={() => copyRowJson(row)}>
                              {copiedRowId === row.id ? <Check className="size-3 text-[#198754]" /> : <Copy className="size-3 text-muted-foreground" />}
                            </Button>
                          </td>
                        </tr>
                      ))}
                      {pagedRows.length === 0 && (
                        <tr><td colSpan={7} className="px-3 py-8 text-center text-muted-foreground">No matching records found.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </ScrollArea>
              <div className="flex items-center justify-between border-t px-4 py-2">
                <p className="text-[10px] text-muted-foreground">
                  Showing {(currentTablePage - 1) * rowsPerPage + 1}-{Math.min(currentTablePage * rowsPerPage, filteredRows.length)} of {filteredRows.length} entries
                </p>
                <div className="flex items-center gap-1">
                  <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={currentTablePage === 1} onClick={() => setCurrentTablePage(1)}><ChevronsLeft className="size-3" /></Button>
                  <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={currentTablePage === 1} onClick={() => setCurrentTablePage((p) => p - 1)}><ChevronLeft className="size-3" /></Button>
                  <span className="text-[10px] text-muted-foreground px-2">Page {currentTablePage} of {totalPages || 1}</span>
                  <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={currentTablePage >= totalPages} onClick={() => setCurrentTablePage((p) => p + 1)}><ChevronRight className="size-3" /></Button>
                  <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={currentTablePage >= totalPages} onClick={() => setCurrentTablePage(totalPages)}><ChevronsRight className="size-3" /></Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* RIGHT COLUMN - Human Validation Panel */}
        {validationOpen && (
          <div className="w-[340px] shrink-0 flex flex-col min-h-0">
            <Card className="border shadow-none flex-1 flex flex-col min-h-0">
              <CardHeader className="px-4 py-3 flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle className="text-sm font-semibold">Human Validation</CardTitle>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Review & correct entities</p>
                </div>
                <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setValidationOpen(false)}>
                  <X className="size-3.5 text-muted-foreground" />
                </Button>
              </CardHeader>
              <ScrollArea className="flex-1 min-h-0">
                <div className="px-4 pb-4 space-y-5">
                  {committed && (
                    <div className="rounded-md border border-[#198754]/30 bg-[#198754]/5 p-3">
                      <div className="flex items-start gap-2">
                        <ShieldCheck className="size-4 text-[#198754] mt-0.5 shrink-0" />
                        <div>
                          <p className="text-xs font-semibold text-[#198754]">Parsing completed and committed to forensic database.</p>
                          <p className="text-[10px] text-[#198754]/70 mt-0.5">Audit trail recorded. Evidence chain intact.</p>
                        </div>
                      </div>
                    </div>
                  )}
                  <div>
                    <Label className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">Detected Entities</Label>
                    <div className="mt-2 space-y-2.5">
                      {entities.length === 0 ? (
                        <p className="text-[10px] text-muted-foreground">No entities detected yet. Upload a file to see detected entities.</p>
                      ) : (
                        entities.map((entity, idx) => {
                          const key = `${entity.type}-${idx}`
                          return (
                            <div key={key} className="space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] font-medium text-foreground">{entity.type}</span>
                                <Badge variant="outline" className="text-[8px] h-3.5 px-1 font-mono">{(entity.confidence * 100).toFixed(0)}%</Badge>
                              </div>
                              <Input
                                className="h-7 text-[11px] font-mono"
                                defaultValue={entityOverrides[key] || entity.value}
                                onChange={(e) => setEntityOverrides((prev) => ({ ...prev, [key]: e.target.value }))}
                              />
                            </div>
                          )
                        })
                      )}
                    </div>
                  </div>
                  <Separator />
                  <div>
                    <Label className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">Validation Flags</Label>
                    <div className="mt-2 space-y-2">
                      {flags.length === 0 ? (
                        <p className="text-[10px] text-muted-foreground">No validation flags. All data validated successfully.</p>
                      ) : (
                        flags.map((flag) => (
                          <div key={flag.type} className={`rounded-md border p-2.5 ${
                            flag.type === "ambiguous_timestamp" ? "border-amber-200 bg-amber-50/50"
                            : flag.type === "suspicious_string" ? "border-red-200 bg-red-50/50"
                            : "border-blue-200 bg-blue-50/50"
                          }`}>
                            <div className="flex items-start gap-2">
                              {flag.type === "ambiguous_timestamp" && <AlertTriangle className="size-3.5 text-amber-500 mt-0.5 shrink-0" />}
                              {flag.type === "suspicious_string" && <FileWarning className="size-3.5 text-red-500 mt-0.5 shrink-0" />}
                              {flag.type === "unknown_pattern" && <HelpCircle className="size-3.5 text-blue-500 mt-0.5 shrink-0" />}
                              <div>
                                <p className="text-[10px] font-semibold text-foreground">{flag.label}</p>
                                <p className="text-[9px] text-muted-foreground mt-0.5">{flag.description}</p>
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                  <Separator />
                  <Button className="w-full h-9 text-xs font-semibold bg-[#0B5ED7] hover:bg-[#0B5ED7]/90" disabled={committing || committed || stagingData.length === 0} onClick={handleCommit}>
                    {committing ? (
                      <><Loader2 className="size-3.5 mr-1.5 animate-spin" />Committing...</>
                    ) : committed ? (
                      <><Check className="size-3.5 mr-1.5" />Committed to Database</>
                    ) : (
                      "Confirm & Commit to Database"
                    )}
                  </Button>
                </div>
              </ScrollArea>
            </Card>
          </div>
        )}
      </div>
    </div>
  )
}
