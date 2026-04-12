"use client"

import { useState, useCallback, useMemo, useRef, useEffect } from "react"
import {
  Search,
  Sparkles,
  Play,
  RotateCcw,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Download,
  ShieldAlert,
  Clock,
  Table2,
  Database,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Loader2,
  X,
  AlertTriangle,
  CheckCircle2,
  Pencil,
  Eye,
  Columns3,
  Terminal,
  Wand2,
  Info,
  FileText,
  Zap,
  History,
  Trash2,
  ChevronDown,
  ChevronUp,
  Hash,
  Activity,
  Shield,
} from "lucide-react"
import { useApp } from "@/lib/app-context"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { ScrollArea } from "@/components/ui/scroll-area"

/* ================================================================== */
/* TYPES                                                               */
/* ================================================================== */
type QueryDataSource = "live" | "live_empty" | "mock" | "mock_fallback"

interface QueryResult {
  columns: string[]
  rows: Record<string, string | number>[]
  executionTime: number
  totalRows: number
  tablesUsed: string[]
  dataSource?: QueryDataSource
  dataSourceDetail?: string
}

interface QueryHistoryEntry {
  id: number
  query: string
  sql: string
  rows: number
  time: number
  timestamp: string
}

type SortDir = "asc" | "desc" | null

/* ================================================================== */
/* SQL KEYWORDS                                                        */
/* ================================================================== */
const SQL_KEYWORDS = [
  "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "LIKE", "BETWEEN",
  "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET", "AS", "ON", "JOIN",
  "LEFT", "RIGHT", "INNER", "OUTER", "FULL", "CROSS", "UNION", "ALL",
  "DISTINCT", "COUNT", "SUM", "AVG", "MIN", "MAX", "NOW", "INTERVAL",
  "IS", "NULL", "TRUE", "FALSE", "CASE", "WHEN", "THEN", "ELSE", "END",
  "ASC", "DESC", "EXISTS", "CAST", "COALESCE", "EXTRACT", "DATE", "TIME",
  "TIMESTAMP", "WITH", "CURRENT_TIMESTAMP", "CURRENT_DATE",
]

const UNSAFE_KEYWORDS = ["DELETE", "UPDATE", "DROP", "INSERT", "ALTER", "TRUNCATE", "CREATE", "REPLACE", "EXEC", "EXECUTE"]

/* ================================================================== */
/* NER FIELDS FROM PHASE-2                                             */
/* ================================================================== */
const nerFields = [
  { name: "id", description: "Row ID (primary key)", type: "INTEGER" },
  { name: "timestamp", description: "ISO-8601 UTC timestamp", type: "TIMESTAMP" },
  { name: "event_template", description: "DRAIN3 event template", type: "TEXT" },
  { name: "ip_address", description: "IPv4 address", type: "TEXT" },
  { name: "process_name", description: "System process", type: "TEXT" },
  { name: "user", description: "System username", type: "TEXT" },
  { name: "severity", description: "INFO / WARN / ERROR", type: "TEXT" },
  { name: "facility", description: "Log facility", type: "TEXT" },
  { name: "raw_log", description: "Original log line", type: "TEXT" },
]

/* ================================================================== */
/* AVAILABLE TABLES                                                    */
/* ================================================================== */
const availableTables = [
  { name: "parsed_logs", description: "Phase-2 parsed & structured log entries" },
  { name: "raw_logs", description: "Phase-1 raw ingested log lines" },
  { name: "audit_trail", description: "System audit & access records" },
  { name: "evidence_store", description: "Hashed evidence artifacts" },
  { name: "alert_events", description: "Triggered alert & anomaly events" },
]

/* ================================================================== */
/* SQL FUNCTIONS (classified separately from keywords)                  */
/* ================================================================== */
const SQL_FUNCTIONS = [
  "COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE", "CAST", "EXTRACT",
  "UPPER", "LOWER", "TRIM", "LENGTH", "SUBSTRING", "CONCAT",
  "DATE_TRUNC", "DATE_PART",
]

/* ================================================================== */
/* SQL TOKEN                                                           */
/* ================================================================== */
interface SqlToken {
  id: number
  text: string
  type: "keyword" | "table" | "column" | "string" | "number" | "operator" | "punctuation" | "whitespace" | "function"
}

const TABLE_PRECEDING = new Set(["FROM", "JOIN", "INTO"])
const JOIN_MODIFIERS = new Set(["LEFT", "RIGHT", "INNER", "OUTER", "FULL", "CROSS", "AS", "ON", "AND", "OR", "NOT"])

function tokenizeSQL(sql: string): SqlToken[] {
  const tokens: SqlToken[] = []
  let id = 0
  const knownTables = new Set(availableTables.map((t) => t.name))
  const knownColumns = new Set(nerFields.map((f) => f.name))
  const kwSet = new Set(SQL_KEYWORDS.map((k) => k.toUpperCase()))
  const fnSet = new Set(SQL_FUNCTIONS.map((f) => f.toUpperCase()))
  const unsafeSet = new Set(UNSAFE_KEYWORDS.map((k) => k.toUpperCase()))

  const regex = /('(?:[^'\\]|\\.)*')|(\d+(?:\.\d+)?)|([a-zA-Z_]\w*)|(\s+)|(>=|<=|<>|!=|[=<>])|([+\-*/%(),;.])/g
  let match: RegExpExecArray | null
  let lastCtx = ""

  while ((match = regex.exec(sql)) !== null) {
    const [, str, num, word, ws, cmpOp, misc] = match

    if (str !== undefined) {
      tokens.push({ id: id++, text: str, type: "string" })
      lastCtx = ""
    } else if (num !== undefined) {
      tokens.push({ id: id++, text: num, type: "number" })
    } else if (word !== undefined) {
      const upper = word.toUpperCase()
      if (kwSet.has(upper) || unsafeSet.has(upper)) {
        tokens.push({ id: id++, text: upper, type: "keyword" })
        if (TABLE_PRECEDING.has(upper)) lastCtx = "TABLE_NEXT"
        else if (!JOIN_MODIFIERS.has(upper)) lastCtx = ""
      } else if (fnSet.has(upper)) {
        tokens.push({ id: id++, text: upper, type: "function" })
      } else if (lastCtx === "TABLE_NEXT" || knownTables.has(word.toLowerCase())) {
        tokens.push({ id: id++, text: word, type: "table" })
        lastCtx = ""
      } else if (knownColumns.has(word.toLowerCase())) {
        tokens.push({ id: id++, text: word, type: "column" })
      } else {
        tokens.push({ id: id++, text: word, type: "column" })
      }
    } else if (ws !== undefined) {
      tokens.push({ id: id++, text: ws, type: "whitespace" })
    } else if (cmpOp !== undefined) {
      tokens.push({ id: id++, text: cmpOp, type: "operator" })
      lastCtx = ""
    } else if (misc !== undefined) {
      tokens.push({ id: id++, text: misc, type: "punctuation" })
    }
  }

  return tokens
}

/* ================================================================== */
/* EXAMPLE QUERIES                                                     */
/* ================================================================== */
const exampleQueries = [
  { label: "Login events from specific IP", query: "Show all login events from IP 192.168.1.22 in the last 24 hours" },
  { label: "Failed auth by user", query: "Find all failed authentication attempts grouped by user" },
  { label: "Processes on unusual ports", query: "List processes that started on unusual ports after midnight" },
  { label: "Events by severity", query: "Count events per severity level for today" },
  { label: "All error & warning logs", query: "Show all logs with severity ERROR or WARN" },
  { label: "SSH activity", query: "Show all sshd process events ordered by timestamp" },
]

/* ================================================================== */
/* SQL SYNTAX HIGHLIGHTER                                              */
/* ================================================================== */
function highlightSQL(sql: string): string {
  let html = sql
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")

  html = html.replace(/'([^']*)'/g, '<span class="text-amber-500">\'$1\'</span>')
  html = html.replace(/\b(\d+)\b/g, '<span class="text-purple-400">$1</span>')

  const keywordPattern = new RegExp(`\\b(${SQL_KEYWORDS.join("|")})\\b`, "gi")
  html = html.replace(keywordPattern, '<span class="text-sky-400 font-bold">$1</span>')

  const unsafePattern = new RegExp(`\\b(${UNSAFE_KEYWORDS.join("|")})\\b`, "gi")
  html = html.replace(unsafePattern, '<span class="text-red-400 font-bold bg-red-950/50">$1</span>')

  html = html.replace(/(--.*$)/gm, '<span class="text-slate-500 italic">$1</span>')

  return html
}

/* ================================================================== */
/* SQL EDITOR COMPONENT                                                */
/* ================================================================== */
function SqlEditor({
  value,
  onChange,
  insertField,
  activeAuditId,
}: {
  value: string
  onChange: (val: string) => void
  insertField: string | null
  activeAuditId: string | null
}) {
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const highlightRef = useRef<HTMLDivElement>(null)
  const [lineCount, setLineCount] = useState(1)

  useEffect(() => {
    setLineCount(Math.max(value.split("\n").length, 1))
  }, [value])

  useEffect(() => {
    if (insertField && textareaRef.current) {
      const ta = textareaRef.current
      const start = ta.selectionStart
      const end = ta.selectionEnd
      const before = value.slice(0, start)
      const after = value.slice(end)
      onChange(before + insertField + after)
      setTimeout(() => {
        ta.focus()
        ta.selectionStart = ta.selectionEnd = start + insertField.length
      }, 10)
    }
  }, [insertField])

  const handleScroll = () => {
    if (textareaRef.current && highlightRef.current) {
      highlightRef.current.scrollTop = textareaRef.current.scrollTop
      highlightRef.current.scrollLeft = textareaRef.current.scrollLeft
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Tab") {
      e.preventDefault()
      const ta = textareaRef.current!
      const start = ta.selectionStart
      const end = ta.selectionEnd
      onChange(value.slice(0, start) + "  " + value.slice(end))
      setTimeout(() => {
        ta.selectionStart = ta.selectionEnd = start + 2
      }, 0)
    }
  }

  return (
    <div className="relative border border-border bg-[#0d1117] font-mono text-[13px] overflow-hidden">
      {/* Line numbers */}
      <div className="absolute left-0 top-0 bottom-0 w-11 bg-[#0d1117] border-r border-slate-800 z-10 select-none overflow-hidden">
        <div className="flex flex-col pt-3 px-1">
          {Array.from({ length: lineCount }, (_, i) => (
            <div key={i} className="text-right text-[11px] leading-[20px] text-slate-600 pr-2">
              {i + 1}
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-md border border-border bg-muted/20 px-3 py-2 text-[11px] text-muted-foreground">
          <span className="font-semibold text-foreground">Phases 1→4 pipeline: </span>
          {activeAuditId ? (
            <>
              Active audit <code className="text-[10px] bg-muted px-1 rounded">{activeAuditId.slice(0, 8)}…</code>
              — Magic Query loads committed rows from this audit after Phase 2 commit. Without an audit, the built-in demo
              dataset is used.
            </>
          ) : (
            <>
              Set an audit by completing Phase 1 ingestion (or open Parsing with a saved audit). Phase 4 then queries real{" "}
              <code className="text-[10px] bg-muted px-1 rounded">normalized_logs</code> via the backend.
            </>
          )}
        </div>
      </div>

{/* Syntax highlight layer */}
      <div
        ref={highlightRef}
        className="absolute inset-0 pl-14 pt-3 pr-4 pb-3 overflow-hidden whitespace-pre-wrap break-words text-[13px] leading-[20px] pointer-events-none text-slate-300"
        aria-hidden
        dangerouslySetInnerHTML={{ __html: highlightSQL(value) + "\n" }}
      />

      {/* Actual textarea */}
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onScroll={handleScroll}
        onKeyDown={handleKeyDown}
        spellCheck={false}
        className="relative w-full min-h-[180px] max-h-[360px] bg-transparent text-transparent caret-slate-300 pl-14 pt-3 pr-4 pb-3 resize-y font-mono text-[13px] leading-[20px] outline-none z-[1]"
        style={{ WebkitTextFillColor: "transparent" }}
      />
    </div>
  )
}

/* ================================================================== */
/* VISUAL SQL EDITOR — every name is an editable token                 */
/* ================================================================== */
function VisualSqlEditor({ sql, onSqlChange }: { sql: string; onSqlChange: (s: string) => void }) {
  const tokens = useMemo(() => tokenizeSQL(sql), [sql])
  const [editingId, setEditingId] = useState<number | null>(null)
  const [filterText, setFilterText] = useState("")
  const [highlightedIdx, setHighlightedIdx] = useState(0)
  const searchInputRef = useRef<HTMLInputElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)

  // Reset editing when SQL changes externally
  useEffect(() => {
    setEditingId(null)
    setFilterText("")
    setHighlightedIdx(0)
  }, [sql])

  // Close on Escape key globally
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && editingId !== null) {
        setEditingId(null)
        setFilterText("")
        setHighlightedIdx(0)
      }
    }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [editingId])

  // Auto-focus search input
  useEffect(() => {
    if (editingId !== null && searchInputRef.current) {
      setTimeout(() => {
        searchInputRef.current?.focus()
        searchInputRef.current?.select()
      }, 50)
    }
  }, [editingId])

  // Reset highlight when filter changes
  useEffect(() => {
    setHighlightedIdx(0)
  }, [filterText])

  const editingToken = editingId !== null ? tokens.find((t) => t.id === editingId) : null

  const applyChange = useCallback(
    (tokenId: number, newText: string) => {
      if (!newText.trim()) return
      const newSql = tokens.map((t) => (t.id === tokenId ? newText : t.text)).join("")
      setEditingId(null)
      setFilterText("")
      setHighlightedIdx(0)
      onSqlChange(newSql)
    },
    [tokens, onSqlChange],
  )

  const startEditing = useCallback((tokenId: number, currentText: string) => {
    setEditingId(tokenId)
    setFilterText("")
    setHighlightedIdx(0)
  }, [])

  const getDropdownItems = useCallback(
    (token: SqlToken) => {
      if (token.type === "table")
        return availableTables.filter((t) => !filterText || t.name.toLowerCase().includes(filterText.toLowerCase()))
      if (token.type === "column")
        return nerFields.filter((f) => !filterText || f.name.toLowerCase().includes(filterText.toLowerCase()))
      return []
    },
    [filterText],
  )

  const chipStyles: Record<string, { base: string; dot: string }> = {
    table: { base: "bg-purple-50 text-purple-700 border-purple-200 hover:bg-purple-100 hover:border-purple-300", dot: "bg-purple-500" },
    column: { base: "bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100 hover:border-emerald-300", dot: "bg-emerald-500" },
    string: { base: "bg-amber-50 text-amber-700 border-amber-200 hover:bg-amber-100 hover:border-amber-300", dot: "bg-amber-500" },
    number: { base: "bg-violet-50 text-violet-700 border-violet-200 hover:bg-violet-100 hover:border-violet-300", dot: "bg-violet-500" },
  }

  const dropdownItems = editingToken ? getDropdownItems(editingToken) : []
  const hasDropdown = editingToken ? (editingToken.type === "table" || editingToken.type === "column") : false

  return (
    <>
      {/* SQL Token Display */}
      <div className="border border-slate-200 bg-white rounded-lg p-4 min-h-[160px] max-h-[360px] overflow-auto">
        <div className="font-mono text-[13px] leading-[2.1]" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {tokens.map((token) => {
            if (token.type === "whitespace") return <span key={token.id}>{token.text}</span>
            if (token.type === "keyword") return <span key={token.id} className="text-blue-600 font-bold">{token.text}</span>
            if (token.type === "function") return <span key={token.id} className="text-cyan-600 font-semibold">{token.text}</span>
            if (token.type === "operator") return <span key={token.id} className="text-slate-500 font-medium">{token.text}</span>
            if (token.type === "punctuation") return <span key={token.id} className="text-slate-400">{token.text}</span>

            const isEditing = editingId === token.id
            const style = chipStyles[token.type] || chipStyles.column

            return (
              <span key={token.id} className="inline-flex items-center group/tok">
                <button
                  onClick={() => startEditing(token.id, token.text)}
                  className={`inline-flex items-center gap-1 px-1.5 py-[1px] rounded border text-[12px] transition-all cursor-pointer ${
                    isEditing
                      ? "ring-2 ring-[#0B5ED7] border-[#0B5ED7] bg-blue-50 text-[#0B5ED7]"
                      : style.base
                  }`}
                  title="Click to edit"
                >
                  <span className={`size-1.5 rounded-full ${style.dot} shrink-0`} />
                  {token.text}
                  <Pencil className="size-2.5 opacity-0 group-hover/tok:opacity-60 transition-opacity shrink-0 ml-0.5" />
                </button>
              </span>
            )
          })}
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 mt-3 pt-3 border-t border-slate-100">
          {[
            { color: "bg-purple-500", label: "Table" },
            { color: "bg-emerald-500", label: "Column" },
            { color: "bg-amber-500", label: "Value" },
            { color: "bg-violet-500", label: "Number" },
          ].map((l) => (
            <div key={l.label} className="flex items-center gap-1.5">
              <span className={`size-2 rounded-full ${l.color}`} />
              <span className="text-[9px] text-slate-500 font-medium">{l.label}</span>
            </div>
          ))}
          <span className="text-[9px] text-slate-400 ml-auto">Click any token to edit · Esc to close</span>
        </div>
      </div>

      {/* ══════════ FULLSCREEN OVERLAY PANEL ══════════ */}
      {editingId !== null && editingToken && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4" onClick={() => { setEditingId(null); setFilterText(""); setHighlightedIdx(0) }}>
          {/* Backdrop */}
          <div className="absolute inset-0 bg-black/20 backdrop-blur-[2px]" />

          {/* Panel */}
          <div
            ref={panelRef}
            onClick={(e) => e.stopPropagation()}
            className="relative w-full max-w-md bg-white rounded-xl border border-slate-200 shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
          >
            {/* Panel Header */}
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-100 bg-slate-50/80">
              <div className="flex items-center gap-2.5">
                <div className={`flex size-8 items-center justify-center rounded-lg ${
                  editingToken.type === "table" ? "bg-purple-100 text-purple-600" : editingToken.type === "column" ? "bg-emerald-100 text-emerald-600" : editingToken.type === "string" ? "bg-amber-100 text-amber-600" : "bg-violet-100 text-violet-600"
                }`}>
                  {editingToken.type === "table" ? (
                    <Database className="size-4" />
                  ) : editingToken.type === "column" ? (
                    <Columns3 className="size-4" />
                  ) : editingToken.type === "string" ? (
                    <FileText className="size-4" />
                  ) : (
                    <Hash className="size-4" />
                  )}
                </div>
                <div>
                  <h3 className="text-[13px] font-semibold text-slate-800">
                    Edit {editingToken.type === "table" ? "Table" : editingToken.type === "column" ? "Column" : editingToken.type === "string" ? "Value" : "Number"}
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Current: <code className="font-mono text-[11px] text-[#0B5ED7] bg-blue-50 px-1 py-px rounded">{editingToken.text}</code>
                  </p>
                </div>
              </div>
              <button
                onClick={() => { setEditingId(null); setFilterText(""); setHighlightedIdx(0) }}
                className="flex size-7 items-center justify-center rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors"
              >
                <X className="size-3.5" />
              </button>
            </div>

            {/* Search / Manual Input */}
            <div className="px-4 py-3 bg-white">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <Search className="size-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    ref={searchInputRef}
                    value={filterText}
                    onChange={(e) => setFilterText(e.target.value)}
                    placeholder={hasDropdown ? "Search or type custom name..." : "Type new value..."}
                    className="w-full h-9 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-800 pl-9 pr-3 font-mono placeholder:text-slate-400 focus:outline-none focus:border-[#0B5ED7]/40 focus:ring-2 focus:ring-[#0B5ED7]/10 transition-all"
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        if (hasDropdown && dropdownItems.length > 0 && !filterText) {
                          applyChange(editingToken.id, dropdownItems[highlightedIdx].name)
                        } else if (hasDropdown && dropdownItems.length > 0 && highlightedIdx < dropdownItems.length) {
                          applyChange(editingToken.id, dropdownItems[highlightedIdx].name)
                        } else if (filterText.trim()) {
                          applyChange(editingToken.id, filterText)
                        }
                      }
                      if (e.key === "ArrowDown" && hasDropdown) {
                        e.preventDefault()
                        setHighlightedIdx((i) => Math.min(i + 1, dropdownItems.length - 1))
                      }
                      if (e.key === "ArrowUp" && hasDropdown) {
                        e.preventDefault()
                        setHighlightedIdx((i) => Math.max(i - 1, 0))
                      }
                      if (e.key === "Escape") {
                        setEditingId(null)
                        setFilterText("")
                        setHighlightedIdx(0)
                      }
                    }}
                  />
                </div>
                {(!hasDropdown || filterText.trim()) && (
                  <Button
                    onClick={() => {
                      if (filterText.trim()) applyChange(editingToken.id, filterText)
                    }}
                    className="h-9 px-4 bg-[#198754] hover:bg-[#157347] text-white text-xs font-semibold gap-1.5 rounded-lg shrink-0"
                    disabled={!filterText.trim()}
                  >
                    <Check className="size-3.5" />
                    Apply
                  </Button>
                )}
              </div>
            </div>

            {/* Options List */}
            {hasDropdown && (
              <div className="max-h-[42vh] overflow-y-auto border-t border-slate-100">
                {dropdownItems.length > 0 ? (
                  <div className="py-1">
                    {dropdownItems.map((opt, idx) => {
                      const isCurrent = opt.name === editingToken.text
                      const isHighlighted = idx === highlightedIdx
                      return (
                        <button
                          key={opt.name}
                          onClick={() => applyChange(editingToken.id, opt.name)}
                          onMouseEnter={() => setHighlightedIdx(idx)}
                          className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                            isHighlighted
                              ? "bg-[#0B5ED7]/6"
                              : "hover:bg-slate-50"
                          }`}
                        >
                          <div className={`flex size-8 items-center justify-center rounded-lg shrink-0 ${
                            editingToken.type === "table"
                              ? isHighlighted ? "bg-purple-100 text-purple-600" : "bg-slate-100 text-slate-400"
                              : isHighlighted ? "bg-emerald-100 text-emerald-600" : "bg-slate-100 text-slate-400"
                          }`}>
                            {editingToken.type === "table" ? (
                              <Database className="size-4" />
                            ) : (
                              <Columns3 className="size-4" />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className={`text-sm font-mono font-medium ${
                                isHighlighted ? "text-[#0B5ED7]" : "text-slate-700"
                              }`}>
                                {opt.name}
                              </span>
                              {isCurrent && (
                                <span className="inline-flex items-center gap-0.5 text-[10px] font-medium text-[#198754] bg-green-50 border border-green-200 px-1.5 py-px rounded-full">
                                  <Check className="size-2.5" />
                                  current
                                </span>
                              )}
                              {"type" in opt && (
                                <span className="text-[10px] font-mono text-slate-400 ml-auto">{(opt as any).type}</span>
                              )}
                            </div>
                            <p className="text-[11px] text-slate-400 mt-0.5 truncate">{opt.description}</p>
                          </div>
                          {isHighlighted && (
                            <Check className="size-4 text-[#0B5ED7] shrink-0" />
                          )}
                        </button>
                      )
                    })}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-8 text-center">
                    <Search className="size-6 text-slate-300 mb-2" />
                    <p className="text-sm text-slate-500 font-medium">No matches</p>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Press <kbd className="px-1.5 py-0.5 bg-slate-100 border border-slate-200 text-[10px] font-mono rounded">Enter</kbd> to use &quot;{filterText}&quot;
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Panel Footer */}
            <div className="flex items-center justify-between px-4 py-2.5 border-t border-slate-100 bg-slate-50/60">
              <span className="text-[10px] text-slate-400 flex items-center gap-1.5">
                {hasDropdown ? (
                  <>
                    <kbd className="px-1 py-0.5 bg-white border border-slate-200 text-[9px] font-mono rounded">↑↓</kbd>
                    <span>navigate</span>
                    <kbd className="px-1 py-0.5 bg-white border border-slate-200 text-[9px] font-mono rounded ml-1">↵</kbd>
                    <span>select</span>
                  </>
                ) : (
                  "Press Enter to apply"
                )}
              </span>
              <button
                onClick={() => { setEditingId(null); setFilterText(""); setHighlightedIdx(0) }}
                className="text-[11px] text-slate-400 hover:text-slate-600 font-medium transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

/* ================================================================== */
/* SQL VALIDATION                                                      */
/* ================================================================== */
function validateSQL(sql: string): { valid: boolean; error?: string } {
  const trimmed = sql.trim()
  if (!trimmed) return { valid: false, error: "SQL query is empty." }

  const upper = trimmed.toUpperCase()

  for (const kw of UNSAFE_KEYWORDS) {
    if (new RegExp(`\\b${kw}\\b`, "i").test(upper)) {
      return {
        valid: false,
        error: `Only read-only queries are allowed in Magic Query mode. Detected unsafe keyword: ${kw}`,
      }
    }
  }

  if (!upper.startsWith("SELECT") && !upper.startsWith("WITH")) {
    return { valid: false, error: "Query must start with SELECT or WITH statement." }
  }

  return { valid: true }
}

/* ================================================================== */
/* MAIN COMPONENT                                                      */
/* ================================================================== */
export function Phase4Page() {
  const { activeAuditId } = useApp()

  // Query input
  const [naturalQuery, setNaturalQuery] = useState("")
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState<string | null>(null)
  const [usedFallback, setUsedFallback] = useState(false)
  const [fallbackReason, setFallbackReason] = useState<string | null>(null)

  // SQL editor
  const [sql, setSql] = useState("")
  const [insertField, setInsertField] = useState<string | null>(null)

  // Execution
  const [showConfirmation, setShowConfirmation] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [result, setResult] = useState<QueryResult | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [execError, setExecError] = useState<string | null>(null)

  // Results table
  const [resultSearch, setResultSearch] = useState("")
  const [resultPage, setResultPage] = useState(1)
  const [sortCol, setSortCol] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>(null)
  const [copiedCell, setCopiedCell] = useState<string | null>(null)
  const resultRowsPerPage = 10

  // History
  const [history, setHistory] = useState<QueryHistoryEntry[]>([])
  const [showHistory, setShowHistory] = useState(false)
  const historyIdRef = useRef(0)

  // Schema explorer
  const [schemaOpen, setSchemaOpen] = useState(true)

  // Editor mode
  const [editorMode, setEditorMode] = useState<"visual" | "code">("visual")

  // Stats
  const totalQueries = history.length
  const avgExecTime = history.length > 0 ? Math.round(history.reduce((s, h) => s + h.time, 0) / history.length * 10) / 10 : 0

  /* ── Generate SQL via API ── */
  const handleGenerateSQL = useCallback(async () => {
    if (!naturalQuery.trim()) return
    setGenerating(true)
    setGenerateError(null)
    setValidationError(null)
    setExecError(null)
    setResult(null)
    setShowConfirmation(false)
    setUsedFallback(false)
    setFallbackReason(null)

    try {
      const res = await fetch("/api/magic-query/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: naturalQuery.trim() }),
      })
      const data = await res.json()

      if (!res.ok) {
        setGenerateError(data.error || "Failed to generate SQL")
        setGenerating(false)
        return
      }

      setSql(data.sql || "")
      if (data.fallback) {
        setUsedFallback(true)
        setFallbackReason(data.fallbackReason || "Using local SQL generator.")
      }
      setGenerating(false)
    } catch (err: any) {
      setGenerateError(err.message || "Network error")
      setGenerating(false)
    }
  }, [naturalQuery])

  /* ── Insert NER field ── */
  const handleInsertField = useCallback((fieldName: string) => {
    setInsertField(fieldName)
    setTimeout(() => setInsertField(null), 50)
  }, [])

  /* ── Pre-run validation ── */
  const handleRunClick = useCallback(() => {
    const validation = validateSQL(sql)
    if (!validation.valid) {
      setValidationError(validation.error || "Invalid SQL")
      return
    }
    setValidationError(null)
    setShowConfirmation(true)
  }, [sql])

  /* ── Execute query via API ── */
  const handleExecute = useCallback(async () => {
    setShowConfirmation(false)
    setExecuting(true)
    setExecError(null)
    setResultPage(1)
    setSortCol(null)
    setSortDir(null)
    setResultSearch("")

    try {
      const res = await fetch("/api/magic-query/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sql: sql.trim(), audit_id: activeAuditId || undefined }),
      })
      const data = await res.json()

      if (!res.ok) {
        setExecError(data.error || "Query execution failed")
        setExecuting(false)
        return
      }

      const queryResult: QueryResult = {
        columns: data.columns,
        rows: data.rows,
        executionTime: data.executionTime,
        totalRows: data.totalRows,
        tablesUsed: data.tablesUsed,
        dataSource: data.dataSource,
        dataSourceDetail: data.dataSourceDetail,
      }
      setResult(queryResult)
      setExecuting(false)

      // Add to history
      historyIdRef.current++
      setHistory((prev) => [
        {
          id: historyIdRef.current,
          query: naturalQuery || "(manual SQL)",
          sql: sql.trim(),
          rows: queryResult.totalRows,
          time: queryResult.executionTime,
          timestamp: new Date().toLocaleTimeString("en-GB", { hour12: false }),
        },
        ...prev,
      ].slice(0, 20))
    } catch (err: any) {
      setExecError(err.message || "Network error")
      setExecuting(false)
    }
  }, [sql, naturalQuery, activeAuditId])

  /* ── Reset ── */
  const handleReset = useCallback(() => {
    setSql("")
    setNaturalQuery("")
    setResult(null)
    setValidationError(null)
    setGenerateError(null)
    setExecError(null)
    setShowConfirmation(false)
    setExecuting(false)
    setResultSearch("")
    setResultPage(1)
    setSortCol(null)
    setSortDir(null)
    setUsedFallback(false)
    setFallbackReason(null)
    setEditorMode("visual")
  }, [])

  /* ── Sort / filter / paginate results ── */
  const processedRows = useMemo(() => {
    if (!result) return []
    let rows = [...result.rows]

    if (resultSearch.trim()) {
      const q = resultSearch.toLowerCase()
      rows = rows.filter((r) =>
        Object.values(r).some((v) => String(v).toLowerCase().includes(q))
      )
    }

    if (sortCol && sortDir) {
      rows.sort((a, b) => {
        const aVal = a[sortCol] ?? ""
        const bVal = b[sortCol] ?? ""
        const cmp = String(aVal).localeCompare(String(bVal), undefined, { numeric: true })
        return sortDir === "asc" ? cmp : -cmp
      })
    }

    return rows
  }, [result, resultSearch, sortCol, sortDir])

  const totalResultPages = Math.ceil(processedRows.length / resultRowsPerPage)
  const pagedResultRows = processedRows.slice(
    (resultPage - 1) * resultRowsPerPage,
    resultPage * resultRowsPerPage
  )

  const handleSort = (col: string) => {
    if (sortCol === col) {
      if (sortDir === "asc") setSortDir("desc")
      else if (sortDir === "desc") { setSortCol(null); setSortDir(null) }
    } else {
      setSortCol(col)
      setSortDir("asc")
    }
    setResultPage(1)
  }

  /* ── Export CSV ── */
  const exportCSV = useCallback(() => {
    if (!result) return
    const header = result.columns.join(",")
    const rows = processedRows.map((r) =>
      result.columns.map((c) => `"${String(r[c] ?? "").replace(/"/g, '""')}"`).join(",")
    )
    const csv = [header, ...rows].join("\n")
    const blob = new Blob([csv], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `nflip-query-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [result, processedRows])

  const copyCell = (val: string, key: string) => {
    navigator.clipboard.writeText(val)
    setCopiedCell(key)
    setTimeout(() => setCopiedCell(null), 1200)
  }

  const loadFromHistory = (entry: QueryHistoryEntry) => {
    setNaturalQuery(entry.query)
    setSql(entry.sql)
    setResult(null)
    setShowHistory(false)
  }

  return (
    <div className="flex flex-col min-h-0 h-full animate-in fade-in duration-300">
      {/* ══════════════ PAGE HEADER ══════════════ */}
      <div className="px-6 pt-5 pb-3 border-b border-border bg-card shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex size-10 items-center justify-center bg-primary/10">
              <Wand2 className="size-5 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-foreground flex items-center gap-2">
                Magic Query
                <span className="text-muted-foreground font-normal text-sm">— Natural Language Log Investigation</span>
              </h1>
              <p className="text-xs text-muted-foreground mt-0.5">
                Ask questions about forensic logs in natural language. The system converts your request into SQL using Gemini AI and runs it against the parsed logs database.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="h-8 text-[11px] gap-1.5"
              onClick={() => setShowHistory(!showHistory)}
            >
              <History className="size-3.5" />
              History ({history.length})
            </Button>
          </div>
        </div>

        {/* Quick stats */}
        <div className="mt-3 grid grid-cols-4 gap-3">
          {[
            {
              icon: Database,
              label: "Database",
              value: "parsed_logs",
              sub: activeAuditId ? "Phase 4 API → DuckDB" : "demo or live",
            },
            {
              icon: Hash,
              label: "Records",
              value: result != null ? String(result.totalRows) : "—",
              sub:
                result?.dataSource === "live"
                  ? "committed Phase 2 rows"
                  : result?.dataSource === "live_empty"
                    ? "none for this audit"
                    : activeAuditId
                      ? "run query (uses audit)"
                      : "no audit — demo set",
            },
            { icon: Activity, label: "Queries Run", value: String(totalQueries), sub: avgExecTime > 0 ? `avg ${avgExecTime}ms` : "none yet" },
            { icon: Shield, label: "Mode", value: "READ-ONLY", sub: "SELECT only" },
          ].map((s) => (
            <div key={s.label} className="flex items-center gap-2.5 border border-border bg-card p-2.5">
              <s.icon className="size-4 text-muted-foreground shrink-0" />
              <div>
                <div className="flex items-baseline gap-1.5">
                  <p className="text-xs font-bold text-foreground">{s.value}</p>
                  <p className="text-[9px] text-muted-foreground">{s.sub}</p>
                </div>
                <p className="text-[9px] font-semibold tracking-wider text-muted-foreground uppercase">{s.label}</p>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-md border border-border bg-muted/20 px-3 py-2 text-[11px] text-muted-foreground">
          <span className="font-semibold text-foreground">Phases 1→4 pipeline: </span>
          {activeAuditId ? (
            <>
              Active audit <code className="text-[10px] bg-muted px-1 rounded">{activeAuditId.slice(0, 8)}…</code>
              — Magic Query loads committed rows from this audit after Phase 2 commit. Without an audit, the built-in demo
              dataset is used.
            </>
          ) : (
            <>
              Set an audit by completing Phase 1 ingestion (or open Parsing with a saved audit). Phase 4 then queries real{" "}
              <code className="text-[10px] bg-muted px-1 rounded">normalized_logs</code> via the backend.
            </>
          )}
        </div>
      </div>

      {/* ══════════════ MAIN CONTENT ══════════════ */}
      <div className="flex flex-1 min-h-0">
        <ScrollArea className="flex-1">
          <div className="px-6 py-4 space-y-4">
            <div className="grid grid-cols-[1fr_280px] gap-4">
              {/* ── LEFT COLUMN ── */}
              <div className="space-y-4">
                {/* SECTION 1 — Natural Language Input */}
                <Card className="border shadow-none">
                  <CardHeader className="px-5 py-3.5 space-y-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <Sparkles className="size-4 text-primary" />
                        <CardTitle className="text-sm font-semibold">Investigation Query</CardTitle>
                      </div>
                      <Badge className="bg-primary/10 text-primary border border-primary/20 hover:bg-primary/10 text-[10px] gap-1 px-2.5">
                        <Zap className="size-2.5" />
                        Gemini AI
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="px-5 pb-5 space-y-3">
                    <div>
                      <Label className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase">
                        Ask in Natural Language
                      </Label>
                      <textarea
                        value={naturalQuery}
                        onChange={(e) => setNaturalQuery(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                            e.preventDefault()
                            handleGenerateSQL()
                          }
                        }}
                        placeholder="Show all login events from IP 192.168.1.22 in the last 24 hours"
                        rows={3}
                        className="mt-1.5 w-full resize-none border border-border bg-background px-3 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/50 transition-all"
                      />
                      <p className="text-[10px] text-muted-foreground mt-1">
                        Press <kbd className="px-1 py-0.5 bg-muted border border-border text-[9px] font-mono">Ctrl+Enter</kbd> to generate
                      </p>
                    </div>

                    {/* Example queries */}
                    <div>
                      <span className="text-[10px] font-semibold tracking-wider text-muted-foreground uppercase block mb-2">
                        Quick Examples
                      </span>
                      <div className="grid grid-cols-3 gap-1.5">
                        {exampleQueries.map((eq) => (
                          <button
                            key={eq.label}
                            onClick={() => setNaturalQuery(eq.query)}
                            className="text-left text-[10px] px-2.5 py-2 bg-muted/30 border border-border hover:bg-primary/5 hover:border-primary/20 hover:text-primary text-muted-foreground transition-all group"
                          >
                            <span className="font-semibold text-foreground group-hover:text-primary block">{eq.label}</span>
                            <span className="truncate block mt-0.5 opacity-60">{eq.query}</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    <Separator />

                    {/* Generate button */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                        <Info className="size-3 shrink-0" />
                        Gemini API key is configured via environment variable
                      </div>
                      <Button
                        onClick={handleGenerateSQL}
                        disabled={generating || !naturalQuery.trim()}
                        className="h-9 px-6 text-xs font-bold bg-[#0B5ED7] hover:bg-[#0B5ED7]/90 gap-2 shadow-sm hover:shadow-md transition-all hover:scale-[1.01] active:scale-[0.99]"
                      >
                        {generating ? (
                          <>
                            <Loader2 className="size-3.5 animate-spin" />
                            Generating SQL...
                          </>
                        ) : (
                          <>
                            <Sparkles className="size-3.5" />
                            Generate SQL
                          </>
                        )}
                      </Button>
                    </div>

                    {/* Generate error */}
                    {generateError && (
                      <div className="flex items-start gap-2.5 border border-red-200 bg-red-50/60 p-3">
                        <AlertTriangle className="size-4 text-red-600 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-xs font-semibold text-red-700">Generation Failed</p>
                          <p className="text-[11px] text-red-600 mt-0.5">{generateError}</p>
                        </div>
                      </div>
                    )}

                    {/* Fallback notice */}
                    {usedFallback && sql && (
                      <div className="flex items-start gap-2.5 border border-amber-200 bg-amber-50/40 p-3">
                        <Info className="size-4 text-amber-600 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-xs font-semibold text-amber-700">Fallback SQL Generator Active</p>
                          <p className="text-[11px] text-amber-600 mt-0.5">
                            {fallbackReason || "SQL was generated using built-in intelligent pattern matching."}
                            {" "}You can edit the SQL below before running.
                          </p>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* SECTION 2 — SQL Editor */}
                <Card className="border shadow-none">
                  <CardHeader className="px-5 py-3.5 space-y-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <Terminal className="size-4 text-primary" />
                        <CardTitle className="text-sm font-semibold">Generated SQL</CardTitle>
                        {sql && (
                          <Badge variant="outline" className="text-[9px] h-4 px-1.5 font-mono text-muted-foreground">
                            {sql.split("\n").length} lines
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {sql && (
                          <>
                            <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1" onClick={handleReset}>
                              <RotateCcw className="size-3" />
                              Reset
                            </Button>
                            <Button
                              size="sm"
                              className="h-7 text-[11px] gap-1.5 bg-[#198754] hover:bg-[#198754]/90 font-semibold shadow-sm hover:shadow-md transition-all"
                              onClick={handleRunClick}
                              disabled={executing}
                            >
                              {executing ? (
                                <Loader2 className="size-3 animate-spin" />
                              ) : (
                                <Play className="size-3" />
                              )}
                              Run Query
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="px-5 pb-5 space-y-3">
                    {/* ── Visual / Code Mode Toggle ── */}
                    {sql && (
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-0.5 bg-muted/20 border border-border p-0.5">
                          <button
                            onClick={() => setEditorMode("visual")}
                            className={`flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-semibold transition-all ${
                              editorMode === "visual"
                                ? "bg-primary text-white shadow-sm"
                                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                            }`}
                          >
                            <Eye className="size-3" />
                            Visual Editor
                          </button>
                          <button
                            onClick={() => setEditorMode("code")}
                            className={`flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-semibold transition-all ${
                              editorMode === "code"
                                ? "bg-primary text-white shadow-sm"
                                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                            }`}
                          >
                            <Terminal className="size-3" />
                            Code Editor
                          </button>
                        </div>
                        <span className="text-[9px] text-muted-foreground">
                          {editorMode === "visual"
                            ? "Click any name to edit with dropdown · ✓ to confirm"
                            : "Edit SQL directly with syntax highlighting"}
                        </span>
                      </div>
                    )}

                    {!sql ? (
                      <div className="flex flex-col items-center justify-center py-14 text-center border border-dashed border-border bg-muted/10">
                        <Terminal className="size-10 text-muted-foreground/20 mb-3" />
                        <p className="text-sm font-medium text-muted-foreground">No SQL generated yet</p>
                        <p className="text-[11px] text-muted-foreground/50 mt-1 max-w-md">
                          Type a natural language query above and click Generate SQL, or write SQL directly
                        </p>
                        <Button
                          variant="outline"
                          size="sm"
                          className="mt-4 h-7 text-[11px] gap-1.5"
                          onClick={() => setSql("SELECT *\nFROM parsed_logs\nORDER BY timestamp DESC\nLIMIT 20;")}
                        >
                          <Pencil className="size-3" />
                          Write SQL Manually
                        </Button>
                      </div>
                    ) : editorMode === "visual" ? (
                      <VisualSqlEditor sql={sql} onSqlChange={setSql} />
                    ) : (
                      <>
                        <SqlEditor
                          value={sql}
                          onChange={setSql}
                          insertField={insertField}
                          activeAuditId={activeAuditId}
                        />
                        <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                          <Info className="size-3 shrink-0" />
                          <span>Edit SQL freely. Tab inserts 2 spaces. Use the schema panel on the right to insert columns.</span>
                        </div>
                      </>
                    )}

                    {/* Validation Error */}
                    {validationError && (
                      <div className="flex items-start gap-2.5 border-2 border-red-300 bg-red-50/80 p-3.5">
                        <ShieldAlert className="size-4 text-red-600 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-xs font-bold text-red-700">Query Blocked — Security Violation</p>
                          <p className="text-[11px] text-red-600 mt-0.5">{validationError}</p>
                        </div>
                      </div>
                    )}

                    {/* Exec Error */}
                    {execError && (
                      <div className="flex items-start gap-2.5 border border-red-200 bg-red-50/60 p-3">
                        <AlertTriangle className="size-4 text-red-600 shrink-0 mt-0.5" />
                        <div>
                          <p className="text-xs font-semibold text-red-700">Execution Error</p>
                          <p className="text-[11px] text-red-600 mt-0.5">{execError}</p>
                        </div>
                      </div>
                    )}

                    {/* SECTION 7 — Confirmation */}
                    {showConfirmation && (
                      <div className="border-2 border-[#0B5ED7]/30 bg-[#0B5ED7]/[0.03] p-5">
                        <div className="flex items-start gap-4">
                          <div className="flex size-10 items-center justify-center bg-[#0B5ED7]/10 shrink-0">
                            <Eye className="size-5 text-[#0B5ED7]" />
                          </div>
                          <div className="flex-1">
                            <p className="text-sm font-bold text-foreground">Review the generated SQL before execution</p>
                            <p className="text-[11px] text-muted-foreground mt-1">
                              This query will be executed against the <strong>parsed_logs</strong> table in the forensic database (DuckDB). Ensure the query is correct and returns the data you need.
                            </p>
                            <div className="mt-3 border border-border bg-[#0d1117] p-3 font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-32 overflow-y-auto">
                              {sql}
                            </div>
                            <div className="flex items-center gap-2 mt-4">
                              <Button
                                size="sm"
                                className="h-9 text-xs gap-2 bg-[#198754] hover:bg-[#198754]/90 font-bold px-5 shadow-sm hover:shadow-md transition-all"
                                onClick={handleExecute}
                              >
                                <CheckCircle2 className="size-3.5" />
                                Confirm & Run Query
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                className="h-9 text-xs gap-1.5"
                                onClick={() => setShowConfirmation(false)}
                              >
                                <Pencil className="size-3.5" />
                                Edit SQL
                              </Button>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Execution loader */}
                {executing && (
                  <Card className="border shadow-none border-primary/20">
                    <CardContent className="px-5 py-10 flex flex-col items-center gap-3">
                      <div className="relative">
                        <div className="absolute inset-0 flex items-center justify-center">
                          <div className="size-12 border-2 border-primary/20 animate-ping opacity-30" />
                        </div>
                        <Loader2 className="size-8 text-primary animate-spin relative" />
                      </div>
                      <p className="text-sm font-semibold text-foreground mt-2">Executing query against parsed_logs...</p>
                      <p className="text-[11px] text-muted-foreground">Running read-only SELECT on DuckDB</p>
                    </CardContent>
                  </Card>
                )}

                {/* SECTION 6 — Query Results */}
                {result && !executing && (
                  <>
                    {/* Query Metadata */}
                    <div className="grid grid-cols-3 gap-3">
                      {[
                        { icon: Clock, label: "Execution Time", value: `${result.executionTime}ms`, color: "text-primary", bg: "bg-primary/5 border-primary/15" },
                        { icon: Table2, label: "Rows Returned", value: String(result.totalRows), color: "text-[#198754]", bg: "bg-[#198754]/5 border-[#198754]/15" },
                        { icon: Database, label: "Tables Used", value: result.tablesUsed.join(", "), color: "text-foreground", bg: "bg-muted/30 border-border" },
                      ].map((m) => (
                        <div key={m.label} className={`flex items-center gap-3 border p-3.5 ${m.bg}`}>
                          <div className="flex size-9 items-center justify-center bg-card border border-border shrink-0">
                            <m.icon className="size-4 text-muted-foreground" />
                          </div>
                          <div>
                            <p className="text-[9px] font-semibold tracking-wider text-muted-foreground uppercase">{m.label}</p>
                            <p className={`text-sm font-bold ${m.color} font-mono`}>{m.value}</p>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Results Table */}
                    <Card className="border shadow-none">
                      <CardHeader className="px-5 py-3.5 space-y-0">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2.5">
                            <FileText className="size-4 text-[#198754]" />
                            <CardTitle className="text-sm font-semibold">Query Results</CardTitle>
                            <Badge className="bg-[#198754]/10 text-[#198754] border border-[#198754]/20 hover:bg-[#198754]/10 text-[9px] h-4 px-1.5 font-mono">
                              {processedRows.length} rows x {result.columns.length} cols
                            </Badge>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="relative">
                              <Search className="size-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                              <Input
                                placeholder="Filter results..."
                                value={resultSearch}
                                onChange={(e) => { setResultSearch(e.target.value); setResultPage(1) }}
                                className="h-7 w-52 pl-8 text-[11px]"
                              />
                            </div>
                            <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1.5" onClick={exportCSV}>
                              <Download className="size-3" />
                              Export CSV
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent className="px-0 pb-0">
                        <div className="overflow-x-auto">
                          <table className="w-full text-[11px]">
                            <thead>
                              <tr className="border-t border-b bg-muted/40">
                                {result.columns.map((col) => (
                                  <th
                                    key={col}
                                    className="px-3 py-2.5 text-left font-bold text-muted-foreground uppercase tracking-wider text-[9px] cursor-pointer hover:text-foreground hover:bg-muted/60 transition-colors select-none"
                                    onClick={() => handleSort(col)}
                                  >
                                    <div className="flex items-center gap-1.5">
                                      {col}
                                      {sortCol === col ? (
                                        sortDir === "asc" ? <ArrowUp className="size-2.5 text-primary" /> : <ArrowDown className="size-2.5 text-primary" />
                                      ) : (
                                        <ArrowUpDown className="size-2.5 text-muted-foreground/30" />
                                      )}
                                    </div>
                                  </th>
                                ))}
                              </tr>
                            </thead>
                            <tbody>
                              {pagedResultRows.map((row, ri) => (
                                <tr key={ri} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                                  {result.columns.map((col) => {
                                    const val = String(row[col] ?? "")
                                    const cellKey = `${ri}-${col}`
                                    return (
                                      <td
                                        key={col}
                                        className="px-3 py-2 font-mono whitespace-nowrap group cursor-pointer hover:bg-primary/[0.02]"
                                        onClick={() => copyCell(val, cellKey)}
                                        title="Click to copy"
                                      >
                                        <span className="flex items-center gap-1.5">
                                          {col === "severity" ? (
                                            <Badge className={`text-[9px] px-1.5 py-0 h-4 font-bold ${
                                              val === "ERROR"
                                                ? "bg-red-500/10 text-red-600 border border-red-300/30 hover:bg-red-500/10"
                                                : val === "WARN"
                                                ? "bg-amber-500/10 text-amber-600 border border-amber-300/30 hover:bg-amber-500/10"
                                                : "bg-primary/10 text-primary border border-primary/20 hover:bg-primary/10"
                                            }`}>
                                              {val}
                                            </Badge>
                                          ) : col === "id" ? (
                                            <span className="text-muted-foreground">{val}</span>
                                          ) : col === "ip_address" ? (
                                            <span className="text-primary">{val}</span>
                                          ) : col === "event_template" ? (
                                            <span className="truncate max-w-[280px]">{val}</span>
                                          ) : (
                                            <span className="truncate max-w-[200px]">{val}</span>
                                          )}
                                          {copiedCell === cellKey ? (
                                            <Check className="size-2.5 text-[#198754] shrink-0" />
                                          ) : (
                                            <Copy className="size-2.5 text-muted-foreground/0 group-hover:text-muted-foreground/40 shrink-0 transition-colors" />
                                          )}
                                        </span>
                                      </td>
                                    )
                                  })}
                                </tr>
                              ))}
                              {pagedResultRows.length === 0 && (
                                <tr>
                                  <td colSpan={result.columns.length} className="px-3 py-10 text-center text-muted-foreground">
                                    No matching results found.
                                  </td>
                                </tr>
                              )}
                            </tbody>
                          </table>
                        </div>

                        {/* Pagination */}
                        <div className="flex items-center justify-between border-t px-4 py-2.5">
                          <p className="text-[10px] text-muted-foreground">
                            Showing {processedRows.length > 0 ? (resultPage - 1) * resultRowsPerPage + 1 : 0}-{Math.min(resultPage * resultRowsPerPage, processedRows.length)} of {processedRows.length} rows
                          </p>
                          <div className="flex items-center gap-1">
                            <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={resultPage === 1} onClick={() => setResultPage(1)}>
                              <ChevronsLeft className="size-3" />
                            </Button>
                            <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={resultPage === 1} onClick={() => setResultPage((p) => p - 1)}>
                              <ChevronLeft className="size-3" />
                            </Button>
                            <span className="text-[10px] text-muted-foreground px-2">Page {resultPage} of {totalResultPages || 1}</span>
                            <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={resultPage >= totalResultPages} onClick={() => setResultPage((p) => p + 1)}>
                              <ChevronRight className="size-3" />
                            </Button>
                            <Button variant="outline" size="sm" className="h-6 w-6 p-0" disabled={resultPage >= totalResultPages} onClick={() => setResultPage(totalResultPages)}>
                              <ChevronsRight className="size-3" />
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </>
                )}
              </div>

              {/* ── RIGHT COLUMN ── */}
              <div className="space-y-4">
                {/* SECTION 3 — Schema / NER Column Helper */}
                <Card className="border shadow-none">
                  <CardHeader className="px-4 py-3 space-y-0 cursor-pointer" onClick={() => setSchemaOpen(!schemaOpen)}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Columns3 className="size-3.5 text-primary" />
                        <CardTitle className="text-xs font-semibold">Table Schema</CardTitle>
                        <Badge variant="outline" className="text-[8px] h-3.5 px-1 font-mono">parsed_logs</Badge>
                      </div>
                      {schemaOpen ? <ChevronUp className="size-3.5 text-muted-foreground" /> : <ChevronDown className="size-3.5 text-muted-foreground" />}
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-1">
                      Click a field to insert into SQL editor
                    </p>
                  </CardHeader>
                  {schemaOpen && (
                    <CardContent className="px-4 pb-4 pt-0">
                      <div className="space-y-1">
                        {nerFields.map((field) => (
                          <button
                            key={field.name}
                            onClick={() => handleInsertField(field.name)}
                            className="w-full flex items-center gap-2 px-2.5 py-2 border border-border bg-card hover:bg-primary/5 hover:border-primary/20 transition-all text-left group"
                          >
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-1.5">
                                <p className="text-[11px] font-mono font-bold text-foreground group-hover:text-primary transition-colors">
                                  {field.name}
                                </p>
                                <Badge variant="outline" className="text-[7px] h-3 px-1 font-mono text-muted-foreground/50 shrink-0">
                                  {field.type}
                                </Badge>
                              </div>
                              <p className="text-[9px] text-muted-foreground truncate mt-0.5">{field.description}</p>
                            </div>
                          </button>
                        ))}
                      </div>
                    </CardContent>
                  )}
                </Card>

                {/* Security Notice */}
                <Card className="border shadow-none border-amber-200/50 bg-amber-50/10">
                  <CardContent className="px-4 py-3">
                    <div className="flex items-start gap-2">
                      <ShieldAlert className="size-3.5 text-amber-600 mt-0.5 shrink-0" />
                      <div>
                        <p className="text-[10px] font-bold text-amber-700">Security Policy</p>
                        <ul className="text-[9px] text-amber-600/80 mt-1 space-y-0.5 leading-relaxed">
                          <li>Only SELECT queries permitted</li>
                          <li>DELETE, UPDATE, DROP, INSERT, ALTER blocked</li>
                          <li>SQL injection protection enforced</li>
                          <li>Gemini prompt sanitization active</li>
                          <li>All queries logged for audit</li>
                        </ul>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Query History */}
                {showHistory && history.length > 0 && (
                  <Card className="border shadow-none">
                    <CardHeader className="px-4 py-3 space-y-0">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <History className="size-3.5 text-primary" />
                          <CardTitle className="text-xs font-semibold">Query History</CardTitle>
                        </div>
                        <Button variant="ghost" size="sm" className="h-5 w-5 p-0" onClick={() => setHistory([])}>
                          <Trash2 className="size-3 text-muted-foreground" />
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent className="px-4 pb-4 pt-0">
                      <ScrollArea className="max-h-60">
                        <div className="space-y-1.5">
                          {history.map((h) => (
                            <button
                              key={h.id}
                              onClick={() => loadFromHistory(h)}
                              className="w-full text-left border border-border bg-card hover:bg-muted/30 p-2.5 transition-colors"
                            >
                              <p className="text-[10px] text-foreground font-medium truncate">{h.query}</p>
                              <div className="flex items-center gap-3 mt-1">
                                <span className="text-[9px] text-muted-foreground">{h.rows} rows</span>
                                <span className="text-[9px] text-muted-foreground">{h.time}ms</span>
                                <span className="text-[9px] text-muted-foreground ml-auto">{h.timestamp}</span>
                              </div>
                            </button>
                          ))}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                )}

                {/* Query Stats (when result exists) */}
                {result && (
                  <Card className="border shadow-none border-[#198754]/20 bg-[#198754]/[0.02]">
                    <CardHeader className="px-4 py-3 space-y-0">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="size-3.5 text-[#198754]" />
                        <CardTitle className="text-xs font-semibold text-[#198754]">Query Complete</CardTitle>
                      </div>
                    </CardHeader>
                    <CardContent className="px-4 pb-4 pt-0 space-y-1.5">
                      {[
                        { label: "Execution Time", value: `${result.executionTime}ms` },
                        { label: "Total Rows", value: String(result.totalRows) },
                        { label: "Columns", value: String(result.columns.length) },
                        { label: "Tables", value: result.tablesUsed.join(", ") },
                        { label: "Filtered", value: String(processedRows.length) },
                      ].map((s) => (
                        <div key={s.label} className="flex items-center justify-between py-1.5 border-b border-border/50 last:border-0">
                          <span className="text-[10px] text-muted-foreground">{s.label}</span>
                          <span className="text-[10px] font-mono font-bold text-foreground">{s.value}</span>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>
          </div>
        </ScrollArea>
      </div>
    </div>
  )
}
