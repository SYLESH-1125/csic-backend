import { NextRequest, NextResponse } from "next/server"

interface ParsedLogRow {
  id: number
  timestamp: string
  event_template: string
  ip_address: string
  process_name: string
  user: string
  severity: string
  facility: string
  raw_log: string
}

const PARSED_LOGS: ParsedLogRow[] = Array.from({ length: 48 }, (_, i) => ({
  id: i + 1,
  timestamp: `2026-03-05T${String(8 + Math.floor(i / 6)).padStart(2, "0")}:${String((i * 7) % 60).padStart(2, "0")}:${String((i * 13) % 60).padStart(2, "0")}Z`,
  event_template: [
    "User <*> logged in from <*>",
    "Process <*> started on port <*>",
    "Connection refused from <*>:<*>",
    "File <*> modified by <*>",
    "Authentication failure for <*> from <*>",
    "Service <*> restarted successfully",
  ][i % 6],
  ip_address: `192.168.${1 + (i % 5)}.${10 + i}`,
  process_name: ["sshd", "nginx", "systemd", "crond", "auditd", "firewalld"][i % 6],
  user: ["root", "admin", "operator", "auditor", "system", "investigator"][i % 6],
  severity: ["INFO", "INFO", "WARN", "INFO", "ERROR", "INFO"][i % 6],
  facility: ["auth", "http", "system", "cron", "audit", "firewall"][i % 6],
  raw_log: `log-${i + 1}`,
}))

const UNSAFE = ["DELETE", "UPDATE", "DROP", "INSERT", "ALTER", "TRUNCATE", "CREATE", "REPLACE", "EXEC", "EXECUTE"]
const ALL_COLUMNS = ["id", "timestamp", "event_template", "ip_address", "process_name", "user", "severity", "facility", "raw_log"]

export async function POST(request: NextRequest) {
  const start = performance.now()
  try {
    const body = await request.json()
    const sql = (body?.sql || "").toString().trim()
    if (!sql) return NextResponse.json({ error: "SQL query is required" }, { status: 400 })

    const upper = sql.toUpperCase()
    for (const kw of UNSAFE) {
      if (new RegExp(`\\b${kw}\\b`).test(upper)) {
        return NextResponse.json({ error: `Unsafe SQL detected: ${kw}` }, { status: 400 })
      }
    }
    if (!upper.startsWith("SELECT") && !upper.startsWith("WITH")) {
      return NextResponse.json({ error: "Query must start with SELECT or WITH statement." }, { status: 400 })
    }

    // Lightweight execution for UI flow; supports common WHERE/LIMIT patterns.
    let rows = [...PARSED_LOGS]
    const whereIp = sql.match(/ip_address\s*=\s*'([^']+)'/i)?.[1]
    if (whereIp) rows = rows.filter((r) => r.ip_address === whereIp)
    const whereSeverity = sql.match(/severity\s*=\s*'([^']+)'/i)?.[1]
    if (whereSeverity) rows = rows.filter((r) => r.severity.toUpperCase() === whereSeverity.toUpperCase())

    const likeTerms = [...sql.matchAll(/(?:event_template|raw_log)\s+LIKE\s+'%([^']+)%'/gi)].map((m) => m[1].toLowerCase())
    if (likeTerms.length) {
      rows = rows.filter((r) => likeTerms.every((t) => r.event_template.toLowerCase().includes(t) || r.raw_log.toLowerCase().includes(t)))
    }

    const limit = Number(sql.match(/LIMIT\s+(\d+)/i)?.[1] || rows.length)
    rows = rows.slice(0, Math.max(0, limit))

    const executionTime = Math.round((performance.now() - start) * 10) / 10
    return NextResponse.json({
      columns: ALL_COLUMNS,
      rows: rows.map((r) => ({ ...r })),
      executionTime,
      totalRows: rows.length,
      tablesUsed: ["parsed_logs"],
    })
  } catch (error: any) {
    return NextResponse.json({ error: error?.message || "Failed to execute query" }, { status: 500 })
  }
}

