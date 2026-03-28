"use client"

import React, { useEffect, useMemo, useRef, useState } from "react"
import { useApp } from "@/lib/app-context"
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Sector,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"

type ReportTemplate = {
  id: string
  name: string
  color: string
  thumbnail?: string
  covers: { id: string; name: string; image: string }[]
  fonts: { id: string; name: string }[]
  graphs: { id: string; name: string }[]
  tables: { id: string; name: string }[]
}

type ReportChart = {
  b64?: string
  type?: string
  data?: { name: string; value: number }[]
}
type ReportTable = { title?: string; columns?: string[]; rows?: string[][] }
type ReportList = { title?: string; items?: string[] }
type ReportPage = { title?: string; paragraphs?: string[]; charts?: ReportChart[]; tables?: ReportTable[]; lists?: ReportList[] }

type ReportPreview = {
  meta?: { case_id?: string; generated_at?: string; verdict?: string; verdict_reason?: string }
  toc?: { no: number; title: string; page: number }[]
  pages?: ReportPage[]
}

type StreamBlock =
  | { pageIndex: number; type: "title" | "paragraph"; text: string }
  | { pageIndex: number; type: "chart"; chart: ReportChart }
  | { pageIndex: number; type: "table"; table: ReportTable }
  | { pageIndex: number; type: "list"; list: ReportList }

function absolutize(apiBase: string, maybeUrl?: string): string | undefined {
  if (!maybeUrl) return undefined
  if (/^https?:\/\//i.test(maybeUrl)) return maybeUrl
  if (maybeUrl.startsWith("/")) return `${apiBase}${maybeUrl}`
  return maybeUrl
}

export function Phase6Page() {
  const { setCurrentPage } = useApp()
  const apiBase = useMemo(() => {
    const raw = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").trim().replace(/\/+$/, "")
    // Browsers cannot call 0.0.0.0; treat it as localhost.
    return raw.replace("://0.0.0.0", "://127.0.0.1")
  }, [])

  type Phase6Nav = "engine" | "templates" | "data" | "exports" | "settings"
  const [nav, setNav] = useState<Phase6Nav>("engine")

  const [templates, setTemplates] = useState<ReportTemplate[]>([])
  const [selectedTemplate, setSelectedTemplate] = useState("")
  const [jsonFile, setJsonFile] = useState<File | null>(null)
  const [jsonData, setJsonData] = useState<any>(null)
  const [selectedCover, setSelectedCover] = useState("")
  const [setupStep, setSetupStep] = useState<"template" | "customize">("template")
  const [fontStyle, setFontStyle] = useState("times")
  const [graphStyle, setGraphStyle] = useState("classic")
  const [tableStyle, setTableStyle] = useState("clean")
  const [customTab, setCustomTab] = useState<"fonts" | "graphs" | "tables">("fonts")

  const [selectedGraphs, setSelectedGraphs] = useState<string[]>(["timeline", "top_entities", "file_types"])

  const [phase, setPhase] = useState<"idle" | "writing" | "compiling" | "done">("idle")
  const [preview, setPreview] = useState<ReportPreview | null>(null)
  const [pdfUrl, setPdfUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [viewMode, setViewMode] = useState<"pdf" | "html">("pdf")

  const [streamIndex, setStreamIndex] = useState(0)
  const [streamChar, setStreamChar] = useState(0)
  const [pieActiveIdx, setPieActiveIdx] = useState<number | undefined>(undefined)

  const scrollRef = useRef<HTMLDivElement>(null)
  const userScrolled = useRef(false)

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const t = e.currentTarget
    userScrolled.current = t.scrollHeight - t.scrollTop - t.clientHeight > 150
  }

  useEffect(() => {
    fetch(`${apiBase}/api/report/templates`)
      .then((r) => r.json())
      .then((d) => {
        const list: ReportTemplate[] = d.templates || []
        setTemplates(list)
        if (list.length > 0) {
          const first = list[0]
          setSelectedTemplate(first.id)
          setFontStyle(first.fonts?.[0]?.id || "times")
          setGraphStyle(first.graphs?.[0]?.id || "classic")
          setTableStyle(first.tables?.[0]?.id || "clean")
        }
      })
      .catch(() => {})
  }, [apiBase])

  const activeTemplate = templates.find((t) => t.id === selectedTemplate) || null
  const coverImg = absolutize(apiBase, activeTemplate?.covers?.find((c) => c.id === selectedCover)?.image)

  const pages = useMemo(() => preview?.pages || [], [preview])
  const displayPages = useMemo(() => (phase === "done" ? pages : pages.slice(0, 5)), [pages, phase])
  const totalActualPages = preview?.pages ? preview.pages.length + 2 : 0

  const streamBlocks = useMemo<StreamBlock[]>(() => {
    const arr: StreamBlock[] = []
    displayPages.forEach((page, pageIndex) => {
      if (page.title) arr.push({ pageIndex, type: "title", text: page.title })
      ;(page.paragraphs || []).forEach((p) => arr.push({ pageIndex, type: "paragraph", text: p }))
      ;(page.charts || []).forEach((chart) => arr.push({ pageIndex, type: "chart", chart }))
      ;(page.tables || []).forEach((table) => arr.push({ pageIndex, type: "table", table }))
      ;(page.lists || []).forEach((list) => arr.push({ pageIndex, type: "list", list }))
    })
    return arr
  }, [displayPages])

  useEffect(() => {
    if (phase !== "writing") return
    if (!streamBlocks.length) return

    if (streamIndex >= streamBlocks.length) {
      const t = setTimeout(() => setPhase("compiling"), 600)
      return () => clearTimeout(t)
    }

    const current = streamBlocks[streamIndex]
    if (current.type === "title" || current.type === "paragraph") {
      if (streamChar < current.text.length) {
        const t = setTimeout(() => setStreamChar((v) => v + 1), 8)
        return () => clearTimeout(t)
      }
      const t = setTimeout(() => {
        setStreamIndex((v) => v + 1)
        setStreamChar(0)
      }, 110)
      return () => clearTimeout(t)
    }

    const t = setTimeout(() => {
      setStreamIndex((v) => v + 1)
      setStreamChar(0)
    }, 260)
    return () => clearTimeout(t)
  }, [phase, streamBlocks, streamIndex, streamChar])

  useEffect(() => {
    if (phase === "writing" && !userScrolled.current) {
      const el = document.getElementById("phase6-active-typing-block")
      el?.scrollIntoView({ behavior: "smooth", block: "center" })
    }
  }, [streamIndex, phase])

  useEffect(() => {
    if (phase === "compiling" && pdfUrl) {
      const t = setTimeout(() => {
        setPhase("done")
        setViewMode("html")
      }, 2000)
      return () => clearTimeout(t)
    }
  }, [phase, pdfUrl])

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (!f) return
    setJsonFile(f)
    setError("")
    try {
      const txt = await f.text()
      setJsonData(JSON.parse(txt))
    } catch {
      setJsonData(null)
      setError("Invalid JSON file")
    }
  }

  const availableGraphs = [
    { id: "timeline", name: "Risk Time (Line)" },
    { id: "top_entities", name: "Entities (Horiz)" },
    { id: "signals", name: "Behaviors (Bar)" },
    { id: "file_types", name: "File Types (Pie)" },
    { id: "scores", name: "Scores (Hist)" },
    { id: "integrity", name: "Integrity (Bar)" },
    { id: "parse_errors", name: "Errors (Bar)" },
    { id: "duckdb", name: "Database (Bar)" },
  ]

  const toggleGraph = (id: string) => {
    if (selectedGraphs.includes(id)) {
      if (selectedGraphs.length <= 1) {
        setError("You must select at least 1 graph type.")
        setTimeout(() => setError(""), 2000)
        return
      }
      setSelectedGraphs((prev) => prev.filter((g) => g !== id))
      return
    }
    if (selectedGraphs.length >= 5) {
      setError("Maximum 5 graph types allowed for optimal layout.")
      setTimeout(() => setError(""), 2000)
      return
    }
    setSelectedGraphs((prev) => [...prev, id])
  }

  const start = async () => {
    if (!jsonData) {
      setError("Upload a valid JSON first")
      return
    }
    if (!selectedTemplate) {
      setError("Choose a template first")
      return
    }

    try {
      setLoading(true)
      setError("")
      setPreview(null)
      setPdfUrl("")
      setPhase("idle")
      setStreamIndex(0)
      setStreamChar(0)
      userScrolled.current = false

      const body = {
        payload: jsonData,
        template_id: selectedTemplate,
        cover_id: selectedCover,
        font_style: fontStyle,
        graph_style: graphStyle,
        table_style: tableStyle,
        selected_graphs: selectedGraphs,
      }

      const previewRes = await fetch(`${apiBase}/api/report/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      const previewData = await previewRes.json()
      if (!previewRes.ok) {
        setError("Preview failed")
        setLoading(false)
        return
      }

      setPreview(previewData.preview)
      setPhase("writing")

      const generateRes = await fetch(`${apiBase}/api/report/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      const generateData = await generateRes.json()
      if (!generateRes.ok) {
        setError(`SYSTEM HALT: ${generateData.detail || "Unknown Server Crash"}`)
        setPhase("idle")
        setLoading(false)
        return
      }

      setPdfUrl(`${apiBase}${generateData.pdf_url}`)
      setLoading(false)
    } catch {
      setError("Something went wrong. Verify backend is running.")
      setLoading(false)
    }
  }

  const fontFamily =
    fontStyle === "times" ? "Times New Roman, serif" : fontStyle === "georgia" ? "Georgia, serif" : "Arial, sans-serif"

  const palette =
    graphStyle === "modern"
      ? {
          bg: "#0F172A",
          text: "#F8FAFC",
          grid: "#334155",
          c1: "#06B6D4",
          c2: "#6366F1",
          c3: "#8B5CF6",
          c4: "#64748B",
          colors: ["#06B6D4", "#6366F1", "#8B5CF6", "#F472B6", "#FB7185", "#34D399", "#FBBF24"],
        }
      : graphStyle === "clean" || graphStyle === "minimal"
        ? {
            bg: "#FFFFFF",
            text: "#0F172A",
            grid: "#E2E8F0",
            c1: "#0369A1",
            c2: "#0284C7",
            c3: "#38BDF8",
            c4: "#BAE6FD",
            colors: ["#0369A1", "#0284C7", "#38BDF8", "#7DD3FC", "#BAE6FD", "#E0F2FE", "#F0F9FF"],
          }
        : {
            bg: "#FFFFFF",
            text: "#0F172A",
            grid: "#E2E8F0",
            c1: "#B91C1C",
            c2: "#1D4ED8",
            c3: "#15803D",
            c4: "#D97706",
            colors: ["#B91C1C", "#1D4ED8", "#15803D", "#D97706", "#7E22CE", "#0F766E", "#64748B"],
          }

  const renderActiveShape = (props: any) => {
    const RADIAN = Math.PI / 180
    const { cx, cy, midAngle, innerRadius, outerRadius, startAngle, endAngle, fill, payload, percent, value } = props
    const sin = Math.sin(-RADIAN * midAngle)
    const cos = Math.cos(-RADIAN * midAngle)
    const sx = cx + (outerRadius + 5) * cos
    const sy = cy + (outerRadius + 5) * sin
    const mx = cx + (outerRadius + 20) * cos
    const my = cy + (outerRadius + 20) * sin
    const ex = mx + (cos >= 0 ? 1 : -1) * 20
    const ey = my
    const textAnchor = cos >= 0 ? "start" : "end"

    return (
      <g>
        <Sector
          cx={cx}
          cy={cy}
          innerRadius={innerRadius}
          outerRadius={outerRadius + 10}
          startAngle={startAngle}
          endAngle={endAngle}
          fill={fill}
          style={{ filter: "drop-shadow(0px 6px 8px rgba(0,0,0,0.3))" }}
        />
        <path d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`} stroke={fill} strokeWidth={2} fill="none" />
        <circle cx={ex} cy={ey} r={4} fill={fill} stroke="none" />
        <text x={ex + (cos >= 0 ? 1 : -1) * 10} y={ey} textAnchor={textAnchor} fill={palette.text} fontSize={13} fontWeight="bold">
          {payload.name}
        </text>
        <text x={ex + (cos >= 0 ? 1 : -1) * 10} y={ey} dy={18} textAnchor={textAnchor} fill="#64748B" fontSize={12}>
          {`Metric Value: ${value} (${(percent * 100).toFixed(1)}%)`}
        </text>
      </g>
    )
  }

  const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent }: any) => {
    const RADIAN = Math.PI / 180
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5
    const x = cx + radius * Math.cos(-RADIAN * midAngle)
    const y = cy + radius * Math.sin(-RADIAN * midAngle)

    return percent > 0.07 ? (
      <text
        x={x}
        y={y}
        fill="#FFFFFF"
        textAnchor="middle"
        dominantBaseline="central"
        fontSize={12}
        fontWeight="bold"
        style={{ textShadow: "0px 1px 3px rgba(0,0,0,0.6)" }}
      >
        {`${(percent * 100).toFixed(0)}%`}
      </text>
    ) : null
  }

  const navButtonStyle = (active: boolean): React.CSSProperties => ({
    cursor: "pointer",
    padding: "12px 16px",
    borderRadius: "6px",
    transition: "0.2s",
    textAlign: "left",
    backgroundColor: active ? "#F1F5F9" : "transparent",
    color: active ? "#0F172A" : "#475569",
    borderLeft: active ? "4px solid #0284C7" : "4px solid transparent",
  })

  return (
    <div
      style={{
        display: "flex",
        height: "100%",
        minHeight: "100vh",
        backgroundColor: "#F8FAFC",
        color: "#0F172A",
        fontFamily: "Arial, sans-serif",
        overflow: "hidden",
      }}
    >
      <style>{`
        @keyframes phase6_blink { 50% { border-color: transparent; } }
        @keyframes phase6_fadein { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes phase6_spin { 100% { transform: rotate(360deg); } }

        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #F1F5F9; }
        ::-webkit-scrollbar-thumb { background: #CBD5E1; border-radius: 4px; }

        .phase6-table-clean { border-collapse: collapse; width: 100%; }
        .phase6-table-clean th { border-bottom: 2px solid #CBD5E1; padding: 12px; text-align: left; font-weight: bold; color: #0F172A; }
        .phase6-table-clean td { border-bottom: 1px solid #E2E8F0; padding: 12px; color: #334155; }
        .phase6-table-clean tr:hover td { background-color: #F8FAFC; transform: scale(1.01); transition: all 0.2s ease; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); color: #0284C7; font-weight: bold; cursor: help; }

        .phase6-table-grid { border-collapse: collapse; width: 100%; border: 1px solid #CBD5E1; }
        .phase6-table-grid th { border: 1px solid #CBD5E1; padding: 10px; text-align: left; background-color: #E2E8F0; color: #0F172A; font-weight: bold; }
        .phase6-table-grid td { border: 1px solid #CBD5E1; padding: 10px; color: #334155; }
        .phase6-table-grid tr:nth-child(even) td { background-color: #F8FAFC; }
        .phase6-table-grid tr:hover td { background-color: #E0F2FE; transition: background-color 0.2s ease; color: #0369A1; cursor: help; }

        .phase6-table-executive { border-collapse: collapse; width: 100%; border: 2px solid #0F172A; }
        .phase6-table-executive th { background-color: #0F172A; color: #FFFFFF; padding: 14px 12px; text-align: left; border: 1px solid #0F172A; font-weight: bold; text-transform: uppercase; font-size: 11px; letter-spacing: 1px; }
        .phase6-table-executive td { border: 1px solid #CBD5E1; padding: 12px; color: #0F172A; font-weight: 500; }
        .phase6-table-executive tr:hover td { background-color: #F1F5F9; border-top: 1px solid #0284C7; border-bottom: 1px solid #0284C7; color: #0284C7; transition: all 0.1s ease; cursor: help; }
      `}</style>

      <div
        style={{
          width: "260px",
          backgroundColor: "#FFFFFF",
          borderRight: "1px solid #E2E8F0",
          display: "flex",
          flexDirection: "column",
          padding: "25px",
          boxShadow: "2px 0 10px rgba(0,0,0,0.03)",
          zIndex: 10,
        }}
      >
        <div
          style={{
            fontSize: "20px",
            fontWeight: "bold",
            color: "#0284C7",
            letterSpacing: "1px",
            marginBottom: "40px",
            display: "flex",
            alignItems: "center",
            gap: "10px",
          }}
        >
          <div style={{ width: "20px", height: "20px", backgroundColor: "#0284C7", borderRadius: "4px" }} />
          FORENIX
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", flexGrow: 1, color: "#475569", fontSize: "14px", fontWeight: "bold" }}>
          <button type="button" style={navButtonStyle(false)} onClick={() => setCurrentPage("dashboard")}>
            Dashboard
          </button>
          <button
            type="button"
            style={navButtonStyle(nav === "engine")}
            onClick={() => {
              setNav("engine")
              if (phase === "idle" && (setupStep === "template" || setupStep === "customize")) return
              setPhase("idle")
              setSetupStep("template")
            }}
          >
            Report Engine
          </button>
          <button
            type="button"
            style={navButtonStyle(nav === "templates")}
            onClick={() => {
              setNav("templates")
              setPhase("idle")
              setSetupStep("template")
            }}
          >
            Templates
          </button>
          <button
            type="button"
            style={navButtonStyle(nav === "data")}
            onClick={() => {
              setNav("data")
              setPhase("idle")
            }}
          >
            Data Sources
          </button>
          <button
            type="button"
            style={navButtonStyle(nav === "exports")}
            onClick={() => {
              setNav("exports")
              setPhase("idle")
            }}
          >
            Exports
          </button>
          <button
            type="button"
            style={navButtonStyle(nav === "settings")}
            onClick={() => {
              setNav("settings")
              setPhase("idle")
              if (activeTemplate) setSetupStep("customize")
            }}
          >
            Settings
          </button>
        </div>
        <div style={{ backgroundColor: "#F8FAFC", padding: "20px", borderRadius: "8px", border: "1px solid #E2E8F0", fontSize: "12px", fontWeight: "bold" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "12px" }}>
            <span style={{ color: "#64748B" }}>Engine Status</span>
            <span style={{ color: "#10B981" }}>● Active</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "12px" }}>
            <span style={{ color: "#64748B" }}>API</span>
            <span style={{ color: "#0F172A" }}>{apiBase.replace(/^https?:\/\//, "")}</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ color: "#64748B" }}>Format</span>
            <span style={{ color: "#0284C7" }}>PDF</span>
          </div>
        </div>
      </div>

      <div style={{ flexGrow: 1, display: "flex", flexDirection: "column", backgroundColor: "#F8FAFC", position: "relative" }}>
        <div style={{ padding: "10px 30px", borderBottom: "1px solid #E2E8F0", backgroundColor: "#FFFFFF", display: "flex", gap: "20px", alignItems: "center", boxShadow: "0 2px 10px rgba(0,0,0,0.02)" }}>
          <div style={{ fontWeight: "bold", color: "#0F172A", fontSize: "16px", marginRight: "auto" }}>Report Generation Pipeline</div>
          <input
            type="file"
            accept=".json,application/json"
            onChange={handleFile}
            style={{
              padding: "8px",
              border: "1px solid #CBD5E1",
              borderRadius: "6px",
              backgroundColor: "#F8FAFC",
              color: "#0F172A",
              cursor: "pointer",
              fontSize: "14px",
              fontWeight: "bold",
            }}
          />
          {phase === "idle" && setupStep === "customize" && (
            <button
              onClick={start}
              disabled={loading}
              style={{
                backgroundColor: "#0284C7",
                opacity: loading ? 0.7 : 1,
                color: "#FFFFFF",
                padding: "10px 25px",
                borderRadius: "6px",
                fontWeight: "bold",
                border: "none",
                cursor: loading ? "not-allowed" : "pointer",
                fontSize: "14px",
                boxShadow: "0 4px 6px -1px rgba(2, 132, 199, 0.2)",
              }}
            >
              {loading ? "WORKING..." : "COMPILE REPORT"}
            </button>
          )}
        </div>

        <div style={{ padding: "10px 30px", borderBottom: "1px solid #E2E8F0", backgroundColor: "#FFFFFF" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
            <h2 style={{ color: "#0F172A", fontSize: "16px", fontWeight: "bold", margin: 0 }}>Your report is being dynamically drafted with verified telemetry.</h2>
          </div>

          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            {["Upload Data", "Configure Style", "Ghostwriting", "Compiling Ledger", "Official PDF"].map((txt, i) => {
              const active = (i === 0 && phase === "idle" && !jsonData) || (i === 1 && phase === "idle" && !!jsonData) || (i === 2 && phase === "writing") || (i === 3 && phase === "compiling") || (i === 4 && phase === "done")
              const past = (i === 0 && !!jsonData) || (i === 1 && phase !== "idle") || (i === 2 && (phase === "compiling" || phase === "done")) || (i === 3 && phase === "done")
              return (
                <div key={txt} style={{ display: "flex", alignItems: "center", flex: 1 }}>
                  <div
                    style={{
                      width: "20px",
                      height: "20px",
                      borderRadius: "50%",
                      backgroundColor: active ? "#0284C7" : past ? "#10B981" : "#F1F5F9",
                      color: active || past ? "#FFFFFF" : "#94A3B8",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: "10px",
                      fontWeight: "bold",
                    }}
                  >
                    {past ? "✓" : i + 1}
                  </div>
                  <div style={{ color: active || past ? "#0F172A" : "#94A3B8", fontSize: "12px", marginLeft: "8px", fontWeight: active ? "bold" : "normal" }}>{txt}</div>
                  {i < 4 && <div style={{ flexGrow: 1, height: "2px", backgroundColor: past ? "#10B981" : "#E2E8F0", margin: "0 10px" }} />}
                </div>
              )
            })}
          </div>
        </div>

        <div style={{ flexGrow: 1, overflow: "hidden", display: "flex", flexDirection: "column", position: "relative" }}>
          {phase === "idle" && !jsonData && (
            <div style={{ flexGrow: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "#64748B", fontWeight: "bold", fontSize: "18px" }}>
              Please upload a verified JSON payload to begin.
            </div>
          )}

          {error && <div style={{ margin: "20px", padding: "15px", background: "#FEE2E2", color: "#B91C1C", fontWeight: "bold", borderRadius: "6px", border: "1px solid #F87171" }}>{error}</div>}

          <div ref={scrollRef} onScroll={handleScroll} style={{ flexGrow: 1, overflowY: "auto", padding: "20px", display: "flex", flexDirection: "column", alignItems: "center", scrollBehavior: "smooth" }}>
            {nav === "data" && phase === "idle" && (
              <div style={{ width: "100%", maxWidth: "1000px", animation: "phase6_fadein 0.4s" }}>
                <div style={{ background: "#FFFFFF", padding: "20px", borderRadius: "8px", border: "1px solid #E2E8F0", boxShadow: "0 4px 10px rgba(0,0,0,0.03)" }}>
                  <h3 style={{ margin: 0, color: "#0F172A" }}>Data Sources</h3>
                  <p style={{ color: "#64748B", fontSize: "13px", fontWeight: "bold", marginTop: "8px" }}>
                    Upload the Phase 6 JSON payload using the file picker in the top bar.
                  </p>
                  <div style={{ marginTop: "14px", padding: "12px", borderRadius: "8px", background: "#F8FAFC", border: "1px solid #E2E8F0", fontSize: "12px", fontWeight: "bold" }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "#64748B" }}>Current payload</span>
                      <span style={{ color: jsonData ? "#10B981" : "#B91C1C" }}>{jsonData ? "Loaded" : "Not loaded"}</span>
                    </div>
                    {jsonFile?.name ? <div style={{ marginTop: "6px", color: "#0F172A" }}>{jsonFile.name}</div> : null}
                  </div>
                </div>
              </div>
            )}

            {nav === "exports" && phase === "idle" && (
              <div style={{ width: "100%", maxWidth: "1000px", animation: "phase6_fadein 0.4s" }}>
                <div style={{ background: "#FFFFFF", padding: "20px", borderRadius: "8px", border: "1px solid #E2E8F0", boxShadow: "0 4px 10px rgba(0,0,0,0.03)" }}>
                  <h3 style={{ margin: 0, color: "#0F172A" }}>Exports</h3>
                  <p style={{ color: "#64748B", fontSize: "13px", fontWeight: "bold", marginTop: "8px" }}>
                    {pdfUrl ? "Your latest compiled report is ready." : "No compiled report available yet. Compile a report first."}
                  </p>
                  {pdfUrl ? (
                    <div style={{ marginTop: "14px", display: "flex", gap: "12px", flexWrap: "wrap" }}>
                      <a
                        href={`${pdfUrl}?download=true`}
                        download
                        style={{
                          padding: "12px 18px",
                          background: "#0284C7",
                          color: "#FFFFFF",
                          textDecoration: "none",
                          borderRadius: "6px",
                          fontWeight: "bold",
                          fontSize: "13px",
                          boxShadow: "0 4px 6px -1px rgba(2, 132, 199, 0.2)",
                          display: "inline-flex",
                          alignItems: "center",
                        }}
                      >
                        Download PDF ↓
                      </a>
                      <button
                        type="button"
                        onClick={() => setViewMode("pdf")}
                        style={{ padding: "12px 18px", background: "#FFFFFF", color: "#0F172A", border: "1px solid #CBD5E1", borderRadius: "6px", fontWeight: "bold", cursor: "pointer" }}
                      >
                        Open PDF Viewer
                      </button>
                    </div>
                  ) : null}
                </div>
              </div>
            )}

            {phase === "done" && pdfUrl && (
              <div style={{ width: "100%", maxWidth: "1000px", animation: "phase6_fadein 0.5s", marginBottom: "20px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#FFFFFF", padding: "20px", borderRadius: "8px", border: "1px solid #E2E8F0", boxShadow: "0 4px 10px rgba(0,0,0,0.03)" }}>
                  <div>
                    <h2 style={{ color: "#0F172A", marginBottom: "5px" }}>Official Verified Dossier</h2>
                    <div style={{ color: "#64748B", fontSize: "14px", fontWeight: "bold" }}>Ready for secure distribution or presentation.</div>
                  </div>
                  <div style={{ display: "flex", gap: "15px", alignItems: "center" }}>
                    <div style={{ display: "flex", background: "#F1F5F9", borderRadius: "6px", padding: "4px", border: "1px solid #CBD5E1" }}>
                      <button
                        onClick={() => setViewMode("html")}
                        style={{
                          padding: "8px 16px",
                          background: viewMode === "html" ? "#FFFFFF" : "transparent",
                          color: viewMode === "html" ? "#0284C7" : "#64748B",
                          border: "none",
                          borderRadius: "4px",
                          fontWeight: "bold",
                          fontSize: "12px",
                          cursor: "pointer",
                          boxShadow: viewMode === "html" ? "0 2px 4px rgba(0,0,0,0.05)" : "none",
                          transition: "0.2s",
                        }}
                      >
                        Interactive Web
                      </button>
                      <button
                        onClick={() => setViewMode("pdf")}
                        style={{
                          padding: "8px 16px",
                          background: viewMode === "pdf" ? "#FFFFFF" : "transparent",
                          color: viewMode === "pdf" ? "#0284C7" : "#64748B",
                          border: "none",
                          borderRadius: "4px",
                          fontWeight: "bold",
                          fontSize: "12px",
                          cursor: "pointer",
                          boxShadow: viewMode === "pdf" ? "0 2px 4px rgba(0,0,0,0.05)" : "none",
                          transition: "0.2s",
                        }}
                      >
                        Static PDF View
                      </button>
                    </div>
                    <button
                      onClick={() => {
                        setPhase("idle")
                        setSetupStep("template")
                      }}
                      style={{
                        padding: "12px 20px",
                        background: "#FFFFFF",
                        color: "#0F172A",
                        border: "1px solid #CBD5E1",
                        borderRadius: "6px",
                        fontWeight: "bold",
                        fontSize: "13px",
                        cursor: "pointer",
                        transition: "0.2s",
                      }}
                    >
                      Restart Process
                    </button>
                    <a
                      href={`${pdfUrl}?download=true`}
                      download
                      style={{
                        padding: "12px 20px",
                        background: "#0284C7",
                        color: "#FFFFFF",
                        textDecoration: "none",
                        borderRadius: "6px",
                        fontWeight: "bold",
                        fontSize: "13px",
                        boxShadow: "0 4px 6px -1px rgba(2, 132, 199, 0.2)",
                        display: "flex",
                        alignItems: "center",
                      }}
                    >
                      Download Final PDF ↓
                    </a>
                  </div>
                </div>
              </div>
            )}

            {(nav === "engine" || nav === "templates") && phase === "idle" && setupStep === "template" && (
              <div style={{ width: "100%", maxWidth: "1000px" }}>
                {!jsonData && (
                  <div style={{ marginBottom: "16px", padding: "14px", borderRadius: "8px", background: "#FFFBEB", border: "1px solid #FDE68A", color: "#92400E", fontWeight: "bold", fontSize: "12px" }}>
                    Upload a JSON payload (top bar) to enable compilation. You can still browse templates now.
                  </div>
                )}
                <h3 style={{ marginBottom: "15px", color: "#0F172A" }}>1. Select Core Template</h3>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "20px", marginBottom: "30px" }}>
                  {templates.map((t) => {
                    const thumb = absolutize(apiBase, t.thumbnail)
                    return (
                      <div
                        key={t.id}
                        onClick={() => {
                          setSelectedTemplate(t.id)
                          setSelectedCover("")
                          setError("")
                        }}
                        style={{
                          cursor: "pointer",
                          border: selectedTemplate === t.id ? "2px solid #0284C7" : "1px solid #CBD5E1",
                          borderRadius: "8px",
                          padding: "20px",
                          background: "#FFFFFF",
                          boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.05)",
                          transition: "all 0.2s",
                          transform: selectedTemplate === t.id ? "translateY(-2px)" : "none",
                        }}
                      >
                        {thumb ? (
                          <img
                            src={thumb}
                            alt={t.name}
                            style={{
                              width: "100%",
                              height: "160px",
                              objectFit: "cover",
                              marginBottom: "15px",
                              borderRadius: "8px",
                              backgroundColor: "#0B1220",
                              border: "1px solid #E2E8F0",
                            }}
                          />
                        ) : (
                          <div style={{ width: "100%", height: "160px", borderRadius: "8px", backgroundColor: "#0B1220", marginBottom: "15px", border: "1px solid #E2E8F0" }} />
                        )}
                        <div style={{ fontWeight: "bold", marginBottom: "6px", color: "#0F172A", fontSize: "16px" }}>{t.name}</div>
                        <div style={{ color: "#64748B", fontSize: "13px", fontWeight: "bold" }}>Standard Architecture</div>
                      </div>
                    )
                  })}
                </div>

                {activeTemplate && (
                  <div style={{ animation: "phase6_fadein 0.4s" }}>
                    <h3 style={{ marginBottom: "15px", color: "#0F172A", borderTop: "1px solid #E2E8F0", paddingTop: "20px" }}>2. Select Cover Layout</h3>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "20px", marginBottom: "30px" }}>
                      {(activeTemplate.covers || []).map((c) => {
                        const cover = absolutize(apiBase, c.image)
                        return (
                          <div
                            key={c.id}
                            onClick={() => setSelectedCover(c.id)}
                            style={{
                              cursor: "pointer",
                              border: selectedCover === c.id ? "2px solid #0284C7" : "1px solid #CBD5E1",
                              borderRadius: "8px",
                              padding: "15px",
                              background: "#FFFFFF",
                              boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.05)",
                              textAlign: "center",
                              transition: "all 0.2s",
                            }}
                          >
                            {cover ? (
                              <img
                                src={cover}
                                alt={c.name}
                                style={{
                                  width: "100%",
                                  height: "280px",
                                  objectFit: "cover",
                                  borderRadius: "8px",
                                  marginBottom: "15px",
                                  background: "#0B1220",
                                  border: "1px solid #E2E8F0",
                                }}
                              />
                            ) : (
                              <div style={{ width: "100%", height: "280px", borderRadius: "8px", marginBottom: "15px", background: "#0B1220", border: "1px solid #E2E8F0" }} />
                            )}
                            <div style={{ fontWeight: "bold", color: "#0F172A" }}>{c.name}</div>
                          </div>
                        )
                      })}
                    </div>

                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                      <button
                        onClick={() => {
                          if (!selectedCover) {
                            setError("Please select a cover page to proceed.")
                            return
                          }
                          setFontStyle(activeTemplate.fonts?.[0]?.id || "times")
                          setGraphStyle(activeTemplate.graphs?.[0]?.id || "classic")
                          setTableStyle(activeTemplate.tables?.[0]?.id || "clean")
                          setError("")
                          setSetupStep("customize")
                          setNav("engine")
                        }}
                        style={{
                          padding: "14px 35px",
                          background: "#0F172A",
                          color: "#FFFFFF",
                          border: "none",
                          borderRadius: "6px",
                          fontWeight: "bold",
                          cursor: "pointer",
                          fontSize: "16px",
                          boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
                        }}
                      >
                        PROCEED TO CUSTOMIZATION →
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {(nav === "engine" || nav === "settings") && phase === "idle" && setupStep === "customize" && activeTemplate && (
              <div style={{ width: "100%", maxWidth: "1200px", animation: "phase6_fadein 0.4s" }}>
                <div style={{ display: "flex", justifyContent: "flex-start", marginBottom: "15px" }}>
                  <button
                    onClick={() => setSetupStep("template")}
                    style={{ padding: "8px 16px", borderRadius: "6px", border: "1px solid #CBD5E1", cursor: "pointer", background: "#FFFFFF", color: "#0F172A", fontWeight: "bold", boxShadow: "0 2px 4px rgba(0,0,0,0.02)" }}
                  >
                    ← Back to Layouts
                  </button>
                </div>

                <div style={{ display: "flex", gap: "30px" }}>
                  <div style={{ flex: 1.5, maxHeight: "700px", overflowY: "auto", background: "#FFFFFF", color: "#0F172A", padding: "40px", borderRadius: "8px", boxShadow: "0 10px 30px rgba(0,0,0,0.08)", fontFamily, border: "1px solid #E2E8F0" }}>
                    <div style={{ fontSize: "24px", fontWeight: "bold", marginBottom: "20px", borderBottom: "2px solid #E2E8F0", paddingBottom: "10px" }}>Sample Report Document</div>
                    <p style={{ lineHeight: "1.6", marginBottom: "25px", fontSize: "14px", color: "#334155" }}>
                      This interactive preview accurately simulates your selected data grids and visual metrics. Hover over the elements to test interactivity.
                    </p>

                    <div style={{ display: "grid", gridTemplateColumns: selectedGraphs.length > 1 ? "1fr 1fr" : "1fr", gap: "20px", marginBottom: "35px" }}>
                      {selectedGraphs.map((gid) => (
                        <div key={gid} style={{ height: "180px", borderRadius: "8px", background: palette.bg, border: `1px solid ${palette.grid}`, padding: "15px", display: "flex", flexDirection: "column" }}>
                          <div style={{ fontSize: "12px", fontWeight: "bold", color: palette.text, marginBottom: "15px", textAlign: "center" }}>
                            {availableGraphs.find((g) => g.id === gid)?.name || gid}
                          </div>
                          {gid === "file_types" && (
                            <div style={{ width: "100px", height: "100px", borderRadius: "50%", background: `conic-gradient(${palette.c1} 0% 40%, ${palette.c2} 40% 75%, ${palette.c4} 75% 90%, ${palette.c3} 90% 100%)`, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "center" }}>
                              <span style={{ color: "#FFF", fontSize: "12px", fontWeight: "bold", textShadow: "0px 1px 3px rgba(0,0,0,0.6)" }}>40%</span>
                            </div>
                          )}
                          {gid === "timeline" && (
                            <div style={{ flex: 1, borderBottom: `2px solid ${palette.grid}`, borderLeft: `2px solid ${palette.grid}`, position: "relative" }}>
                              <svg viewBox="0 0 100 40" preserveAspectRatio="none" style={{ width: "100%", height: "100%", overflow: "visible" }}>
                                <path d="M0,35 L20,25 L40,30 L60,10 L80,15 L100,5 L100,40 L0,40 Z" fill={palette.c2} opacity="0.15" />
                                <polyline points="0,35 20,25 40,30 60,10 80,15 100,5" fill="none" stroke={palette.c1} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                              </svg>
                            </div>
                          )}
                          {["signals", "scores", "integrity", "parse_errors", "duckdb"].includes(gid) && (
                            <div style={{ flex: 1, display: "flex", alignItems: "flex-end", justifyContent: "space-around", gap: "8px", borderBottom: `2px solid ${palette.grid}` }}>
                              <div style={{ width: "20%", height: "40%", background: palette.c3, borderRadius: "3px 3px 0 0" }} />
                              <div style={{ width: "20%", height: "70%", background: palette.c2, borderRadius: "3px 3px 0 0" }} />
                              <div style={{ width: "20%", height: "50%", background: palette.c4, borderRadius: "3px 3px 0 0" }} />
                              <div style={{ width: "20%", height: "90%", background: palette.c1, borderRadius: "3px 3px 0 0" }} />
                            </div>
                          )}
                          {gid === "top_entities" && (
                            <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "space-around", borderLeft: `2px solid ${palette.grid}` }}>
                              <div style={{ width: "90%", height: "15px", background: palette.c1, borderRadius: "0 3px 3px 0" }} />
                              <div style={{ width: "70%", height: "15px", background: palette.c2, borderRadius: "0 3px 3px 0" }} />
                              <div style={{ width: "80%", height: "15px", background: palette.c3, borderRadius: "0 3px 3px 0" }} />
                              <div style={{ width: "50%", height: "15px", background: palette.c4, borderRadius: "0 3px 3px 0" }} />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>

                    <div style={{ marginBottom: "15px", fontSize: "15px", fontWeight: "bold", color: "#0F172A" }}>Extracted Telemetry Metrics</div>
                    <table className={`phase6-table-${tableStyle}`}>
                      <thead>
                        <tr>{["Target Entity", "Observed Value", "Verification"].map((h) => <th key={h}>{h}</th>)}</tr>
                      </thead>
                      <tbody>
                        <tr title="Hover test: This is a verified system artifact.">
                          <td>System Artifact ID</td>
                          <td>CASE-DEMO-2026</td>
                          <td style={{ color: "#10B981", fontWeight: "bold" }}>Verified</td>
                        </tr>
                        <tr title="Hover test: High-risk anomaly detected in lateral movement.">
                          <td>Threat Concentration</td>
                          <td>High-Risk Lateral Mvmt.</td>
                          <td style={{ color: "#EF4444", fontWeight: "bold" }}>Flagged</td>
                        </tr>
                        <tr title="Hover test: Hash chain remains intact across all jumps.">
                          <td>Data Continuity</td>
                          <td>Hash Chain Intact</td>
                          <td style={{ color: "#10B981", fontWeight: "bold" }}>Verified</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  <div style={{ flex: 1 }}>
                    <h3 style={{ marginBottom: "15px", color: "#0F172A" }}>Style Configuration</h3>
                    <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "30px" }}>
                      <div style={{ display: "flex", gap: "10px" }}>
                        <button onClick={() => setCustomTab("fonts")} style={{ flex: 1, padding: "10px", borderRadius: "6px", border: "1px solid #CBD5E1", cursor: "pointer", background: customTab === "fonts" ? "#0284C7" : "#FFFFFF", color: customTab === "fonts" ? "#FFF" : "#0F172A", fontWeight: "bold" }}>
                          Typography
                        </button>
                        <button onClick={() => setCustomTab("graphs")} style={{ flex: 1, padding: "10px", borderRadius: "6px", border: "1px solid #CBD5E1", cursor: "pointer", background: customTab === "graphs" ? "#0284C7" : "#FFFFFF", color: customTab === "graphs" ? "#FFF" : "#0F172A", fontWeight: "bold" }}>
                          Visuals
                        </button>
                        <button onClick={() => setCustomTab("tables")} style={{ flex: 1, padding: "10px", borderRadius: "6px", border: "1px solid #CBD5E1", cursor: "pointer", background: customTab === "tables" ? "#0284C7" : "#FFFFFF", color: customTab === "tables" ? "#FFF" : "#0F172A", fontWeight: "bold" }}>
                          Data Grids
                        </button>
                      </div>

                      <div style={{ background: "#FFFFFF", border: "1px solid #E2E8F0", padding: "20px", borderRadius: "8px", display: "flex", flexDirection: "column", gap: "10px" }}>
                        {customTab === "fonts" &&
                          (activeTemplate?.fonts || []).map((f) => (
                            <button key={f.id} onClick={() => setFontStyle(f.id)} style={{ padding: "12px", borderRadius: "6px", border: "1px solid #CBD5E1", cursor: "pointer", background: fontStyle === f.id ? "#F1F5F9" : "#FFFFFF", color: "#0F172A", fontWeight: "bold", textAlign: "left", display: "flex", justifyContent: "space-between" }}>
                              {f.name} {fontStyle === f.id && <span style={{ color: "#0284C7" }}>✓</span>}
                            </button>
                          ))}

                        {customTab === "graphs" && (
                          <div style={{ display: "flex", flexDirection: "column", gap: "15px" }}>
                            <div style={{ fontWeight: "bold", color: "#0F172A", fontSize: "13px", borderBottom: "1px solid #E2E8F0", paddingBottom: "5px" }}>1. Base Palette Style</div>
                            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                              {(activeTemplate?.graphs || []).map((g) => (
                                <button key={g.id} onClick={() => setGraphStyle(g.id)} style={{ flex: 1, padding: "10px", borderRadius: "6px", border: "1px solid #CBD5E1", cursor: "pointer", background: graphStyle === g.id ? "#F1F5F9" : "#FFFFFF", color: "#0F172A", fontWeight: "bold", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                  {g.name} {graphStyle === g.id && <span style={{ color: "#0284C7" }}>✓</span>}
                                </button>
                              ))}
                            </div>

                            <div style={{ fontWeight: "bold", color: "#0F172A", fontSize: "13px", borderBottom: "1px solid #E2E8F0", paddingBottom: "5px", marginTop: "5px", display: "flex", justifyContent: "space-between" }}>
                              <span>2. Include Charts (Min 1, Max 5)</span>
                              <span style={{ color: "#64748B" }}>{selectedGraphs.length} / 5</span>
                            </div>
                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                              {availableGraphs.map((g) => {
                                const isSel = selectedGraphs.includes(g.id)
                                return (
                                  <div
                                    key={g.id}
                                    onClick={() => toggleGraph(g.id)}
                                    style={{ padding: "10px", borderRadius: "6px", border: `1px solid ${isSel ? "#0284C7" : "#E2E8F0"}`, cursor: "pointer", background: isSel ? "#F0F9FF" : "#F8FAFC", color: "#0F172A", fontSize: "12px", fontWeight: "bold", display: "flex", alignItems: "center", gap: "8px", transition: "0.1s" }}
                                  >
                                    <div style={{ width: "16px", height: "16px", borderRadius: "4px", border: "1px solid #0284C7", background: isSel ? "#0284C7" : "#FFF", display: "flex", alignItems: "center", justifyContent: "center" }}>
                                      {isSel && <span style={{ color: "#FFF", fontSize: "10px" }}>✓</span>}
                                    </div>
                                    {g.name}
                                  </div>
                                )
                              })}
                            </div>
                          </div>
                        )}

                        {customTab === "tables" &&
                          (activeTemplate?.tables || []).map((tb) => (
                            <button key={tb.id} onClick={() => setTableStyle(tb.id)} style={{ padding: "12px", borderRadius: "6px", border: "1px solid #CBD5E1", cursor: "pointer", background: tableStyle === tb.id ? "#F1F5F9" : "#FFFFFF", color: "#0F172A", fontWeight: "bold", textAlign: "left", display: "flex", justifyContent: "space-between" }}>
                              {tb.name} {tableStyle === tb.id && <span style={{ color: "#0284C7" }}>✓</span>}
                            </button>
                          ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {(phase === "writing" || (phase === "done" && viewMode === "html")) && (
              <div style={{ display: "flex", flexDirection: "column", gap: "30px", alignItems: "center", paddingBottom: "40px" }}>
                {coverImg && (
                  <div style={{ width: "800px", height: "1130px", background: "#FFFFFF", padding: "20px", borderRadius: "4px", boxShadow: "0 10px 30px rgba(0,0,0,0.1)", border: "1px solid #CBD5E1", animation: "phase6_fadein 0.5s", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <img src={coverImg} alt="Cover Page" style={{ width: "100%", height: "100%", objectFit: "contain", borderRadius: "4px" }} />
                  </div>
                )}

                {displayPages.map((page, pageIndex) => {
                  const visible = streamBlocks.some((b, idx) => b.pageIndex === pageIndex && idx <= streamIndex)
                  if (!visible && phase !== "done") return null

                  return (
                    <div key={pageIndex} style={{ width: "800px", minHeight: "1050px", background: "#FFFFFF", color: "#0F172A", padding: "60px", borderRadius: "4px", boxShadow: "0 10px 30px rgba(0,0,0,0.1)", fontFamily, border: "1px solid #CBD5E1", animation: "phase6_fadein 0.5s" }}>
                      <div style={{ borderBottom: "1px solid #E2E8F0", paddingBottom: "10px", marginBottom: "30px", fontSize: "11px", color: "#64748B", display: "flex", justifyContent: "space-between", textTransform: "uppercase", letterSpacing: "1px", fontFamily: "Arial, sans-serif" }}>
                        <span>DYNAMITE DYNASTY ENGINE</span>
                        <span>RESTRICTED ACCESS</span>
                      </div>

                      {streamBlocks
                        .map((b, idx) => ({ ...b, idx }))
                        .filter((b) => b.pageIndex === pageIndex)
                        .map((b) => {
                          const past = b.idx < streamIndex || phase === "done"
                          const current = b.idx === streamIndex && phase !== "done"
                          if (!past && !current) return null

                          if (b.type === "title") {
                            const text = past ? b.text : b.text.slice(0, streamChar)
                            return (
                              <h2 key={b.idx} id={current ? "phase6-active-typing-block" : undefined} style={{ fontSize: "26px", marginBottom: "24px", lineHeight: "1.3", color: "#0F172A", borderBottom: "2px solid #F1F5F9", paddingBottom: "10px" }}>
                                {text}
                                {current ? <span style={{ animation: "phase6_blink 0.8s infinite", borderRight: "2px solid #0284C7" }} /> : null}
                              </h2>
                            )
                          }

                          if (b.type === "paragraph") {
                            const text = past ? b.text : b.text.slice(0, streamChar)
                            return (
                              <p key={b.idx} id={current ? "phase6-active-typing-block" : undefined} style={{ lineHeight: "1.8", marginBottom: "16px", fontSize: "14px", textAlign: "justify", color: "#334155" }}>
                                {text}
                                {current ? <span style={{ animation: "phase6_blink 0.8s infinite", borderRight: "2px solid #0284C7" }} /> : null}
                              </p>
                            )
                          }

                          if (b.type === "chart") {
                            const chart = b.chart
                            const isRecharts = chart?.data && chart.data.length > 0
                            const colors = palette.colors

                            return (
                              <div key={b.idx} id={current ? "phase6-active-typing-block" : undefined} style={{ border: "1px solid #E2E8F0", padding: "20px", borderRadius: "8px", margin: "25px 0", background: palette.bg, animation: "phase6_fadein 0.5s", height: "400px", width: "100%" }}>
                                {isRecharts ? (
                                  <ResponsiveContainer width="100%" height="100%">
                                    {chart.type === "pie" ? (
                                      (() => {
                                        const proc = [...(chart.data || [])].sort((a, b2) => b2.value - a.value)
                                        const othIdx = proc.findIndex((d) => String(d.name).toLowerCase() === "other")
                                        if (othIdx !== -1) proc.push(proc.splice(othIdx, 1)[0])
                                        const total = proc.reduce((sum, item) => sum + item.value, 0) || 1
                                        return (
                                          <PieChart>
                                            <Tooltip
                                              contentStyle={{ backgroundColor: palette.bg, color: palette.text, borderRadius: "8px", border: `1px solid ${palette.grid}` }}
                                              formatter={(value, name) => [`${value} (${((Number(value) / total) * 100).toFixed(1)}%)`, name]}
                                            />
                                            <Legend verticalAlign="bottom" height={36} wrapperStyle={{ fontSize: "12px", fontWeight: "bold", color: palette.text }} iconType="circle" />
                                            <Pie
                                              data={proc}
                                              dataKey="value"
                                              nameKey="name"
                                              cx="50%"
                                              cy="50%"
                                              outerRadius={140}
                                              startAngle={220}
                                              endAngle={-140}
                                              stroke={palette.bg}
                                              strokeWidth={2}
                                              labelLine={false}
                                              label={renderCustomLabel}
                                              {...({
                                                activeIndex: pieActiveIdx,
                                                activeShape: renderActiveShape,
                                                onMouseEnter: (_: any, index: number) => setPieActiveIdx(index),
                                                onMouseLeave: () => setPieActiveIdx(undefined),
                                              } as any)}
                                            >
                                              {proc.map((_, index) => (
                                                <Cell key={`cell-${index}`} fill={colors[index % colors.length]} style={{ outline: "none", cursor: "pointer" }} />
                                              ))}
                                            </Pie>
                                          </PieChart>
                                        )
                                      })()
                                    ) : chart.type === "line" ? (
                                      <LineChart data={chart.data}>
                                        <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} />
                                        <XAxis dataKey="name" stroke="#64748B" fontSize={12} />
                                        <YAxis stroke="#64748B" fontSize={12} />
                                        <Tooltip contentStyle={{ backgroundColor: palette.bg, color: palette.text, borderRadius: "8px", border: `1px solid ${palette.grid}` }} />
                                        <Line type="monotone" dataKey="value" stroke={colors[0]} strokeWidth={3} dot={{ r: 4 }} activeDot={{ r: 8 }} />
                                      </LineChart>
                                    ) : chart.type === "horizontal_bar" ? (
                                      <BarChart data={chart.data} layout="vertical">
                                        <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} horizontal vertical={false} />
                                        <XAxis type="number" stroke="#64748B" fontSize={12} />
                                        <YAxis dataKey="name" type="category" stroke="#64748B" fontSize={10} width={120} />
                                        <Tooltip cursor={{ fill: "rgba(0,0,0,0.05)" }} contentStyle={{ backgroundColor: palette.bg, color: palette.text, borderRadius: "8px", border: `1px solid ${palette.grid}` }} />
                                        <Bar dataKey="value" fill={colors[1]} radius={[0, 4, 4, 0]}>
                                          {chart.data?.map((_, index) => <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />)}
                                        </Bar>
                                      </BarChart>
                                    ) : (
                                      <BarChart data={chart.data}>
                                        <CartesianGrid strokeDasharray="3 3" stroke={palette.grid} vertical={false} />
                                        <XAxis dataKey="name" stroke="#64748B" fontSize={10} angle={-35} textAnchor="end" height={60} />
                                        <YAxis stroke="#64748B" fontSize={12} />
                                        <Tooltip cursor={{ fill: "rgba(0,0,0,0.05)" }} contentStyle={{ backgroundColor: palette.bg, color: palette.text, borderRadius: "8px", border: `1px solid ${palette.grid}` }} />
                                        <Bar dataKey="value" fill={colors[0]} radius={[4, 4, 0, 0]}>
                                          {chart.data?.map((_, index) => <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />)}
                                        </Bar>
                                      </BarChart>
                                    )}
                                  </ResponsiveContainer>
                                ) : chart?.b64 ? (
                                  <img src={`data:image/png;base64,${chart.b64}`} alt="chart" style={{ width: "100%", height: "100%", objectFit: "contain" }} />
                                ) : null}
                              </div>
                            )
                          }

                          if (b.type === "table") {
                            const tb = b.table
                            return (
                              <div key={b.idx} id={current ? "phase6-active-typing-block" : undefined} style={{ margin: "25px 0", overflowX: "auto", animation: "phase6_fadein 0.5s" }}>
                                <div style={{ fontWeight: "bold", marginBottom: "12px", color: "#0F172A", fontSize: "15px" }}>{tb?.title}</div>
                                <table className={`phase6-table-${tableStyle}`}>
                                  <thead>
                                    <tr>{(tb?.columns || []).map((col, k) => <th key={k}>{col}</th>)}</tr>
                                  </thead>
                                  <tbody>
                                    {(tb?.rows || []).map((row, k) => (
                                      <tr key={k} title={`Entity Data for: ${row[0]}\nThis row represents correlated telemetry extracted by the core engine.`}>
                                        {row.map((cell, m) => <td key={m}>{cell}</td>)}
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )
                          }

                          if (b.type === "list") {
                            const ls = b.list
                            return (
                              <div key={b.idx} id={current ? "phase6-active-typing-block" : undefined} style={{ margin: "20px 0", animation: "phase6_fadein 0.5s" }}>
                                <div style={{ fontWeight: "bold", marginBottom: "10px", color: "#0F172A", fontSize: "15px" }}>{ls?.title}</div>
                                <ul style={{ paddingLeft: "20px" }}>{(ls?.items || []).map((item, k) => <li key={k} style={{ marginBottom: "8px", color: "#334155", lineHeight: "1.6" }}>{item}</li>)}</ul>
                              </div>
                            )
                          }

                          return null
                        })}

                      <div style={{ borderTop: "1px solid #E2E8F0", paddingTop: "10px", marginTop: "40px", fontSize: "11px", color: "#64748B", textAlign: "center", fontFamily: "Arial, sans-serif" }}>
                        Page {pageIndex + 1}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}

            {phase === "compiling" && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", width: "100%" }}>
                <div style={{ padding: "80px", textAlign: "center", background: "#FFFFFF", borderRadius: "12px", boxShadow: "0 10px 40px rgba(0,0,0,0.08)", border: "1px solid #E2E8F0" }}>
                  <div style={{ width: "60px", height: "60px", border: "5px solid #F1F5F9", borderTop: "5px solid #0284C7", borderRadius: "50%", margin: "0 auto 25px auto", animation: "phase6_spin 1s linear infinite" }} />
                  <h2 style={{ color: "#0F172A", marginBottom: "15px", fontSize: "24px" }}>Compiling Enterprise Dossier</h2>
                  <p style={{ color: "#64748B", fontSize: "15px", fontWeight: "bold" }}>Applying visual assets, layouts, and sealing the immutable ledger.</p>
                </div>
              </div>
            )}

            {phase === "done" && viewMode === "pdf" && pdfUrl && (
              <div style={{ width: "100%", maxWidth: "1000px", animation: "phase6_fadein 0.5s" }}>
                <iframe src={`${pdfUrl}#toolbar=0&navpanes=0&scrollbar=0&view=FitH`} style={{ width: "100%", height: "80vh", border: "1px solid #CBD5E1", borderRadius: "8px", background: "#F8FAFC", boxShadow: "0 10px 40px rgba(0,0,0,0.15)" }} />
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ width: "320px", backgroundColor: "#FFFFFF", borderLeft: "1px solid #E2E8F0", display: "flex", flexDirection: "column", padding: "30px", boxShadow: "-2px 0 10px rgba(0,0,0,0.02)", zIndex: 10 }}>
        <h3 style={{ fontSize: "16px", color: "#0F172A", marginBottom: "25px", borderBottom: "1px solid #E2E8F0", paddingBottom: "15px" }}>Generation Insights</h3>

        <div style={{ display: "flex", flexWrap: "wrap", gap: "15px", marginBottom: "40px" }}>
          <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
            <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Word Count</div>
            <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{phase === "writing" ? Math.floor(streamIndex * 15.5) : phase === "done" ? Math.floor(streamBlocks.length * 15.5) : 0}</div>
          </div>
          <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
            <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Pages Drafted</div>
            <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{phase === "done" ? totalActualPages : phase === "compiling" ? Math.max(1, totalActualPages - 2) : phase === "writing" ? Math.min(totalActualPages, Math.ceil(streamIndex / 8)) : 0}</div>
          </div>
          <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
            <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Visuals</div>
            <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{streamIndex > 25 ? selectedGraphs.length : streamIndex > 15 ? Math.min(2, selectedGraphs.length) : 0}</div>
          </div>
          <div style={{ width: "calc(50% - 7.5px)", backgroundColor: "#F8FAFC", padding: "15px", borderRadius: "8px", border: "1px solid #E2E8F0" }}>
            <div style={{ color: "#64748B", fontSize: "12px", marginBottom: "5px", fontWeight: "bold" }}>Sources</div>
            <div style={{ color: "#0284C7", fontSize: "24px", fontWeight: "bold" }}>{phase !== "idle" ? 19 : 0}</div>
          </div>
        </div>

        <h3 style={{ fontSize: "13px", color: "#64748B", marginBottom: "20px", textTransform: "uppercase", letterSpacing: "1px", fontWeight: "bold" }}>Live Activity Log</h3>
        <div style={{ flexGrow: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "15px", fontSize: "13px", color: "#334155", fontWeight: "bold" }}>
          {phase !== "idle" && <div style={{ display: "flex", gap: "10px", animation: "phase6_fadein 0.3s" }}><span style={{ color: "#0284C7" }}>•</span> Structuring Executive Summary...</div>}
          {streamIndex > 5 && <div style={{ display: "flex", gap: "10px", animation: "phase6_fadein 0.3s" }}><span style={{ color: "#0284C7" }}>•</span> Formatting Telemetry Data...</div>}
          {streamIndex > 12 && <div style={{ display: "flex", gap: "10px", animation: "phase6_fadein 0.3s" }}><span style={{ color: "#10B981" }}>•</span> Rendering Data Visualizations...</div>}
          {streamIndex > 20 && <div style={{ display: "flex", gap: "10px", animation: "phase6_fadein 0.3s" }}><span style={{ color: "#10B981" }}>•</span> Parsing Anomaly Threat Metrics...</div>}
          {phase === "compiling" || phase === "done" ? (
            <div style={{ display: "flex", gap: "10px", animation: "phase6_fadein 0.3s" }}><span style={{ color: "#F59E0B" }}>•</span> Compiling remaining {totalActualPages > 5 ? totalActualPages - 5 : 0} pages...</div>
          ) : null}
          {phase === "done" && <div style={{ display: "flex", gap: "10px", animation: "phase6_fadein 0.3s" }}><span style={{ color: "#10B981" }}>•</span> Official PDF payload packaged successfully.</div>}
        </div>
      </div>
    </div>
  )
}
