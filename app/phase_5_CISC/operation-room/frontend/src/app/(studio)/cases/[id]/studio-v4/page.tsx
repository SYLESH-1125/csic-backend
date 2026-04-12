'use client'

import { api } from '@/lib/api'
import type { Editor } from '@tiptap/core'
import dynamic from 'next/dynamic'
import { useParams, useRouter } from 'next/navigation'
import React, { memo, useCallback, useEffect, useRef, useState } from 'react'

// V4 Canva-style Layout
import { CanvaLayout, DocumentCanvas, useStudioStore } from '@/components/studio-v4'
import { EditorProvider } from '@/components/studio-v4/context/EditorContext'
import { ExportPreviewModal } from '@/components/studio-v4/dialogs/ExportPreviewModal'
import { GhostWriterWizard } from '@/components/studio-v4/dialogs/GhostWriterWizard'
import { InvestigationConfig, InvestigationConfigDialog } from '@/components/studio-v4/dialogs/InvestigationConfigDialog'
import { ReportPreviewPanel } from '@/components/studio-v4/dialogs/ReportPreviewPanel'
import { ChartInspector } from '@/components/studio-v4/toolbar/ChartInspector'
import { MASTER_TEMPLATES } from '@/lib/templates'

// Investigation hook
import { useInvestigationStream } from '@/hooks/useInvestigationStream'

// TipTap Editor
import type { ReportEditorRef } from '@/components/tiptap/ReportEditorV2'
import { Loader2, WifiOff, X } from 'lucide-react'

// Lazy-load TipTap editor
const ReportEditorV2 = dynamic(
  () => import('@/components/tiptap/ReportEditorV2').then(mod => mod.ReportEditorV2),
  {
    ssr: false,
    loading: () => (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }
)

const DEFAULT_AST = {
  type: 'doc',
  content: [
    {
      type: 'heading',
      attrs: { level: 1 },
      content: [{ type: 'text', text: 'Investigation Report' }],
    },
    {
      type: 'paragraph',
      content: [{ type: 'text', text: 'Begin your analysis here...' }],
    },
  ],
}

const resolveApiOrigin = (): string => {
  const configured = process.env.NEXT_PUBLIC_API_URL?.replace(/\/api\/?$/, '').replace(/\/+$/, '')
  if (configured) {
    return configured
  }
  if (typeof window !== 'undefined') {
    return window.location.origin
  }
  return ''
}

type EditorContent = Record<string, unknown>
type StudioModuleSource = 'timeline' | 'anomaly' | 'correlation' | 'crud' | 'network' | 'depth' | 'case'
type InsertComponentConfig = Record<string, unknown> & {
  module?: string
  dataEndpoint?: string
}
type InsertFindingInput = {
  title: string
  content: string
  source: string
}

const isEditorContent = (value: unknown): value is EditorContent => {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

const MODULE_SOURCES: StudioModuleSource[] = ['timeline', 'anomaly', 'correlation', 'crud', 'network', 'depth', 'case']

const normalizeModuleSource = (value: unknown): StudioModuleSource => {
  if (typeof value !== 'string') return 'case'
  const normalized = value.toLowerCase()
  return MODULE_SOURCES.includes(normalized as StudioModuleSource)
    ? (normalized as StudioModuleSource)
    : 'case'
}

const normalizeEndpointPath = (path?: string) => {
  if (!path) return undefined
  return path.startsWith('/api/') ? path.slice(4) : path
}

const prettifyComponentId = (componentId: string) => {
  return componentId
    .split('-')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

const hashString = (value: string) => {
  let hash = 0
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(i)
    hash |= 0
  }
  return Math.abs(hash).toString(16)
}

// ── Offline Toast Banner ─────────────────────────────────────────────────
const OfflineBanner = memo(({ onDismiss, onRetry }: { onDismiss: () => void; onRetry: () => void }) => (
  <div className="fixed top-2 left-1/2 -translate-x-1/2 z-[100] flex items-center gap-3 px-4 py-2.5 rounded-xl bg-amber-950/90 text-amber-200 text-xs font-medium shadow-2xl backdrop-blur-xl border border-amber-800/50 animate-in slide-in-from-top-4 duration-300">
    <WifiOff className="h-3.5 w-3.5 flex-shrink-0" />
    <span>Working offline — changes saved locally. Reconnecting…</span>
    <button onClick={onRetry} className="underline underline-offset-2 hover:text-white transition-colors">Retry</button>
    <button onClick={onDismiss} className="ml-1 hover:text-white transition-colors"><X className="h-3 w-3" /></button>
  </div>
))
OfflineBanner.displayName = 'OfflineBanner'

// ── Memoised Editor Wrapper ──────────────────────────────────────────────
const MemoEditor = memo(ReportEditorV2)

export default function StudioV4Page() {
  const params = useParams()
  const router = useRouter()
  const caseId = params.id as string
  const apiOrigin = resolveApiOrigin()

  const {
    zoom,
    setDocument,
    setSaving,
    setLastSaved,
    hasChanges,
    setHasChanges,
    documentTitle,
    setActivePanel,
    setInvestigationRunning,
    setInvestigationProgress,
  } = useStudioStore()

  const editorRef = useRef<ReportEditorRef | null>(null)
  const [tipTapEditor, setTipTapEditor] = useState<Editor | null>(null)

  // Investigation hook
  const investigation = useInvestigationStream()

  // Investigation dialog state
  const [investigationDialogOpen, setInvestigationDialogOpen] = useState(false)

  // Document state
  const [documentId, setDocumentId] = useState<string | null>(null)
  const [initialContent, setInitialContent] = useState<EditorContent>(DEFAULT_AST)
  const [loading, setLoading] = useState(true)
  const [isOffline, setIsOffline] = useState(false)
  const [showOfflineBanner, setShowOfflineBanner] = useState(false)

  // Fatal error boundary state
  const [fatalError, setFatalError] = useState<Error | null>(null)
  const [fatalInfo, setFatalInfo] = useState<string | null>(null)

  // Export gate dialog state
  const [exportDialogOpen, setExportDialogOpen] = useState(false)
  const [previewModalOpen, setPreviewModalOpen] = useState(false)
  const [reportPreviewOpen, setReportPreviewOpen] = useState(false)
  const [exportEngine, setExportEngine] = useState<'standard' | 'dynamite'>('standard')
  const [exportFormat, setExportFormat] = useState<'pdf' | 'docx'>('pdf')

  // Debounced save ref
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Update TipTap editor reference when available
  useEffect(() => {
    if (editorRef.current) {
      const editor = editorRef.current.getEditor()
      if (editor && editor !== tipTapEditor) {
        setTipTapEditor(editor)
      }
    }
  }, [loading, tipTapEditor])

  // ── Load or create document (with graceful offline fallback) ────────────
  const attemptLoad = useCallback(async () => {
    try {
      const docsResponse = await api.get(`/v4/studio/cases/${caseId}/docs`)
      const docs = Array.isArray(docsResponse) ? docsResponse : docsResponse?.documents || []

      if (docs && Array.isArray(docs) && docs.length > 0) {
        const doc = docs[0]
        setDocumentId(doc.doc_id)
        setDocument(caseId, doc.doc_id, doc.title || 'Untitled Report')

        const fullDoc = await api.get(`/v4/studio/cases/${caseId}/docs/${doc.doc_id}`)
        if (fullDoc?.ast?.type === 'v4-canvas' && Array.isArray(fullDoc.ast.pages)) {
          useStudioStore.getState().setPages(fullDoc.ast.pages)
        } else if (isEditorContent(fullDoc?.ast)) {
          setInitialContent(fullDoc.ast)
        } else if (isEditorContent(fullDoc?.content)) {
          setInitialContent(fullDoc.content)
        }
      } else {
        const newDoc = await api.post(`/v4/studio/cases/${caseId}/docs`, {
          title: 'New Investigation Report',
          template: 'technical',
        })

        if (newDoc?.doc_id) {
          setDocumentId(newDoc.doc_id)
          setDocument(caseId, newDoc.doc_id, newDoc.title || 'New Investigation Report')
          if (newDoc?.ast?.type === 'v4-canvas' && Array.isArray(newDoc.ast.pages)) {
            useStudioStore.getState().setPages(newDoc.ast.pages)
          } else {
            setInitialContent(
              isEditorContent(newDoc.ast) ? newDoc.ast
                : isEditorContent(newDoc.content) ? newDoc.content
                  : DEFAULT_AST
            )
          }
        }
      }
      // Successful — clear offline state
      setIsOffline(false)
      setShowOfflineBanner(false)
      return true
    } catch (err) {
      console.warn('[Studio] API unreachable, entering offline mode:', err)
      return false
    }
  }, [caseId, setDocument])

  useEffect(() => {
    const loadDocument = async () => {
      setLoading(true)
      const success = await attemptLoad()
      if (!success) {
        // Offline fallback — let the investigator type freely
        const localId = `local-${crypto.randomUUID()}`
        setDocumentId(localId)
        setDocument(caseId, localId, 'Untitled Report (Offline)')
        setInitialContent(DEFAULT_AST)
        setIsOffline(true)
        setShowOfflineBanner(true)
      }
      setLoading(false)
    }
    loadDocument()
  }, [caseId, attemptLoad, setDocument])

  // ── Background retry loop when offline ────────────────────────────────
  useEffect(() => {
    if (!isOffline) return
    const interval = setInterval(async () => {
      const success = await attemptLoad()
      if (success) {
        clearInterval(interval)
      }
    }, 12000)
    return () => clearInterval(interval)
  }, [isOffline, attemptLoad])

  // ── Save handler ──────────────────────────────────────────────────────
  const handleSave = useCallback(async () => {
    if (!documentId || documentId.startsWith('local-')) {
      throw new Error('Offline document cannot be saved to server')
    }

    try {
      setSaving(true)
      // Serialize the V4 Canvas Layout instead of default TipTap AST
      const pages = useStudioStore.getState().pages;
      const ast = {
        type: 'v4-canvas',
        version: '1.0',
        pages: pages,
      }

      await api.put(`/v4/studio/cases/${caseId}/docs/${documentId}`, {
        title: documentTitle,
        ast,
        change_summary: 'Autosave from Studio V4',
      })

      setLastSaved(new Date())
      setHasChanges(false)
    } catch (err) {
      console.error('Failed to save:', err)
      throw err
    } finally {
      setSaving(false)
    }
  }, [caseId, documentId, documentTitle, setSaving, setLastSaved, setHasChanges])

  // ── Debounced content change → autosave ───────────────────────────────
  const handleContentChange = useCallback(() => {
    // Only mark dirty after debounce to avoid re-rendering the layout on every keystroke
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
    saveTimerRef.current = setTimeout(() => {
      setHasChanges(true)
    }, 800)
  }, [setHasChanges])

  useEffect(() => {
    return () => { if (saveTimerRef.current) clearTimeout(saveTimerRef.current) }
  }, [])

  // Navigation handlers
  const handleBack = useCallback(() => {
    router.push(`/cases/${caseId}`)
  }, [router, caseId])

  const handleExport = useCallback(async () => {
    if (documentId?.startsWith('local-')) {
      setReportPreviewOpen(true)
      return
    }
    // Auto-save before export to ensure latest changes are included
    // This is a TRANSACTIONAL requirement: export MUST include current state
    if (hasChanges && documentId && !documentId.startsWith('local-')) {
      try {
        await handleSave()
      } catch (err) {
        console.error('Failed to save before export:', err)
        // FAIL HARD: Do NOT export stale state
        alert('Cannot export: Failed to save current changes. Please try saving manually first.')
        return
      }
    }
    // Show preview panel first, then proceed to export
    setReportPreviewOpen(true)
  }, [hasChanges, documentId, handleSave])

  const handleExportFromPreview = useCallback(async (format: 'pdf' | 'docx') => {
    if (documentId && !documentId.startsWith('local-')) {
      try {
        const precheck = await api.post(`/v4/studio/cases/${caseId}/exports/precheck`, { doc_id: documentId })
        if (precheck?.blocked) {
          const count = Array.isArray(precheck.violations) ? precheck.violations.length : 0
          alert(`Export blocked by governance precheck: ${count} critical uncited evidence block(s).`)
          return
        }
      } catch (err) {
        console.error('Export precheck failed:', err)
        alert('Cannot export: precheck failed. Please retry.')
        return
      }
    }
    setExportFormat(format)
    setReportPreviewOpen(false)
    setPreviewModalOpen(true)
  }, [caseId, documentId])

  const handleShare = useCallback(() => {
    console.log('Share clicked')
  }, [])

  // Investigation handlers
  const handleInvestigate = useCallback(() => {
    setInvestigationDialogOpen(true)
  }, [])

  const handleStartInvestigation = useCallback(async (config: InvestigationConfig) => {
    setInvestigationDialogOpen(false)
    setInvestigationRunning(true)
    setInvestigationProgress(0)

    try {
      await investigation.startInvestigation({
        caseId: config.caseId,
        scenario: config.scenario,
        objectives: config.objectives,
        modules: config.modules,
        hypotheses: config.hypotheses,
        options: config.options,
      })
    } catch (error) {
      console.error('Failed to start investigation:', error)
      setInvestigationRunning(false)
      setInvestigationProgress(0)
    }
  }, [investigation, setInvestigationRunning, setInvestigationProgress])

  const handleStopInvestigation = useCallback(() => {
    investigation.stopInvestigation()
    setInvestigationRunning(false)
    setInvestigationProgress(0)
  }, [investigation, setInvestigationRunning, setInvestigationProgress])

  // Sync investigation progress with store
  useEffect(() => {
    setInvestigationProgress(Math.max(0, Math.min(100, investigation.progress)))
    setInvestigationRunning(investigation.isRunning)
  }, [investigation.progress, investigation.isRunning, setInvestigationProgress, setInvestigationRunning])

  useEffect(() => {
    if (investigation.errors.length === 0) return
    const latestError = investigation.errors[investigation.errors.length - 1]
    setInvestigationRunning(false)
    alert(`Investigation error: ${latestError}`)
  }, [investigation.errors, setInvestigationRunning])

  // Add findings to canvas as they stream in
  useEffect(() => {
    if (investigation.findings.length === 0) return

    const lastFinding = investigation.findings[investigation.findings.length - 1]
    const { currentPage } = useStudioStore.getState()

    // Auto-add finding cards to canvas
    if (lastFinding.type === 'hypothesis' || lastFinding.type === 'hypothesis_verdict') {
      useStudioStore.getState().addElement(currentPage, {
        type: 'component',
        x: 40,
        y: 40 + (investigation.findings.length * 140),
        width: 720,
        height: 120,
        data: {
          type: 'hypothesis-card',
          module: 'hypothesis',
          componentId: 'HypothesisCard',
          data: lastFinding.data,
        },
      })
      setHasChanges(true)
    }
  }, [investigation.findings, setHasChanges])

  const getNextFigureNumber = useCallback(() => {
    const editor = editorRef.current?.getEditor()
    if (!editor) return 1

    let evidenceBlockCount = 0
    editor.state.doc.descendants((node) => {
      if (node.type.name === 'evidenceBlock') {
        evidenceBlockCount += 1
      }
    })

    return evidenceBlockCount + 1
  }, [])

  const fetchInsertData = useCallback(async (source: StudioModuleSource, config?: InsertComponentConfig) => {
    const endpointPath = normalizeEndpointPath(typeof config?.dataEndpoint === 'string' ? config.dataEndpoint : undefined)

    const fetchEndpoint = endpointPath
      ? api.get(endpointPath).catch(() => null)
      : Promise.resolve(null)

    if (source === 'timeline') {
      const [endpointData, events, fallbackStats] = await Promise.all([
        fetchEndpoint,
        api.get(`/cases/${caseId}/timeline?limit=50`).catch(() => []),
        !endpointPath ? api.get(`/cases/${caseId}/timeline/stats`).catch(() => null) : Promise.resolve(null)
      ])
      return {
        endpointPath,
        endpointData: endpointData || fallbackStats,
        timelineEvents: events && Array.isArray(events.clusters) ? events.clusters : (Array.isArray(events) ? events : []), /* handles both legacy and cluster payloads */
      }
    }

    if (source === 'anomaly') {
      const [endpointData, fallbackSummary] = await Promise.all([
        fetchEndpoint,
        !endpointPath ? api.get(`/cases/${caseId}/anomalies/summary`).catch(() => null) : Promise.resolve(null)
      ])
      return { endpointPath, endpointData: endpointData || fallbackSummary }
    }

    const endpointData = await fetchEndpoint
    return { endpointPath, endpointData }
  }, [caseId])

  const fetchComponentData = useCallback(async (componentId: string, config?: Record<string, unknown>) => {

    const typedConfig = (config || {}) as InsertComponentConfig
    const source = normalizeModuleSource(typedConfig.module)
    const figureNumber = getNextFigureNumber()
    const title = prettifyComponentId(componentId)
    const citationId = `[EVD-${source.toUpperCase()}-${String(figureNumber).padStart(3, '0')}]`

    const { endpointPath, endpointData, timelineEvents } = await fetchInsertData(source, typedConfig)
    const lowerId = componentId.toLowerCase()

    let type: 'chart' | 'table' | 'metric' | 'finding' | 'timeline-event' | 'anomaly' | 'network-flow' | 'shap-explanation' | 'correlation-graph' = 'chart'

    if (lowerId.includes('shap')) {
      type = 'shap-explanation'
    } else if (lowerId === 'timeline-vertical-list' || lowerId === 'timeline-single-event') {
      type = 'timeline-event'
    } else if (lowerId.includes('network')) {
      type = 'network-flow'
    } else if (lowerId.includes('correlation')) {
      type = 'correlation-graph'
    } else if (lowerId.includes('stats') || lowerId.includes('metric')) {
      type = 'metric'
    } else if (lowerId.includes('table') || lowerId.includes('list') || lowerId.includes('manifest')) {
      type = 'table'
    }

    let data: Record<string, unknown> = {
      type: type,  // Add explicit type for PDF dispatch
      componentType: type,  // Add componentType for widget renderers
      chartType: componentId,
      sourceModule: source,
      summary: endpointData || {},
    }

    if (source === 'timeline' || lowerId.includes('timeline') || lowerId.includes('swimlane')) {
      data.clusters = Array.isArray(timelineEvents) ? timelineEvents : []
    }

    if (type === 'timeline-event') {
      const chartType = lowerId.includes('swimlane') ? 'swimlane' : 'timeline'
      data = {
        ...data,
        type: 'timeline-event',
        componentType: 'timeline-event',
        chartType: chartType,
      }
    } else if (type === 'shap-explanation') {
      const summary = (endpointData as Record<string, any>) || {}
      const shapFeatures = Array.isArray(summary.shap_global_importance)
        ? summary.shap_global_importance
        : []
      const chartType = lowerId.includes('waterfall') ? 'waterfall' : 'importance'
      data = {
        type: 'shap-explanation',
        componentType: 'shap-explanation',
        chartType: chartType,
        features: shapFeatures.map((feature: Record<string, unknown>) => ({
          feature: feature.feature || feature.name || 'feature',
          contribution: feature.importance || feature.importance_pct || 0,
          value: feature.importance || feature.importance_pct || 0,
        })),
        prediction: summary?.score_stats?.p95 || 0,
        base_value: summary?.score_stats?.mean || 0,
      }
    } else if (type === 'metric') {
      const summary = (endpointData as Record<string, any>) || {}
      const value = source === 'timeline'
        ? summary.total_events || 0
        : source === 'anomaly'
          ? summary.anomaly_count || 0
          : summary.count || 0
      data = {
        type: 'metric',
        componentType: 'metric',
        value,
        unit: 'events',
        description: `${title} from ${source} analysis`,
      }
    } else if (type === 'table') {
      const payload = (endpointData as Record<string, any>) || {}
      const rowSource = Array.isArray(payload.top_anomalies)
        ? payload.top_anomalies
        : Array.isArray(payload.events)
          ? payload.events
          : Array.isArray(endpointData)
            ? endpointData
            : []

      const columns = rowSource[0]
        ? Object.keys(rowSource[0]).slice(0, 8)
        : ['field', 'value']

      const rows = rowSource.slice(0, 25).map((row: Record<string, unknown>) => (
        columns.map((column) => row[column])
      ))

      data = {
        type: 'table',
        componentType: 'table',
        columns,
        rows,
        summary: `${rows.length} rows captured from ${source}`,
      }
    } else if (type === 'network-flow') {
      const payload = endpointData as Record<string, unknown> | unknown[] | null
      const flows = Array.isArray(payload)
        ? payload
        : Array.isArray((payload as Record<string, unknown>)?.flows)
          ? ((payload as Record<string, unknown>).flows as unknown[])
          : []
      data = {
        type: 'network-flow',
        componentType: 'network-flow',
        flows,
        stats: payload || {},
      }
    } else if (type === 'correlation-graph') {
      const payload = (endpointData as Record<string, any>) || {}
      data = {
        nodes: Array.isArray(payload.nodes) ? payload.nodes : [],
        edges: Array.isArray(payload.edges) ? payload.edges : [],
        summary: payload,
      }
    }

    const configHash = `cfg:${hashString(JSON.stringify({ componentId, source, data }).slice(0, 3000))}`

    return {
      id: `evd-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      type,
      source,
      title,
      caption: `${title} inserted from ${source} module`,
      figureNumber,
      data,
      metadata: {
        timestamp: new Date().toISOString(),
        citationId,
        insertionActor: 'investigator',
        sourceQuery: endpointPath || componentId,
        sourceVersion: 1,
        configHash,
        verified: false,
      },
    }
  }, [caseId, getNextFigureNumber, fetchInsertData])


  const handleDropCanvasComponent = useCallback(async (pageIndex: number, componentId: string, x: number, y: number, payload: any) => {
    if (payload.type === 'text-block') {
      const blockType = typeof payload.content === 'string' ? payload.content : 'paragraph'
      const blockName = blockType === 'heading' ? 'Heading' : 'New text block'

      useStudioStore.getState().addElement(pageIndex, {
        type: 'text',
        x: x - 200,
        y: y - 50,
        width: 400,
        height: 100,
        data: {
          textType: blockType,
          content: blockType === 'heading' ? blockName : 'Start typing...',
          style: blockType,
        }
      })
      useStudioStore.getState().setHasChanges(true)
      return
    }

    if (payload.type === 'entity' && payload.data) {
      const entity = payload.data
      const isCorrelation = typeof entity.primary_entity === 'string' && typeof entity.related_entity === 'string'
      const source: StudioModuleSource = isCorrelation ? 'correlation' : 'network'
      if (isCorrelation) {
        useStudioStore.getState().addElement(pageIndex, {
          type: 'component', x: x - 250, y: y - 150, width: 500, height: 300, data: { type: 'correlation-graph', source, title: 'Correlation Link', data: { nodes: [{ id: entity.primary_entity, label: entity.primary_entity, kind: entity.primary_type || 'primary' }, { id: entity.related_entity, label: entity.related_entity, kind: entity.related_type || 'related' }], edges: [{ source: entity.primary_entity, target: entity.related_entity, type: entity.relationship_type || 'linked', confidence: entity.confidence_score || 0 }], central_entity: entity.primary_entity } }
        })
      } else {
        useStudioStore.getState().addElement(pageIndex, {
          type: 'component', x: x - 250, y: y - 150, width: 500, height: 300, data: { type: 'network-flow', source, title: 'Network Entity', data: { src_ip: entity.ip_address || 'unknown', dst_ip: entity.domain || 'unknown', bytes: entity.bytes_transferred || 0, packets: entity.connections_count || 0, protocol: entity.entity_type || 'network', direction: 'outbound' } }
        })
      }
      useStudioStore.getState().setHasChanges(true)
      return
    }

    if (payload.type === 'finding' && payload.data) {
      const finding = payload.data
      const source = normalizeModuleSource(finding.source)
      useStudioStore.getState().addElement(pageIndex, {
        type: 'component', x: x - 200, y: y - 100, width: 400, height: 200, data: { type: 'finding', chartType: 'finding', componentType: 'finding', source, title: finding.title, summary: { severity: 'medium', summary: finding.content, details: finding.content } }
      })
      useStudioStore.getState().setHasChanges(true)
      return
    }

    if (payload.type === 'canvas-element' || payload.type === 'annotation') {
      const name = typeof payload.elementId === 'string' ? payload.elementId : 'Element'
      useStudioStore.getState().addElement(pageIndex, {
        type: 'shape', x: x - 50, y: y - 50, width: 100, height: 100, data: { name }
      })
      useStudioStore.getState().setHasChanges(true)
      return
    }

    if (payload.type === 'upload') {
      const name = typeof payload.fileId === 'string' ? payload.fileId : 'Upload'
      const url = typeof payload.url === 'string' ? payload.url : ''
      useStudioStore.getState().addElement(pageIndex, {
        type: 'image', x: x - 150, y: y - 100, width: 300, height: 200, data: { name, url }
      })
      useStudioStore.getState().setHasChanges(true)
      return
    }

    const blockData = await fetchComponentData(componentId, payload)

    // Add to absolute-positioned freeform canvas
    useStudioStore.getState().addElement(pageIndex, {
      type: 'component',
      x: x - 200, // Center relative to cursor
      y: y - 100,
      width: 400,
      height: 300,
      data: blockData
    })

    useStudioStore.getState().setHasChanges(true)
  }, [fetchComponentData])
  // Legacy handler for clicking side-panel buttons without drag-and-drop
  const handleInsertComponent = useCallback(async (componentId: string, config?: Record<string, unknown>) => {
    const blockData = await fetchComponentData(componentId, config)
    const { currentPage } = useStudioStore.getState()

    // Default to center of page roughly
    useStudioStore.getState().addElement(currentPage, {
      type: 'component',
      x: 100,
      y: 100,
      width: 400,
      height: 300,
      data: blockData
    })

    useStudioStore.getState().setActivePanel(null)
    useStudioStore.getState().setHasChanges(true)
  }, [fetchComponentData])

  const handleInsertFinding = useCallback((finding: InsertFindingInput) => {
    const source = normalizeModuleSource(finding.source)
    const { currentPage } = useStudioStore.getState()
    useStudioStore.getState().addElement(currentPage, {
      type: 'component', x: 100, y: 100, width: 400, height: 200, data: { type: 'finding', chartType: 'finding', componentType: 'finding', source, title: finding.title, summary: { severity: 'medium', summary: finding.content, details: finding.content } }
    })
    useStudioStore.getState().setHasChanges(true)
    useStudioStore.getState().setActivePanel(null)
  }, [])

  const handleInsertEntity = useCallback((entity: Record<string, unknown>) => {
    const isCorrelation = typeof entity.primary_entity === 'string' && typeof entity.related_entity === 'string'
    const source: StudioModuleSource = isCorrelation ? 'correlation' : 'network'
    const { currentPage } = useStudioStore.getState()
    if (isCorrelation) {
      useStudioStore.getState().addElement(currentPage, {
        type: 'component', x: 100, y: 100, width: 500, height: 300, data: { type: 'correlation-graph', source, title: 'Correlation Link', data: { nodes: [{ id: entity.primary_entity, label: entity.primary_entity, kind: entity.primary_type || 'primary' }, { id: entity.related_entity, label: entity.related_entity, kind: entity.related_type || 'related' }], edges: [{ source: entity.primary_entity, target: entity.related_entity, type: entity.relationship_type || 'linked', confidence: entity.confidence_score || 0 }], central_entity: entity.primary_entity } }
      })
    } else {
      useStudioStore.getState().addElement(currentPage, {
        type: 'component', x: 100, y: 100, width: 500, height: 300, data: { type: 'network-flow', source, title: 'Network Entity', data: { src_ip: entity.ip_address || 'unknown', dst_ip: entity.domain || 'unknown', bytes: entity.bytes_transferred || 0, packets: entity.connections_count || 0, protocol: entity.entity_type || 'network', direction: 'outbound' } }
      })
    }
    useStudioStore.getState().setHasChanges(true)
    useStudioStore.getState().setActivePanel(null)
  }, [])

  const handleInsertEvidence = useCallback((evidence: Record<string, unknown>) => {
    const { currentPage } = useStudioStore.getState()
    const hashValue = typeof evidence.hash_value === 'string' ? evidence.hash_value : ''
    const hashAlgorithm = typeof evidence.hash_algorithm === 'string' ? evidence.hash_algorithm : 'sha256'
    useStudioStore.getState().addElement(currentPage, {
      type: 'component', x: 100, y: 100, width: 400, height: 200, data: { type: 'finding', chartType: 'finding', componentType: 'finding', source: 'case', title: String(evidence.artefact_name || 'Vault Evidence'), summary: { severity: 'info', summary: `${String(evidence.artefact_type || 'Evidence')} inserted from Vault`, details: `${hashAlgorithm}: ${hashValue}` } }
    })
    useStudioStore.getState().setHasChanges(true)
    useStudioStore.getState().setActivePanel(null)
  }, [])

  const handleInsertBlock = useCallback((block: Record<string, unknown>) => {
    const attrs = (block as { attrs?: Record<string, unknown> }).attrs
    if (!attrs) return
    const { currentPage } = useStudioStore.getState()
    const source = normalizeModuleSource(attrs.source)
    useStudioStore.getState().addElement(currentPage, {
      type: 'component', x: 100, y: 100, width: 500, height: 300, data: { ...attrs, source }
    })
    useStudioStore.getState().setHasChanges(true)
    useStudioStore.getState().setActivePanel(null)
  }, [])

  const handleInsertText = useCallback((blockDef: Record<string, unknown>) => {
    const blockType = typeof blockDef.type === 'string' ? blockDef.type : 'paragraph'
    const blockName = typeof blockDef.name === 'string' ? blockDef.name : 'New text block'
    const { currentPage } = useStudioStore.getState()

    useStudioStore.getState().addElement(currentPage, {
      type: 'text',
      x: 100,
      y: 100,
      width: 400,
      height: 100,
      data: {
        textType: blockType,
        content: blockType === 'heading' ? blockName : 'Start typing...',
        style: blockType,
      }
    })

    useStudioStore.getState().setHasChanges(true)
    useStudioStore.getState().setActivePanel(null)
  }, [])

  const handleInsertElement = useCallback((elementConfig: Record<string, unknown>) => {
    const name = typeof elementConfig.name === 'string' ? elementConfig.name : 'Element'
    const { currentPage } = useStudioStore.getState()
    useStudioStore.getState().addElement(currentPage, {
      type: 'shape', x: 100, y: 100, width: 100, height: 100, data: { name }
    })
    useStudioStore.getState().setHasChanges(true)
    useStudioStore.getState().setActivePanel(null)
  }, [])

  const handleInsertUpload = useCallback((upload: Record<string, unknown>) => {
    const name = typeof upload.name === 'string' ? upload.name : 'Upload'
    const url = typeof upload.url === 'string' ? upload.url : ''
    const { currentPage } = useStudioStore.getState()
    useStudioStore.getState().addElement(currentPage, {
      type: 'image', x: 100, y: 100, width: 300, height: 200, data: { name, url }
    })
    useStudioStore.getState().setHasChanges(true)
    useStudioStore.getState().setActivePanel(null)
  }, [])

  const handleApplyTemplate = useCallback((templateId: string) => {
    const template = MASTER_TEMPLATES[templateId]
    if (!template) {
      console.warn(`Template ${templateId} not mapped.`)
      return
    }

    const state = useStudioStore.getState()
    const { currentPage, pages } = state

    // Phase 3: Totally wipe the current active page and paint the pre-coordinated template skeletons
    const newPages = [...pages]
    if (newPages[currentPage]) {
      newPages[currentPage] = {
        ...newPages[currentPage],
        elements: template
      }
    }

    state.setPages(newPages)
    state.setHasChanges(true)
    state.setActivePanel(null)
  }, [])

  // ── Fatal error screen ────────────────────────────────────────────────
  if (fatalError) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background px-6">
        <div className="w-full max-w-3xl space-y-4 rounded-lg border bg-card p-6 shadow-sm">
          <div className="space-y-1">
            <p className="text-destructive font-semibold">Report Studio crashed: {fatalError.message}</p>
            <p className="text-sm text-muted-foreground">A minimal fallback is shown to avoid re-triggering the crash.</p>
          </div>
          {fatalInfo && (
            <pre className="text-left text-xs bg-muted rounded-md p-3 max-h-[320px] overflow-auto border">
              {fatalInfo}
            </pre>
          )}
          <div className="flex gap-3">
            <button onClick={() => window.location.reload()} className="text-primary underline text-sm">Reload</button>
          </div>
        </div>
      </div>
    )
  }

  // ── Main render (no more error-blocking overlay!) ──────────────────────
  return (
    <StudioErrorBoundary onError={(err, info) => { setFatalError(err); setFatalInfo(info); }}>
      {showOfflineBanner && (
        <OfflineBanner
          onDismiss={() => setShowOfflineBanner(false)}
          onRetry={() => attemptLoad().then(ok => { if (!ok) setShowOfflineBanner(true) })}
        />
      )}
      <EditorProvider>
        <CanvaLayout
          caseId={caseId}
          documentId={documentId || undefined}
          editor={tipTapEditor}
          onBack={handleBack}
          onSave={handleSave}
          onExport={handleExport}
          onShare={handleShare}
          onInvestigate={handleInvestigate}
          onStopInvestigation={handleStopInvestigation}
          onInsertComponent={handleInsertComponent}
          onInsertFinding={handleInsertFinding}
          onInsertEntity={handleInsertEntity}
          onInsertEvidence={handleInsertEvidence}
          onInsertBlock={handleInsertBlock}
          onInsertText={handleInsertText}
          onInsertElement={handleInsertElement}
          onInsertUpload={handleInsertUpload}
          onApplyTemplate={handleApplyTemplate}
        >
          {loading ? (
            <div className="flex items-center justify-center h-[500px] w-full">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <DocumentCanvas
              zoom={zoom}
              onDropNewComponent={handleDropCanvasComponent}
            />
          )}
        </CanvaLayout>

        {/* Chart Inspector — shows when a chart evidence block is selected */}
        {tipTapEditor && <ChartInspector editor={tipTapEditor} />}

        {/* Export Preview Modal */}
        <ExportPreviewModal
          open={previewModalOpen}
          onOpenChange={setPreviewModalOpen}
          onConfirm={(engine) => {
            setPreviewModalOpen(false);
            setTimeout(() => {
              setExportEngine(engine);
              setExportDialogOpen(true);
            }, 300);
          }}
        />

        {/* Ghost Writer Expert Engine */}
        {documentId && (
          <GhostWriterWizard
            open={exportDialogOpen}
            onOpenChange={setExportDialogOpen}
            caseId={caseId}
            docId={documentId}
            apiBaseUrl={apiOrigin || undefined}
            exportEngine={exportEngine}
            exportFormat={exportFormat}
            onExportComplete={(result) => {
              if (result?.filename) {
                const encoded = encodeURIComponent(result.filename)
                // Use location.assign to trigger the file download natively 
                // without getting caught by the async popup blocker
                window.location.assign(`/api/v4/studio/cases/${caseId}/exports/download/${encoded}`)
              }
            }}
          />
        )}

        {/* Investigation Configuration Dialog */}
        <InvestigationConfigDialog
          open={investigationDialogOpen}
          onOpenChange={setInvestigationDialogOpen}
          caseId={caseId}
          onStart={handleStartInvestigation}
        />

        {/* Report Preview Panel */}
        <ReportPreviewPanel
          open={reportPreviewOpen}
          onOpenChange={setReportPreviewOpen}
          caseId={caseId}
          onExport={handleExportFromPreview}
        />
      </EditorProvider>
    </StudioErrorBoundary>
  )
}

// Simple client-only error boundary
class StudioErrorBoundary extends React.Component<{ children: React.ReactNode; onError: (err: Error, stack: string) => void }, { hasError: boolean }> {
  constructor(props: any) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    const mergedStack = [error.stack, info.componentStack].filter(Boolean).join('\n--- component stack ---\n')
    if (typeof window !== 'undefined') {
      ; (window as any).__studio_last_error = { error, componentStack: info.componentStack, mergedStack }
    }
    console.error('StudioErrorBoundary caught error', mergedStack)
    this.props.onError(error, mergedStack)
  }

  render() {
    return this.props.children
  }
}

