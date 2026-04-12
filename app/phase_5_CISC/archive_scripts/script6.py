import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

old_state = '''  const [format, setFormat] = useState<string>('pdf')
  const [exporting, setExporting] = useState(false)
  const [overrideReason, setOverrideReason] = useState('')
  const [showOverride, setShowOverride] = useState(false)'''

new_state = '''  const [format, setFormat] = useState<string>('pdf')
  const [exporting, setExporting] = useState(false)
  const [overrideReason, setOverrideReason] = useState('')
  const [showOverride, setShowOverride] = useState(false)
  const [coverId, setCoverId] = useState<string>('1')
  const [loadingPhase, setLoadingPhase] = useState<number>(-1)
  const [exportError, setExportError] = useState<string>('')

  const LOADING_PHASES = [
    "ESTABLISHING SECURE UPLINK...",
    "PARSING JSON PAYLOAD...",
    "INJECTING HEX OFFSETS...",
    "COMPILING 30-PAGE DOSSIER...",
    "FINALIZING GHOSTWRITER ENGINE..."
  ]'''

old_export_fn = '''  // Execute export
  const handleExport = useCallback(async () => {
    setExporting(true)
    try {
      const result = await api.post(/v4/studio/cases//exports/, {
        doc_id: docId,
        actor: 'investigator',
        override_reason: overrideReason || undefined,
        frontend_url: window.location.origin,
      })
      onExportComplete?.(result)
      onOpenChange(false)
    } catch (err) {
      console.error('[ExportGate] Export failed:', err)
    } finally {
      setExporting(false)
    }
  }, [caseId, docId, format, overrideReason, onExportComplete, onOpenChange])'''

new_export_fn = '''  // Execute export
  const handleExport = useCallback(async () => {
    setExporting(true)
    setExportError('')
    
    // Trigger 5-phase ghostwriter animation
    for (let i = 0; i < LOADING_PHASES.length; i++) {
        setLoadingPhase(i);
        await new Promise(resolve => setTimeout(resolve, 1200));
    }
    
    try {
      const result = await api.post(/v4/studio/cases//exports/, {
        doc_id: docId,
        actor: 'investigator',
        override_reason: overrideReason || undefined,
        frontend_url: window.location.origin,
        cover_id: format === 'pdf' ? coverId : undefined,
      })
      onExportComplete?.(result)
      onOpenChange(false)
    } catch (err: any) {
      console.error('[ExportGate] Export failed:', err)
      setExportError(err.message || 'Export failed')
    } finally {
      setExporting(false)
      setLoadingPhase(-1)
    }
  }, [caseId, docId, format, overrideReason, coverId, onExportComplete, onOpenChange])'''

if old_state in text:
    text = text.replace(old_state, new_state)
else:
    print("Could not find state block")

if old_export_fn in text:
    text = text.replace(old_export_fn, new_export_fn)
else:
    print("Could not find export fn block")

with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated states and handles in ExportGateDialog")
