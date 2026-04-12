import sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

old_ui = '''              {/* Format selection */}
              <div className="space-y-2">'''

new_ui = '''              {/* Cover Template Selection (PDF Only) */}
              {format === 'pdf' && (
                <div className="space-y-2 border-t pt-3">
                  <Label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Cover Template
                  </Label>
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { id: '1', name: 'Original', thumb: '/templates/template_1/thumb.png' },
                      { id: '2', name: 'Cyber Indigo', thumb: '/templates/template_1/thumb.png' },
                      { id: '3', name: 'Midnight', thumb: '/templates/template_1/thumb.png' },
                    ].map(cov => (
                      <button
                        key={cov.id}
                        className={`overflow-hidden rounded-lg border-2 transition-all p-1 ${
                          coverId === cov.id
                            ? 'border-sky-500 bg-sky-50'
                            : 'border-slate-200 hover:border-slate-300'
                        }`}
                        onClick={() => setCoverId(cov.id)}
                      >
                        <div className="h-16 w-full rounded bg-slate-100 bg-cover bg-center" style={{ backgroundImage: `url('/templates/template_1/cover_${cov.id}.png')` }} />
                        <div className="text-[10px] font-medium mt-1 text-center">{cov.name}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Format selection */}
              <div className="space-y-2 border-t pt-3">'''

text = text.replace(old_ui, new_ui)

old_footer = '''        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}>        
            Cancel
          </Button>
          <Button
            disabled={checking || exporting || !!isBlocked}
            onClick={handleExport}
            className="gap-1.5 bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-700 hover:to-indigo-700"
          >
            {exporting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Exporting...
              </>
            ) : (
              <>
                <FileDown className="h-4 w-4" />
                Export {format.toUpperCase()}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>'''

new_footer = '''        {exportError && (
          <div className="text-xs text-red-500 bg-red-50 p-2 rounded px-3 border border-red-100 mt-2">
            {exportError}
          </div>
        )}

        {loadingPhase >= 0 && (
          <div className="flex flex-col items-center justify-center p-4 bg-slate-900 rounded-lg border border-slate-800 space-y-2 mt-4 transition-all">
             <Loader2 className="h-6 w-6 text-sky-400 animate-spin mb-2" />
             <div className="font-mono text-xs text-emerald-400 font-bold tracking-wider">
               {LOADING_PHASES[loadingPhase]}
             </div>
             <div className="flex gap-1 w-full max-w-[200px] justify-between mt-2">
               {LOADING_PHASES.map((_, i) => (
                 <div key={i} className={`h-1 w-full mx-1 rounded-full transition-colors duration-500 ${i <= loadingPhase ? 'bg-sky-500' : 'bg-slate-700'}`} />
               ))}
             </div>
          </div>
        )}

        <DialogFooter className="gap-2 mt-4">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={exporting}>        
            Cancel
          </Button>
          <Button
            disabled={checking || exporting || !!isBlocked}
            onClick={handleExport}
            className={`gap-1.5 transition-all text-white shadow-md ${exporting ? 'bg-slate-800' : 'bg-gradient-to-r from-slate-800 to-slate-900 hover:from-slate-700 hover:to-slate-800 border border-slate-700'}`}
          >
            {exporting ? (
              <>
                <Loader2 className="h-4 w-4 text-sky-400 animate-spin" />
                COMPILING DOSSIER
              </>
            ) : (
              <>
                <FileDown className="h-4 w-4 text-sky-400" />
                EXPORT DOSSIER
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>'''

text = text.replace(old_footer, new_footer)

with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(text)
print("Updated UI rendering using literal string")
