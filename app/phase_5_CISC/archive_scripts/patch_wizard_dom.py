import sys

with open(r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx', 'r', encoding='utf-8') as f:
    text = f.read()

target_ui = \"\"\"            {/* TEMPLATE/COVER/CUSTOMIZE (IDLE) */}
            {new_phase === 'idle' && new_setup_step === 'template' && (
                <div style={{ width: "100%", maxWidth: "1000px", animation: "slidein 0.4s" }}>
                    <h3 style={{ fontSize: "20px", marginBottom: "20px", color: "#0F172A", fontWeight: "bold" }}>1. Select Core Template</h3>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "20px", marginBottom: "40px" }}>
                        {new_templates.map(t => (
                            <div key={t.id} onClick={() => setNewSelectedTemplate(t.id)} style={{ cursor: "pointer", border: new_selected_template === t.id ? "2px solid #0284C7" : "1px solid #CBD5E1", background: "#FFF", padding: "20px", borderRadius: "8px", boxShadow: "0 4px 6px rgba(0,0,0,0.05)" }}>
                                <div style={{ height: "140px", background: "linear-gradient(135deg, #1e293b 0%, #0f172a 100%)", borderRadius: "4px", marginBottom: "15px" }}></div>
                                <div style={{ fontWeight: "bold", fontSize: "16px" }}>{t.name}</div>
                            </div>
                        ))}
                    </div>

                    <h3 style={{ fontSize: "20px", marginBottom: "20px", color: "#0F172A", fontWeight: "bold" }}>2. Select Cover Layout</h3>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "20px", marginBottom: "40px" }}>
                        <div onClick={() => setNewSelectedCover('1')} style={{ cursor: "pointer", border: new_selected_cover === '1' ? "2px solid #0284C7" : "1px solid #CBD5E1", height: "200px", background: "linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%)", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: "bold", color: "#0F172A" }}>Executive White</div>
                        <div onClick={() => setNewSelectedCover('2')} style={{ cursor: "pointer", border: new_selected_cover === '2' ? "2px solid #0284C7" : "1px solid #CBD5E1", height: "200px", background: "linear-gradient(135deg, #0f172a 0%, #312e81 100%)", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: "bold", color: "#FFF" }}>Cyber Indigo</div>
                        <div onClick={() => setNewSelectedCover('3')} style={{ cursor: "pointer", border: new_selected_cover === '3' ? "2px solid #0284C7" : "1px solid #CBD5E1", height: "200px", background: "linear-gradient(135deg, #09090b 0%, #4c0519 100%)", borderRadius: "8px", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: "bold", color: "#FDA4AF" }}>Midnight Flare</div>
                    </div>

                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <button onClick={() => { if(new_selected_cover) setNewSetupStep('customize') }} style={{ padding: "14px 40px", background: "#0F172A", color: "#FFF", border: "none", borderRadius: "6px", fontWeight: "bold", cursor: "pointer" }}>PROCEED TO CUSTOMIZATION →</button>
                    </div>
                </div>
            )}
        </div>
      </DialogContent>
    </Dialog>
  );
}\"\"\"

target_ui = target_ui.strip()

with open(r'c:\CISC\patch_wizard_dom.py', 'a', encoding='utf-8') as f:
    pass
