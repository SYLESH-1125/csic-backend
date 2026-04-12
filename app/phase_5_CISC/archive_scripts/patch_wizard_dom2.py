import sys

with open(r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx', 'r', encoding='utf-8') as f:
    text = f.read()

target_ui = """            {/* TEMPLATE/COVER/CUSTOMIZE (IDLE) */}
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
}"""

with open(r'c:\VSCodeData\User\workspaceStorage\f1ee41e1b9e36ec85388c7337c09aece\GitHub.copilot-chat\chat-session-resources\e6baca95-e638-4944-aeab-3f51b75efd45\call_MHwzY2xPekJlVmF1SFpZYUl6ZHo__vscode-1775113306747\content.txt', 'r', encoding='utf-8') as f2:
    content = f2.read()
    if '```jsx' in content:
        customize_ui = content.split('```jsx\n')[1].split('\n```')[0]
    else:
        print("Couldn't find JSX snippet. Check path.")
        sys.exit(1)

new_ui = """            {/* TEMPLATE/COVER/CUSTOMIZE (IDLE) */}
            {new_phase === 'idle' && new_setup_step === 'template' && (
              <div style={{ width: "100%", maxWidth: "1000px" }}>
                <h3 style={{ marginBottom: "15px", color: "#0F172A", fontSize: "20px", fontWeight: "bold" }}>1. Select Core Template</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                  {new_templates.map((new_t: any) => (
                    <div
                      key={new_t.id}
                      onClick={() => { setNewSelectedTemplate(new_t.id); setNewSelectedCover(''); setNewError(''); }}
                      style={{ cursor: 'pointer', border: new_selected_template === new_t.id ? '2px solid #0284C7' : '1px solid #CBD5E1', borderRadius: '8px', padding: '20px', background: '#FFFFFF', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.05)', transition: 'all 0.2s', transform: new_selected_template === new_t.id ? 'translateY(-2px)' : 'none' }}
                    >
                      <img src={new_t.thumbnail} alt={new_t.name} style={{ width: "100%", height: "140px", objectFit: "contain", marginBottom: "15px", borderRadius: "4px", backgroundColor: "#F8FAFC", padding: "10px" }} />
                      <div style={{ fontWeight: 'bold', marginBottom: '6px', color: '#0F172A', fontSize: "16px" }}>{new_t.name}</div>
                      <div style={{ color: '#64748B', fontSize: '13px', fontWeight: "bold" }}>Standard Architecture</div>
                    </div>
                  ))}
                </div>

                {new_active_template_obj && (
                  <div style={{ animation: "slidein 0.4s" }}>
                    <h3 style={{ marginBottom: "15px", color: "#0F172A", borderTop: "1px solid #E2E8F0", paddingTop: "20px", fontSize: "20px", fontWeight: "bold" }}>2. Select Cover Layout</h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px', marginBottom: '30px' }}>
                      {(new_active_template_obj.covers || []).map((new_c: any) => (
                        <div
                          key={new_c.id}
                          onClick={() => setNewSelectedCover(new_c.id)}
                          style={{ cursor: 'pointer', border: new_selected_cover === new_c.id ? '2px solid #0284C7' : '1px solid #CBD5E1', borderRadius: '8px', padding: '15px', background: '#FFFFFF', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.05)', textAlign: 'center', transition: "all 0.2s" }}
                        >
                          <img src={new_c.image} alt={new_c.name} style={{ width: '100%', height: '260px', objectFit: 'contain', borderRadius: '4px', marginBottom: '15px', background: '#F8FAFC', padding: "5px", border: "1px solid #E2E8F0" }} />
                          <div style={{ fontWeight: 'bold', color: '#0F172A' }}>{new_c.name}</div>
                        </div>
                      ))}
                    </div>
                    
                    <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <button onClick={() => { if(new_selected_cover) setNewSetupStep('customize') }} style={{ padding: "14px 40px", background: "#0F172A", color: "#FFF", border: "none", borderRadius: "6px", fontWeight: "bold", cursor: "pointer" }}>PROCEED TO CUSTOMIZATION →</button>
                    </div>
                  </div>
                )}
              </div>
            )}

""" + customize_ui + """
        </div>
      </DialogContent>
    </Dialog>
  );
}
"""

text = text.replace(target_ui, new_ui)
with open(r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx', 'w', encoding='utf-8') as f:
    f.write(text)
