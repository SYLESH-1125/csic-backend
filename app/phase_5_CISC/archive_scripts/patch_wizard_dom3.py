import re
import sys

# Paths
wizard_path = r'c:\CISC\operation-room\frontend\src\components\studio-v4\dialogs\GhostWriterWizard.tsx'
content_txt_path = r'c:\VSCodeData\User\workspaceStorage\f1ee41e1b9e36ec85388c7337c09aece\GitHub.copilot-chat\chat-session-resources\e6baca95-e638-4944-aeab-3f51b75efd45\call_MHwzY2xPekJlVmF1SFpZYUl6ZHo__vscode-1775113306747\content.txt'

with open(wizard_path, 'r', encoding='utf-8') as f:
    text = f.read()

with open(content_txt_path, 'r', encoding='utf-8') as f2:
    content = f2.read()

customize_ui = content.split('```jsx\n')[1].split('\n```')[0] if '```jsx' in content else "/* Failed to load customize_ui */"

new_ui = r"""            {/* TEMPLATE/COVER/CUSTOMIZE (IDLE) */}
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

""" + customize_ui

# Sub the old UI for the new UI using regex until the end of the `</div>\n      </DialogContent>`
pattern = r'\{\/\*\s*TEMPLATE\/COVER\/CUSTOMIZE\s*\(IDLE\)\s*\*\/\}.*?(?=\n\s*\<\/div>\n\s*\<\/DialogContent>)'

matches = re.findall(pattern, text, re.DOTALL)
if matches:
    new_text = text.replace(matches[0], new_ui)
    with open(wizard_path, 'w', encoding='utf-8') as f:
        f.write(new_text)
    print("Replaced successfully.")
else:
    print("Pattern matched nothing.")
