import os
import re

path = r'C:\CISC\operation-room\frontend\src\app\(main)\cases\[id]\page.js'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

replacement = r'''              )}
            </div>

            {/* Saved Evidence Vault Table */}
            <div className="glass-card-static animate-in animate-in-delay-4" style={{ flex: 1, marginTop: 24 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-muted)' }}>
                  SAVED EVIDENCE VAULT (PINNED SEQUENCES)
                </h3>
              </div>

              {evidenceCards.length === 0 ? (
                <div className="empty-state" style={{ padding: 36 }}>
                  <Package size={40} className="empty-state-glyph" />
                  <h3>No Pinned Sequences</h3>
                  <p>Pin events in the Timeline Flow and save them to the Vault.</p>
                </div>
              ) : (
                <div style={{ overflowX: 'auto', maxHeight: 300 }}>
                  <table className="data-table">
                    <thead style={{ position: 'sticky', top: 0, backgroundColor: '#fff', zIndex: 10 }}>
                      <tr>
                        <th>Title</th>
                        <th>Description</th>
                        <th>Events</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {evidenceCards.map((card) => (
                        <tr key={card.id}>
                          <td style={{ color: '#1e293b', fontWeight: 600 }}>{card.title}</td>
                          <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>{card.description || '—'}</td>
                          <td><span className="hash-value">{(card.evidence_ref?.pointers?.length || 0).toLocaleString()} events</span></td>
                          <td>
                            <button
                              className="btn btn-primary btn-sm"
                              style={{ fontSize: 12, padding: '4px 10px', display: 'flex', alignItems: 'center' }}
                              onClick={() => window.location.href = `/cases/${id}/timeline?card=${card.id}`}
                            >
                              Timeline View
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Generated Reports Table */}'''

new_text = re.sub(r'(\s+\)\}\s*<\/div>\s*\{/\* Generated Reports Table \*/\})', replacement, text)

print("Did replacement happen?", new_text != text)

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_text)
