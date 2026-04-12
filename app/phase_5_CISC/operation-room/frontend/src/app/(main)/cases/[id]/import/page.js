'use client';

import { useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ClipboardList,
  Download,
  RefreshCcw,
} from 'lucide-react';
import { api } from '@operation-room/lib/api';

const SOURCE_OPTIONS = [
  { id: 'AUTH', label: 'Authentication' },
  { id: 'VPN', label: 'VPN' },
  { id: 'FW', label: 'Firewall' },
  { id: 'DB', label: 'Database' },
  { id: 'APP', label: 'Application' },
  { id: 'EPP', label: 'Endpoint Security' },
  { id: 'FILE', label: 'File System' },
];

export default function ImportPage() {
  const { id } = useParams();
  const [form, setForm] = useState({
    source_type: 'AUTH',
    time_start: '',
    time_end: '',
    target_actors: '',
    target_systems: '',
    query_text: '',
    justification: 'Evidence collection',
  });
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const set = (key, val) => setForm((f) => ({ ...f, [key]: val }));

  const handleImport = async () => {
    setImporting(true);
    setError('');
    setResult(null);
    try {
      const payload = {
        ...form,
        time_start: new Date(form.time_start).toISOString(),
        time_end: new Date(form.time_end).toISOString(),
        target_actors: form.target_actors.split(',').map((s) => s.trim()).filter(Boolean),
        target_systems: form.target_systems.split(',').map((s) => s.trim()).filter(Boolean),
      };
      const res = await api.importLogs(id, payload);
      setResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setImporting(false);
    }
  };

  return (
    <>
      <div className="page-header animate-in">
        <div>
          <h1>Import Evidence Logs</h1>
          <p>Fetch logs via the NLP Query Agent, hash and store them in the Case Vault</p>
        </div>
        <Link href={`/cases/${id}`} className="btn btn-ghost">
          <ArrowLeft size={14} />
          Back to Case
        </Link>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        {/* ── Import Form ─────────────────────────── */}
        <div className="glass-card-static animate-in animate-in-delay-1">
          <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 18 }}>
            IMPORT CONFIGURATION
          </h3>

          <div className="form-group">
            <label className="form-label">Log Source *</label>
            <select className="form-select" value={form.source_type}
                    onChange={(e) => set('source_type', e.target.value)}>
              {SOURCE_OPTIONS.map((s) => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="form-group">
              <label className="form-label">Start Time *</label>
              <input className="form-input" type="datetime-local"
                     value={form.time_start} onChange={(e) => set('time_start', e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">End Time *</label>
              <input className="form-input" type="datetime-local"
                     value={form.time_end} onChange={(e) => set('time_end', e.target.value)} />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Target Actors</label>
            <input className="form-input" placeholder="jdoe, asmith (comma‑separated)"
                   value={form.target_actors} onChange={(e) => set('target_actors', e.target.value)} />
          </div>

          <div className="form-group">
            <label className="form-label">Target Systems</label>
            <input className="form-input" placeholder="dc01, db-prod-01 (comma‑separated)"
                   value={form.target_systems} onChange={(e) => set('target_systems', e.target.value)} />
          </div>

          <div className="form-group">
            <label className="form-label">Custom NLP Query (optional)</label>
            <textarea className="form-textarea" rows={2}
                      placeholder="e.g. All failed logins from external IPs after midnight"
                      value={form.query_text} onChange={(e) => set('query_text', e.target.value)} />
          </div>

          <div className="form-group">
            <label className="form-label">Justification</label>
            <input className="form-input" value={form.justification}
                   onChange={(e) => set('justification', e.target.value)} />
            <div className="form-hint">Recorded in the chain‑of‑custody log.</div>
          </div>

          {error && (
            <div style={{ color: 'var(--accent-rose)', marginBottom: 12, fontSize: 13 }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <AlertTriangle size={14} />
                {error}
              </span>
            </div>
          )}

          <button className="btn btn-primary btn-lg" style={{ width: '100%', justifyContent: 'center' }}
                  onClick={handleImport}
                  disabled={importing || !form.time_start || !form.time_end}>
            {importing ? (
              <>
                <div className="spinner" />
                Importing...
              </>
            ) : (
              <>
                <Download size={15} />
                Import and Hash Evidence
              </>
            )}
          </button>
        </div>

        {/* ── Result Panel ─────────────────────────── */}
        <div className="glass-card-static animate-in animate-in-delay-2">
          <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 18 }}>
            IMPORT RESULT
          </h3>

          {!result ? (
            <div className="empty-state" style={{ padding: 40 }}>
              <ClipboardList size={40} className="empty-state-glyph" />
              <p>Configure and run an import to see results here.</p>
            </div>
          ) : (
            <div>
              <div style={{
                padding: 14, background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.2)',
                borderRadius: 'var(--radius-md)', marginBottom: 20,
                color: 'var(--accent-emerald)', fontSize: 14, fontWeight: 500
              }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <CheckCircle2 size={15} />
                  {result.message}
                </span>
              </div>

              <table className="data-table">
                <tbody>
                  <tr><td style={{ fontWeight: 600, width: 140 }}>Artefact</td><td>{result.artefact_name}</td></tr>
                  <tr><td style={{ fontWeight: 600 }}>Records</td><td>{result.record_count?.toLocaleString()}</td></tr>
                  <tr><td style={{ fontWeight: 600 }}>Size</td><td>{(result.byte_size / 1024).toFixed(1)} KB</td></tr>
                  <tr><td style={{ fontWeight: 600 }}>Algorithm</td><td>{result.hash_algorithm}</td></tr>
                  <tr><td style={{ fontWeight: 600 }}>Hash</td>
                      <td><span className="hash-value">{result.hash_value}</span></td></tr>
                  <tr><td style={{ fontWeight: 600 }}>Batch ID</td>
                      <td><span className="hash-value" style={{ fontSize: 11 }}>{result.import_batch_id}</span></td></tr>
                </tbody>
              </table>

              <div style={{ display: 'flex', gap: 10, marginTop: 20 }}>
                <button className="btn btn-secondary" onClick={() => setResult(null)}>
                  <RefreshCcw size={14} />
                  Import Another
                </button>
                <Link href={`/cases/${id}`} className="btn btn-ghost">
                  <ArrowLeft size={14} />
                  Back to Case
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
