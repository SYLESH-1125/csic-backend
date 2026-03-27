import io
import os
import base64
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_JUSTIFY

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

def _get_cover_b64() -> str:
    new_path= os.path.join(os.path.dirname(__file__), "assets", "cover.png")
    if os.path.exists(new_path):
        with open(new_path, "rb") as new_f:
            return base64.b64encode(new_f.read()).decode("utf-8")
    return None

def _parse_iso(new_s: Any):
    if not new_s or not isinstance(new_s, str):
        return None
    try:
        new_x= new_s.replace("Z", "+00:00")
        return datetime.fromisoformat(new_x)
    except Exception:
        return None

def _fmt_dt(new_dt: Any) -> str:
    if not new_dt:
        return "N/A"
    if isinstance(new_dt, str):
        new_dtp= _parse_iso(new_dt)
        if not new_dtp:
            return new_dt
        new_dt= new_dtp
    try:
        return new_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"

def _human_bytes(new_n: Any) -> str:
    try:
        new_b= int(new_n)
    except Exception:
        return "N/A"
    if new_b < 0:
        return "N/A"
    new_units= ["B", "KB", "MB", "GB", "TB"]
    new_i= 0
    new_v= float(new_b)
    while new_v >= 1024 and new_i < len(new_units) - 1:
        new_v/= 1024.0
        new_i+= 1
    if new_i == 0:
        return f"{int(new_v)} {new_units[ new_i ]}"
    return f"{new_v:.2f} {new_units[ new_i ]}"

def _short_hash(new_h: Any, new_n: int = 12) -> str:
    if not new_h or not isinstance(new_h, str):
        return "N/A"
    if len(new_h) <= new_n:
        return new_h
    return new_h[ :new_n ] + "…"

def _safe_list(new_x: Any) -> List[Any]:
    return new_x if isinstance(new_x, list) else []

def _safe_dict(new_x: Any) -> Dict[str, Any]:
    return new_x if isinstance(new_x, dict) else {}

def _b64_png_from_buf(new_buf: io.BytesIO) -> str:
    
    return base64.b64encode(new_buf.getvalue()).decode("utf-8")

class GraphEngine:
    @staticmethod
    def _get_style(new_s: str):
        if new_s == "modern":
            return {
                "bg": "#0F172A", "text": "#F8FAFC", "grid": "#334155",
                "colors": ["#06B6D4", "#6366F1", "#8B5CF6", "#F472B6", "#FB7185", "#34D399", "#FBBF24"]
            }
        elif new_s == "clean" or new_s == "minimal":
            return {
                "bg": "#FFFFFF", "text": "#0F172A", "grid": "#E2E8F0",
                "colors": ["#0369A1", "#0284C7", "#38BDF8", "#7DD3FC", "#BAE6FD", "#E0F2FE", "#F0F9FF"]
            }
        return {
            "bg": "#FFFFFF", "text": "#1E293B", "grid": "#CBD5E1",
            "colors": ["#B91C1C", "#1D4ED8", "#15803D", "#D97706", "#7E22CE", "#0F766E", "#64748B"]
        }

    @staticmethod
    def _setup_plot(new_style):
        plt.figure(figsize=(8, 4))
        new_fig= plt.gcf()
        new_ax= plt.gca()
        new_fig.patch.set_facecolor(new_style[ "bg" ])
        new_ax.set_facecolor(new_style[ "bg" ])
        new_ax.tick_params(colors=new_style[ "text" ], labelsize=8)
        new_ax.xaxis.label.set_color(new_style[ "text" ])
        new_ax.yaxis.label.set_color(new_style[ "text" ])
        new_ax.title.set_color(new_style[ "text" ])
        for new_spine in new_ax.spines.values():
            new_spine.set_color(new_style[ "grid" ])
        return new_fig, new_ax

    @staticmethod
    def _save_fig(new_fig) -> io.BytesIO:
        plt.tight_layout()
        new_buf= io.BytesIO()
        new_fig.savefig(new_buf, format="png", dpi=200)
        new_buf.seek(0)
        plt.close(new_fig)
        return new_buf

    @staticmethod
    def pie_chart(data: Dict[str, int], title: str, new_gstyle: str = "classic") -> io.BytesIO:
        new_style= GraphEngine._get_style(new_gstyle)
        new_items= sorted(data.items(), key=lambda x: x[ 1 ], reverse=True)
        if len(new_items) > 7:
            new_top= new_items[ :6 ]
            new_other= sum(v for _, v in new_items[ 6: ])
            new_items= new_top + [("other", new_other)]
        new_lbls= [k for k, _ in new_items]
        new_vals= [v for _, v in new_items]
        new_fig, new_ax= GraphEngine._setup_plot(new_style)
        new_ax.pie(new_vals, labels=new_lbls, colors=new_style[ "colors" ], autopct="%1.1f%%" if sum(new_vals) > 0 else None, startangle=140, textprops={"color": new_style[ "text" ], "fontsize": 9})
        new_ax.set_title(title, fontsize=11, fontweight="bold")
        new_ax.axis('equal')
        return GraphEngine._save_fig(new_fig)

    @staticmethod
    def bar_chart(data: Dict[str, float], title: str, xlabel: str, new_gstyle: str = "classic") -> io.BytesIO:
        new_style= GraphEngine._get_style(new_gstyle)
        new_items= sorted(data.items(), key=lambda x: x[ 1 ], reverse=True)[ :10 ]
        new_xs= [k for k, _ in new_items]
        new_ys= [v for _, v in new_items]
        new_fig, new_ax= GraphEngine._setup_plot(new_style)
        new_ax.bar(new_xs, new_ys, width=0.6, color=new_style[ "colors" ][ 0 ])
        new_ax.set_title(title, fontsize=11, fontweight="bold")
        new_ax.set_xlabel(xlabel, fontsize=9)
        plt.xticks(rotation=35, ha="right")
        new_ax.grid(axis="y", linestyle="--", alpha=0.5, color=new_style[ "grid" ])
        return GraphEngine._save_fig(new_fig)

    @staticmethod
    def line_chart(timeline: List[Dict[str, Any]], title: str, new_gstyle: str = "classic") -> io.BytesIO:
        new_style= GraphEngine._get_style(new_gstyle)
        new_scores= []
        for new_t in timeline:
            try:
                new_scores.append(float(new_t.get("risk_score", 0)))
            except Exception:
                new_scores.append(0.0)
        new_fig, new_ax= GraphEngine._setup_plot(new_style)
        new_ax.plot(range(len(new_scores)), new_scores, linewidth=2.5, color=new_style[ "colors" ][ 0 ])
        if new_scores:
            new_ax.fill_between(range(len(new_scores)), new_scores, alpha=0.2, color=new_style[ "colors" ][ 0 ])
        new_ax.set_title(title, fontsize=11, fontweight="bold")
        new_ax.set_ylabel("Risk Score", fontsize=9)
        new_ax.grid(True, linestyle="--", alpha=0.5, color=new_style[ "grid" ])
        return GraphEngine._save_fig(new_fig)

    @staticmethod
    def horizontal_bar(data: Dict[str, float], title: str, new_gstyle: str = "classic") -> io.BytesIO:
        new_style= GraphEngine._get_style(new_gstyle)
        new_items= sorted(data.items(), key=lambda x: x[ 1 ], reverse=True)[ :10 ]
        new_lbls= [k for k, _ in new_items][ ::-1 ]
        new_vals= [v for _, v in new_items][ ::-1 ]
        new_fig, new_ax= GraphEngine._setup_plot(new_style)
        new_ax.barh(new_lbls, new_vals, color=new_style[ "colors" ][ 0 ])
        new_ax.set_title(title, fontsize=11, fontweight="bold")
        new_ax.set_xlabel("Score", fontsize=9)
        new_ax.grid(axis="x", linestyle="--", alpha=0.5, color=new_style[ "grid" ])
        return GraphEngine._save_fig(new_fig)

    @staticmethod
    def hist_chart(values: List[float], title: str, new_gstyle: str = "classic") -> io.BytesIO:
        new_style= GraphEngine._get_style(new_gstyle)
        new_fig, new_ax= GraphEngine._setup_plot(new_style)
        new_ax.hist(values, bins=18, color=new_style[ "colors" ][ 0 ], edgecolor=new_style[ "bg" ])
        new_ax.set_title(title, fontsize=11, fontweight="bold")
        new_ax.set_xlabel("Anomaly Score", fontsize=9)
        new_ax.set_ylabel("Count", fontsize=9)
        new_ax.grid(axis="y", linestyle="--", alpha=0.5, color=new_style[ "grid" ])
        return GraphEngine._save_fig(new_fig)

def _extract_stats(raw: Dict[str, Any]) -> Dict[str, Any]:
    new_ev= _safe_list(raw.get("evidence_list"))
    new_alerts= _safe_list(raw.get("alerts"))
    new_timeline= _safe_list(raw.get("timeline"))
    new_file_types: Dict[str, int]= {}
    new_status_counts: Dict[str, int]= {}
    new_total_size= 0
    new_times: List[datetime]= []
    for new_f in new_ev:
        if not isinstance(new_f, dict):
            continue
        new_ft= new_f.get("file_type") or "unknown"
        new_file_types[ new_ft ]= new_file_types.get(new_ft, 0) + 1
        new_st= (new_f.get("verification_status") or "UNKNOWN").upper()
        new_status_counts[ new_st ]= new_status_counts.get(new_st, 0) + 1
        new_sb= new_f.get("size_bytes")
        try:
            new_total_size+= int(new_sb)
        except Exception:
            pass
        new_ut= new_f.get("upload_time")
        new_dt= _parse_iso(new_ut) if isinstance(new_ut, str) else None
        if new_dt:
            new_times.append(new_dt)
    new_times.sort()
    new_earliest= new_times[ 0 ] if new_times else None
    new_latest= new_times[ -1 ] if new_times else None
    new_corrupted= [f for f in new_ev if isinstance(f, dict) and (str(f.get("verification_status", "")).upper() in ["CORRUPTED", "INVALID", "FAIL"])]
    new_largest= sorted([f for f in new_ev if isinstance(f, dict)], key=lambda x: int(x.get("size_bytes", 0) or 0), reverse=True)[ :10 ]
    new_parsing= _safe_dict(raw.get("parsing_summary"))
    new_hot= _safe_dict(raw.get("hot_store"))
    new_signals= _safe_dict(raw.get("signals"))
    new_anomaly= _safe_dict(raw.get("anomaly_detection"))
    new_hash_chain= _safe_dict(raw.get("hash_chain"))
    if not new_hash_chain:
        new_hash_chain= _safe_dict(raw.get("chain_of_custody"))
    return {
        "ev": new_ev,
        "alerts": new_alerts,
        "timeline": new_timeline,
        "file_types": new_file_types,
        "status_counts": new_status_counts,
        "total_size": new_total_size,
        "earliest": new_earliest,
        "latest": new_latest,
        "corrupted": new_corrupted,
        "largest": new_largest,
        "parsing": new_parsing,
        "hot": new_hot,
        "signals": new_signals,
        "anomaly": new_anomaly,
        "hash_chain": new_hash_chain,
    }

def _verdict(stats: Dict[str, Any]) -> Tuple[str, str]:
    new_anomaly= _safe_dict(stats.get("anomaly"))
    new_alerts= _safe_list(stats.get("alerts"))
    new_status_counts= _safe_dict(stats.get("status_counts"))
    try:
        new_flagged= int(new_anomaly.get("anomalies_flagged", 0) or 0)
    except Exception:
        new_flagged= 0
    new_hi= 0
    for new_a in new_alerts:
        if isinstance(new_a, dict):
            try:
                if float(new_a.get("risk_score", 0) or 0) >= 90:
                    new_hi+= 1
            except Exception:
                pass
    new_corrupted= 0
    for new_k, new_v in new_status_counts.items():
        if str(new_k).upper() in ["CORRUPTED", "INVALID", "FAIL"]:
            try:
                new_corrupted+= int(new_v)
            except Exception:
                pass
    if new_hi >= 1 or new_flagged >= 50:
        return "MALICIOUS ACTIVITY LIKELY", "High-risk entities and elevated anomaly concentration observed."
    if new_flagged >= 10:
        return "SUSPICIOUS ACTIVITY POSSIBLE", "Moderate anomaly concentration; targeted validation recommended."
    if new_corrupted >= 1:
        return "INTEGRITY REVIEW REQUIRED", "Some artifacts failed integrity verification; isolate and re-check."
    return "NO STRONG INDICATORS", "No high-confidence malicious indicators detected in the provided dataset."

def _recommended_actions(stats: Dict[str, Any]) -> List[str]:
    new_signals= _safe_dict(stats.get("signals"))
    new_alerts= _safe_list(stats.get("alerts"))
    new_triggers= set()
    for new_a in new_alerts:
        if isinstance(new_a, dict):
            for new_t in _safe_list(new_a.get("triggers")):
                if isinstance(new_t, str):
                    new_triggers.add(new_t.lower())
    new_sig_keys= set(str(k).lower() for k in new_signals.keys())
    new_rec: List[str]= []
    if "password_spray" in new_sig_keys or "password_spray" in new_triggers or "login_velocity_spike" in new_sig_keys:
        new_rec.append("Enforce password reset for affected accounts; enable MFA for all privileged users; review lockout policy.")
    if "privilege_escalation" in new_sig_keys or "privilege_escalation" in new_triggers:
        new_rec.append("Audit recent privilege changes and group membership updates; rotate admin credentials; validate sudo/admin use.")
    if "dns_dga_pattern" in new_sig_keys or "dns_dga_pattern" in new_triggers:
        new_rec.append("Block suspicious domains at resolver and perimeter; check endpoints for beaconing; review DNS logs for related subdomains.")
    if "suspicious_outbound" in new_sig_keys or "large_data_transfer" in new_sig_keys:
        new_rec.append("Inspect outbound traffic for data exfil paths; quarantine endpoints showing repeated high-volume transfers; validate destinations.")
    if "persistence_attempt" in new_sig_keys or "rare_process_spawn" in new_sig_keys:
        new_rec.append("Review scheduled tasks/services/startup entries; inspect script execution history; collect EDR triage for impacted hosts.")
    if "log_tamper" in new_sig_keys or "log_tamper" in new_triggers:
        new_rec.append("Preserve original logs; verify collector integrity; compare against upstream sources; expand timeline window for gaps.")
    if not new_rec:
        new_rec.append("Maintain monitoring and validate anomalies with spot checks on top entities and peak timeline windows.")
    new_rec.append("Document all actions with timestamps and operator identity to preserve auditability.")
    return new_rec

def _num(new_x: Any) -> float:
    try:
        return float(new_x)
    except Exception:
        return 0.0

def _present_path(raw: Dict[str, Any], spec: str) -> bool:
    if not spec:
        return False
    new_alts= [s.strip() for s in spec.split("|") if s.strip()]
    for new_s in new_alts:
        if "[]" in new_s:
            new_left, new_right= new_s.split("[]", 1)
            new_left= new_left.strip(".")
            new_right= new_right.strip(".")
            new_base= raw.get(new_left)
            if not isinstance(new_base, list) or not new_base:
                continue
            for new_it in new_base:
                if not isinstance(new_it, dict):
                    continue
                new_v= new_it.get(new_right) if new_right else new_it
                if new_v is None :
                    continue
                if isinstance(new_v, str) and not new_v.strip():
                    continue
                if isinstance(new_v, (list, dict)) and len(new_v) == 0:
                    continue
                return True
        else:
            new_cur: Any= raw
            new_ok= True
            for new_p in new_s.split("."):
                new_p= new_p.strip()
                if not new_p:
                    continue
                if isinstance(new_cur, dict) and new_p in new_cur:
                    new_cur= new_cur[ new_p ]
                else:
                    new_ok= False
                    break
            if not new_ok:
                continue
            if new_cur is None:
                continue
            if isinstance(new_cur, str) and not new_cur.strip():
                continue
            if isinstance(new_cur, (list, dict)) and len(new_cur) == 0:
                continue
            return True
    return False

def _expected_fields() -> List[List[Tuple[str, str]]]:
    return [
        [("case_id", "case_id"), ("evidence_list", "evidence_list"), ("evidence file_type", "evidence_list[].file_type"), ("evidence size_bytes", "evidence_list[].size_bytes"), ("evidence upload_time", "evidence_list[].upload_time")],
        [("evidence_list", "evidence_list"), ("filename", "evidence_list[].filename"), ("file_type", "evidence_list[].file_type"), ("size_bytes", "evidence_list[].size_bytes"), ("upload_time", "evidence_list[].upload_time")],
        [("evidence_list", "evidence_list"), ("filename", "evidence_list[].filename"), ("hash", "evidence_list[].sha256|evidence_list[].file_hash"), ("verification_status", "evidence_list[].verification_status")],
        [("hash_chain", "hash_chain|chain_of_custody"), ("hash_chain.status", "hash_chain.status|chain_of_custody.status"), ("hash_chain.breaks", "hash_chain.breaks|chain_of_custody.breaks"), ("hash_chain.first_break_at", "hash_chain.first_break_at|chain_of_custody.first_break_at")],
        [("parsing_summary", "parsing_summary"), ("total_records", "parsing_summary.total_records"), ("parsed_records", "parsing_summary.parsed_records"), ("unparsed_records", "parsing_summary.unparsed_records"), ("errors", "parsing_summary.errors")],
        [("hot_store", "hot_store"), ("tables", "hot_store.tables")],
        [("signals", "signals")],
        [("anomaly_detection", "anomaly_detection"), ("scored_records", "anomaly_detection.scored_records"), ("anomalies_flagged", "anomaly_detection.anomalies_flagged"), ("score_min", "anomaly_detection.score_min"), ("score_max", "anomaly_detection.score_max"), ("scores", "anomaly_detection.scores")],
        [("alerts", "alerts"), ("entity", "alerts[].entity"), ("risk_score", "alerts[].risk_score"), ("risk_level", "alerts[].risk_level"), ("triggers", "alerts[].triggers")],
        [("timeline", "timeline"), ("timestamp", "timeline[].timestamp"), ("risk_score", "timeline[].risk_score"), ("summary", "timeline[].summary"), ("signals", "signals"), ("alerts", "alerts")]
    ]

def _coverage_table_for(idx: int, raw: Dict[str, Any], exp: List[List[Tuple[str, str]]]) -> Dict[str, Any]:
    new_rows: List[List[str]]= []
    if 0 <= idx < len(exp):
        for new_label, new_path in exp[ idx ]:
            new_rows.append([new_label, "Yes" if _present_path(raw, new_path) else "No"])
    if not new_rows:
        new_rows= [["N/A", "No"]]
    return {"title": "Data Coverage", "columns": ["Expected Field", "Present"], "rows": new_rows}

def _missing_fields_for(idx: int, raw: Dict[str, Any], exp: List[List[Tuple[str, str]]]) -> List[str]:
    new_miss: List[str]= []
    if 0 <= idx < len(exp):
        for new_label, new_path in exp[ idx ]:
            if not _present_path(raw, new_path):
                new_miss.append(new_label)
    return new_miss

def _availability_paragraphs(missing: List[str]) -> List[str]:
    if not missing:
        return []
    new_m= ", ".join(missing[ :12 ])
    new_p= []
    new_p.append(f"Data availability note: the following expected fields were not present in the input payload: {new_m}.")
    new_p.append("Because these fields are missing, some summaries in this section may be incomplete or conservative, and specific conclusions may require re-ingestion or source-side validation.")
    new_p.append("If you can provide the missing fields on the next run, this section will automatically expand with stronger evidence-backed statements.")
    return new_p

def _extra_paragraphs(idx: int, stats: Dict[str, Any]) -> List[str]:
    new_ev= _safe_list(stats.get("ev"))
    new_sc= _safe_dict(stats.get("status_counts"))
    new_parsing= _safe_dict(stats.get("parsing"))
    new_hot= _safe_dict(stats.get("hot"))
    new_signals= _safe_dict(stats.get("signals"))
    new_anomaly= _safe_dict(stats.get("anomaly"))
    new_alerts= _safe_list(stats.get("alerts"))
    new_timeline= _safe_list(stats.get("timeline"))
    new_hash_chain= _safe_dict(stats.get("hash_chain"))
    new_file_count= len(new_ev)
    new_total_size= _human_bytes(stats.get("total_size", 0))
    new_earliest= _fmt_dt(stats.get("earliest"))
    new_latest= _fmt_dt(stats.get("latest"))
    new_extra: List[str]= []
    if idx == 0:
        new_extra.append(f"Evidence volume summary: {new_file_count} artifacts totaling {new_total_size}, observed between {new_earliest} and {new_latest}.")
        new_extra.append("This snapshot is intended to be a quick orientation layer before drilling into integrity, custody continuity, parsing coverage, and detection outputs.")
    elif idx == 1:
        new_largest= _safe_list(stats.get("largest"))
        if new_largest and isinstance(new_largest[ 0 ], dict):
            new_extra.append(f"Largest artifact observed: {new_largest[ 0 ].get('filename', 'N/A')} at {_human_bytes(new_largest[ 0 ].get('size_bytes'))}.")
        new_extra.append("Large artifacts often dominate runtime and are good candidates for prioritized indexing and targeted extraction.")
    elif idx == 2:
        new_valid= int(new_sc.get("VALID", 0) or 0)
        new_bad= 0
        for new_k, new_v in new_sc.items():
            if str(new_k).upper() in ["CORRUPTED", "INVALID", "FAIL"]:
                try:
                    new_bad+= int(new_v)
                except Exception:
                    pass
        new_extra.append(f"Integrity roll-up: VALID={new_valid}, CORRUPTED/FAIL={new_bad}.")
        new_extra.append("Any failures should be isolated to avoid contaminating derived signals and anomaly scoring.")
    elif idx == 3:
        new_extra.append(f"Custody continuity indicator: status={new_hash_chain.get('status', 'N/A')}, breaks={new_hash_chain.get('breaks', 'N/A')}.")
        new_extra.append("If custody breaks exist, treat post-break artifacts as disputed until independently validated.")
    elif idx == 4:
        new_extra.append(f"Parsing coverage: total={new_parsing.get('total_records', 'N/A')}, parsed={new_parsing.get('parsed_records', 'N/A')}, unparsed={new_parsing.get('unparsed_records', 'N/A')}.")
        new_extra.append("Reducing dominant parse errors typically increases downstream correlation quality and lowers investigation blind spots.")
    elif idx == 5:
        new_tables= _safe_dict(new_hot.get("tables"))
        if new_tables:
            new_top= sorted(new_tables.items(), key=lambda x: _num(x[ 1 ]), reverse=True)[ :3 ]
            new_extra.append("DuckDB materialization sanity check: " + ", ".join([f"{k}={v}" for k, v in new_top]) + ".")
        new_extra.append("Missing or near-empty tables usually indicate upstream parsing/mapping issues rather than a true absence of activity.")
    elif idx == 6:
        if new_signals:
            new_items= []
            for new_k, new_v in new_signals.items():
                if isinstance(new_v, dict):
                    new_items.append((new_k, _num(new_v.get("count", 0))))
                else:
                    new_items.append((new_k, _num(new_v)))
            new_items= sorted(new_items, key=lambda x: x[ 1 ], reverse=True)[ :5 ]
            new_extra.append("Most frequent signals: " + ", ".join([f"{k}({int(v)})" for k, v in new_items]) + ".")
        new_extra.append("Signals are best interpreted as pivots: use them to jump into the exact event slices and supporting artifacts.")
    elif idx == 7:
        new_extra.append(f"Anomaly scoring summary: scored={new_anomaly.get('scored_records', 'N/A')}, flagged={new_anomaly.get('anomalies_flagged', 'N/A')}.")
        new_extra.append("Flagged records are triage candidates; corroborate them using integrity, custody continuity, and correlated telemetry.")
    elif idx == 8:
        if new_alerts:
            new_extra.append(f"Alert volume: {len(new_alerts)} alert rows available for ranking and triage.")
        new_extra.append("Entity aggregation helps reduce noise by focusing effort on the smallest set of principals accounting for most risk.")
    elif idx == 9:
        if new_timeline:
            new_peaks= sorted([t for t in new_timeline if isinstance(t, dict)], key=lambda x: _num(x.get("risk_score", 0)), reverse=True)[ :2 ]
            if new_peaks:
                new_extra.append(f"Top peak window example: {_fmt_dt(new_peaks[ 0 ].get('timestamp'))} with risk {new_peaks[ 0 ].get('risk_score', 'N/A')}.")
        new_extra.append("Recommended actions are generated from dominant triggers and should be logged with operator identity and timestamps.")
    return new_extra

def _enforce_no_blank_sections(preview: Dict[str, Any], raw: Dict[str, Any]) -> Dict[str, Any]:
    new_pv= _safe_dict(preview)
    new_pages= new_pv.get("pages")
    if not isinstance(new_pages, list):
        return new_pv
    new_exp= _expected_fields()
    new_stats= _extract_stats(raw)
    for new_idx in range(len(new_pages)):
        new_sec= new_pages[ new_idx ]
        if not isinstance(new_sec, dict):
            continue
        new_paras= []
        for new_p in _safe_list(new_sec.get("paragraphs")):
            if isinstance(new_p, str) and new_p.strip():
                new_paras.append(new_p.strip())
        new_sec[ "paragraphs" ]= new_paras
        new_chs= []
        for new_c in _safe_list(new_sec.get("charts")):
            if isinstance(new_c, dict) and new_c.get("b64"):
                new_chs.append(new_c)
        new_sec[ "charts" ]= new_chs
        new_tbs= []
        for new_tb in _safe_list(new_sec.get("tables")):
            if not isinstance(new_tb, dict):
                continue
            new_cols= new_tb.get("columns")
            new_rows= new_tb.get("rows")
            new_cols_ok= isinstance(new_cols, list) and len(new_cols) > 0
            new_rows_ok= isinstance(new_rows, list) and len(new_rows) > 0
            if not new_cols_ok and not new_rows_ok:
                continue
            new_tbs.append(new_tb)
        new_sec[ "tables" ]= new_tbs
        new_lss= []
        for new_ls in _safe_list(new_sec.get("lists")):
            if not isinstance(new_ls, dict):
                continue
            new_items= new_ls.get("items")
            if not isinstance(new_items, list) or len(new_items) == 0:
                continue
            new_clean_items= []
            for new_it in new_items:
                if new_it is None:
                    continue
                new_s= str(new_it)
                if new_s.strip():
                    new_clean_items.append(new_s.strip())
            if len(new_clean_items) == 0:
                continue
            new_ls[ "items" ]= new_clean_items
            new_lss.append(new_ls)
        new_sec[ "lists" ]= new_lss
        if len(new_sec[ "paragraphs" ]) < 3:
            for new_p in _extra_paragraphs(new_idx, new_stats):
                if len(new_sec[ "paragraphs" ]) >= 3:
                    break
                if isinstance(new_p, str) and new_p.strip():
                    new_sec[ "paragraphs" ].append(new_p.strip())
        if len(new_sec[ "paragraphs" ]) < 3:
            new_missing= _missing_fields_for(new_idx, raw, new_exp)
            for new_p in _availability_paragraphs(new_missing):
                if len(new_sec[ "paragraphs" ]) >= 3:
                    break
                if isinstance(new_p, str) and new_p.strip():
                    new_sec[ "paragraphs" ].append(new_p.strip())
        if len(new_sec[ "paragraphs" ]) == 0:
            new_sec[ "paragraphs" ]= ["No narrative content could be generated for this section from the provided payload."]
        if len(new_sec.get("charts", [])) == 0 and len(new_sec.get("tables", [])) == 0 and len(new_sec.get("lists", [])) == 0:
            new_sec[ "tables" ]= _safe_list(new_sec.get("tables")) + [_coverage_table_for(new_idx, raw, new_exp)]
        new_pages[ new_idx ]= new_sec
    new_pv[ "pages" ]= new_pages
    return new_pv

def _build_pages(raw: Dict[str, Any], new_gstyle: str = "classic", selected_graphs: List[str] = None) -> Dict[str, Any]:
    if selected_graphs is None:
        selected_graphs= ["file_types", "integrity", "signals", "top_entities", "timeline", "scores", "parse_errors", "duckdb"]
    new_stats= _extract_stats(raw)
    new_case_id= raw.get("case_id", "CASE-UNKNOWN")
    new_generated_at= raw.get("generated_at", datetime.now().isoformat())
    new_verdict_text, new_verdict_reason= _verdict(new_stats)
    new_ev= _safe_list(new_stats.get("ev"))
    new_file_count= len(new_ev)
    new_total_size= _human_bytes(new_stats.get("total_size", 0))
    new_earliest= _fmt_dt(new_stats.get("earliest"))
    new_latest= _fmt_dt(new_stats.get("latest"))
    new_ft_sorted= sorted(_safe_dict(new_stats.get("file_types")).items(), key=lambda x: x[ 1 ], reverse=True)
    new_top_types= ", ".join([f"{k}({v})" for k, v in new_ft_sorted[ :5 ]]) if new_ft_sorted else "N/A"
    new_p1= [
        f"Case {new_case_id} was processed to summarize evidence intake, integrity, custody continuity, normalization quality, behavioral signals, and anomaly outcomes.",
        f"The dataset contains {new_file_count} artifacts with a combined size of {new_total_size}. The observed upload window spans from {new_earliest} to {new_latest}.",
        f"Most frequent formats in this dataset: {new_top_types}. These distributions help anticipate which parsers and correlation paths will contribute most to the investigation."
    ]
    new_largest_rows= []
    for new_f in _safe_list(new_stats.get("largest")):
        if not isinstance(new_f, dict):
            continue
        new_largest_rows.append([new_f.get("filename", "N/A"), (new_f.get("file_type") or "unknown"), _human_bytes(new_f.get("size_bytes")), _fmt_dt(new_f.get("upload_time"))])
    new_p2= [
        "Evidence intake summarizes what was received, when it was received, and how it was categorized for downstream processing.",
        "Artifacts are grouped by format and size to identify heavy sources (for example, memory dumps or PCAP segments) and to verify that the expected telemetry types are present.",
        "The table below highlights the largest artifacts, which typically dominate processing time and often hold high-value forensic context."
    ]
    new_sc= _safe_dict(new_stats.get("status_counts"))
    new_valid= int(new_sc.get("VALID", 0) or 0)
    new_corrupted= 0
    for new_k, new_v in new_sc.items():
        if str(new_k).upper() in ["CORRUPTED", "INVALID", "FAIL"]:
            try:
                new_corrupted+= int(new_v)
            except Exception:
                pass
    new_integrity_rows= []
    for new_f in _safe_list(new_ev)[ :20 ]:
        if isinstance(new_f, dict):
            new_integrity_rows.append([new_f.get("filename", "N/A"), _short_hash(new_f.get("sha256") or new_f.get("file_hash")), (new_f.get("verification_status") or "UNKNOWN").upper()])
    new_p3= [
        "Per-file integrity verification ensures evidence remains bit-consistent from intake through processing.",
        f"Overall distribution: VALID={new_valid}, CORRUPTED/FAIL={new_corrupted}.",
        "Any corrupted or failed artifacts should be isolated for re-acquisition or manual handling to avoid contaminating downstream analytics."
    ]
    new_hc= _safe_dict(new_stats.get("hash_chain"))
    new_hc_status= (new_hc.get("status") or "N/A")
    new_hc_breaks= new_hc.get("breaks", "N/A")
    new_hc_first_break= new_hc.get("first_break_at", None)
    new_p4= [
        "Chain-of-custody status summarizes whether custody continuity was preserved across the evidence lifecycle.",
        f"Hash chain status: {new_hc_status}. Breaks observed: {new_hc_breaks}. First break: {_fmt_dt(new_hc_first_break)}.",
        "If breaks are present, evidence after the first break should be treated as disputed until independently validated."
    ]
    new_parsing= _safe_dict(new_stats.get("parsing"))
    new_total_records= new_parsing.get("total_records", None)
    new_parsed_records= new_parsing.get("parsed_records", None)
    new_unparsed_records= new_parsing.get("unparsed_records", None)
    new_err= _safe_dict(new_parsing.get("errors"))
    new_err_items= sorted(new_err.items(), key=lambda x: _num(x[ 1 ]), reverse=True)[ :6 ]
    new_err_text= ", ".join([f"{k}={v}" for k, v in new_err_items]) if new_err_items else "N/A"
    new_p5= [
        "Parsing and normalization summarize how much raw telemetry could be converted into structured records ready for correlation.",
        f"Records: total={new_total_records if new_total_records is not None else 'N/A'}, parsed={new_parsed_records if new_parsed_records is not None else 'N/A'}, unparsed={new_unparsed_records if new_unparsed_records is not None else 'N/A'}.",
        f"Top parse error reasons: {new_err_text}. Addressing dominant error types typically improves coverage and reduces blind spots."
    ]
    new_hot= _safe_dict(new_stats.get("hot"))
    new_tables= _safe_dict(new_hot.get("tables"))
    new_hot_rows= [[k, str(v)] for k, v in sorted(new_tables.items(), key=lambda x: _num(x[ 1 ]), reverse=True)] if new_tables else []
    new_p6= [
        "Hot store ingestion summarizes which normalized datasets were materialized for fast querying and analytics.",
        "DuckDB table counts are a quick sanity check: they confirm that event streams, entities, indicators, and alerts were actually persisted after parsing.",
        "If any expected table is missing or near-empty, it usually indicates an upstream parsing or mapping issue."
    ]
    new_signals= _safe_dict(new_stats.get("signals"))
    new_sig_items: Dict[str, float]= {}
    for new_k, new_v in new_signals.items():
        if isinstance(new_v, dict):
            new_sig_items[ new_k ]= _num(new_v.get("count", 0))
        else:
            new_sig_items[ new_k ]= _num(new_v)
    new_p7= [
        "Behavioral features describe what signals were computed from normalized records (for example: login velocity spikes, impossible travel, privilege escalations).",
        "Signal counts give a quick view of coverage: higher counts often represent broad, low-confidence indicators; smaller counts can represent high-precision detections.",
        "The chart below highlights the most frequent signals in this dataset."
    ]
    new_anomaly= _safe_dict(new_stats.get("anomaly"))
    new_scored= new_anomaly.get("scored_records", None)
    new_flagged= new_anomaly.get("anomalies_flagged", None)
    new_smin= new_anomaly.get("score_min", None)
    new_smax= new_anomaly.get("score_max", None)
    new_scores_list= new_anomaly.get("scores", [])
    new_scores_vals: List[float]= []
    for new_x in _safe_list(new_scores_list):
        try:
            new_scores_vals.append(float(new_x))
        except Exception:
            pass
    new_p8= [
        "Anomaly detection summarizes how many records were scored and how many were flagged above the anomaly threshold.",
        f"Scored={new_scored if new_scored is not None else 'N/A'}, flagged={new_flagged if new_flagged is not None else 'N/A'}, score range={new_smin if new_smin is not None else 'N/A'} to {new_smax if new_smax is not None else 'N/A'}.",
        "A tight score range usually indicates stable behavior; sharp peaks or long tails typically indicate bursty or staged activity."
    ]
    new_entity_risks: Dict[str, float]= {}
    for new_a in _safe_list(new_stats.get("alerts")):
        if not isinstance(new_a, dict):
            continue
        new_e= new_a.get("entity", "unknown")
        new_rs= _num(new_a.get("risk_score", 0))
        new_entity_risks[ new_e ]= max(new_entity_risks.get(new_e, 0.0), new_rs)
    new_top_entities= sorted(new_entity_risks.items(), key=lambda x: x[ 1 ], reverse=True)[ :10 ]
    new_alert_rows= []
    for new_a in _safe_list(new_stats.get("alerts"))[ :15 ]:
        if isinstance(new_a, dict):
            new_tr= new_a.get("triggers")
            if isinstance(new_tr, list):
                new_tr_s= ", ".join([str(x) for x in new_tr if x is not None])
            else:
                new_tr_s= str(new_tr or "")
            new_alert_rows.append([new_a.get("entity", "N/A"), str(new_a.get("risk_score", "N/A")), str(new_a.get("risk_level", "N/A")), new_tr_s[ :80 ]])
    new_p9= [
        "High-risk entities consolidate alerts by principal (user, host, IP, domain) and provide a ranked view of the most concerning actors.",
        "A small number of entities frequently account for most high-confidence risk, making them good candidates for triage and containment checks.",
        "The table below lists the highest-risk items and the triggers that caused scoring."
    ]
    new_tl= _safe_list(new_stats.get("timeline"))
    new_peaks= sorted([t for t in new_tl if isinstance(t, dict)], key=lambda x: _num(x.get("risk_score", 0)), reverse=True)[ :5 ]
    new_peak_lines= []
    for new_t in new_peaks:
        new_peak_lines.append(f"{_fmt_dt(new_t.get('timestamp'))} — risk {new_t.get('risk_score', 'N/A')} — {new_t.get('summary', 'Peak activity window.')}")
    new_rec_actions= _recommended_actions(new_stats)
    new_p10= [
        "Timeline highlights summarize how risk evolved over the observed window and identify the most important time slices for deeper artifact correlation.",
        "Peak windows are the best starting point for reconstruction: pivot from the timestamp into supporting logs, process events, DNS, and network captures.",
        "Recommended actions are derived from the dominant triggers observed in signals and entity alerts."
    ]
    
    new_charts= {}
    if "file_types" in selected_graphs and _safe_dict(new_stats.get("file_types")):
        new_ft_items= sorted(_safe_dict(new_stats.get("file_types")).items(), key=lambda x: x[ 1 ], reverse=True)
        if len(new_ft_items) > 7:
            new_ft_top= new_ft_items[ :6 ]
            new_ft_other= sum(v for _, v in new_ft_items[ 6: ])
            new_ft_items= new_ft_top + [("other", new_ft_other)]
            
        new_charts[ "file_types" ]= {
            "b64": _b64_png_from_buf(GraphEngine.pie_chart(_safe_dict(new_stats.get("file_types")), "Evidence File Type Distribution", new_gstyle)),
            "type": "pie",
            "data": [{"name": str(k), "value": _num(v)} for k, v in new_ft_items]
        }
    if "integrity" in selected_graphs and _safe_dict(new_stats.get("status_counts")):
        new_charts[ "integrity" ]= {
            "b64": _b64_png_from_buf(GraphEngine.bar_chart({k: _num(v) for k, v in _safe_dict(new_stats.get("status_counts")).items()}, "Integrity Verification Results", "Status", new_gstyle)),
            "type": "bar",
            "data": [{"name": k, "value": _num(v)} for k, v in _safe_dict(new_stats.get("status_counts")).items()]
        }
    if "signals" in selected_graphs and new_sig_items:
        new_charts[ "signals" ]= {
            "b64": _b64_png_from_buf(GraphEngine.bar_chart(new_sig_items, "Top Behavioral Signals", "Signal", new_gstyle)),
            "type": "bar",
            "data": [{"name": k, "value": v} for k, v in sorted(new_sig_items.items(), key=lambda x: x[ 1 ], reverse=True)[ :10 ]]
        }
    if "top_entities" in selected_graphs and new_top_entities:
        new_charts[ "top_entities" ]= {
            "b64": _b64_png_from_buf(GraphEngine.horizontal_bar(dict(new_top_entities), "Top High-Risk Entities", new_gstyle)),
            "type": "horizontal_bar",
            "data": [{"name": k, "value": v} for k, v in new_top_entities[ :10 ]]
        }
    if "timeline" in selected_graphs and new_tl:
        new_charts[ "timeline" ]= {
            "b64": _b64_png_from_buf(GraphEngine.line_chart(new_tl, "Risk Score Over Time", new_gstyle)),
            "type": "line",
            "data": [{"name": _fmt_dt(t.get('timestamp'))[ 11:16 ] if _fmt_dt(t.get('timestamp')) != "N/A" else "N/A", "value": _num(t.get('risk_score', 0))} for t in new_tl]
        }
    if "scores" in selected_graphs and new_scores_vals:
        new_bins= [0] * 10
        for new_s in new_scores_vals:
            new_bins[ min(int(new_s * 10), 9) ]+= 1
        new_charts[ "scores" ]= {
            "b64": _b64_png_from_buf(GraphEngine.hist_chart(new_scores_vals, "Anomaly Score Distribution", new_gstyle)),
            "type": "bar",
            "data": [{"name": f"{i/10:.1f}", "value": new_bins[ i ]} for i in range(10)]
        }
    if "parse_errors" in selected_graphs and new_err:
        new_charts[ "parse_errors" ]= {
            "b64": _b64_png_from_buf(GraphEngine.bar_chart({k: _num(v) for k, v in new_err.items()}, "Top Parse Error Reasons", "Error Type", new_gstyle)),
            "type": "bar",
            "data": [{"name": k, "value": _num(v)} for k, v in sorted(new_err.items(), key=lambda x: _num(x[ 1 ]), reverse=True)[ :10 ]]
        }
    if "duckdb" in selected_graphs and new_tables:
        new_charts[ "duckdb" ]= {
            "b64": _b64_png_from_buf(GraphEngine.bar_chart({k: _num(v) for k, v in new_tables.items()}, "DuckDB Table Row Counts", "Table", new_gstyle)),
            "type": "bar",
            "data": [{"name": k, "value": _num(v)} for k, v in sorted(new_tables.items(), key=lambda x: _num(x[ 1 ]), reverse=True)[ :10 ]]
        }

    new_toc= [
        "Case Snapshot and Dataset Overview",
        "Evidence Intake Summary (Files, Formats, Sizes, Upload Times)",
        "Integrity Status (Per-File Hash Verification Results)",
        "Chain-of-Custody Status (Hash Chain Verification Results)",
        "Parsing and Normalization Summary (Parsed vs Unparsed Records)",
        "Hot Store Ingestion Summary (DuckDB Tables and Row Counts)",
        "Behavioral Feature Summary (Signals Generated and Coverage)",
        "Anomaly Detection Summary (Total Scored, Anomalies Flagged, Score Range)",
        "High-Risk Entities and Alerts (Users/IPs, Risk Levels, Key Triggers)",
        "Investigation Timeline Highlights and Recommended Actions"
    ]

    new_pages= [
        {"title": new_toc[ 0 ], "paragraphs": new_p1, "tables": [], "charts": [new_charts[ "file_types" ]] if "file_types" in new_charts else [], "lists": []},
        {"title": new_toc[ 1 ], "paragraphs": new_p2, "tables": [{"title": "Largest Artifacts (Top 10)", "columns": ["Filename", "Type", "Size", "Upload Time"], "rows": new_largest_rows}] if new_largest_rows else [], "charts": [], "lists": []},
        {"title": new_toc[ 2 ], "paragraphs": new_p3, "tables": [{"title": "Integrity Status (First 20)", "columns": ["Filename", "SHA-256 (short)", "Status"], "rows": new_integrity_rows}] if new_integrity_rows else [], "charts": [new_charts[ "integrity" ]] if "integrity" in new_charts else [], "lists": []},
        {"title": new_toc[ 3 ], "paragraphs": new_p4, "tables": [{"title": "Hash Chain Summary", "columns": ["Status", "Breaks", "First Break"], "rows": [[str(new_hc_status), str(new_hc_breaks), _fmt_dt(new_hc_first_break)]]}], "charts": [], "lists": []},
        {"title": new_toc[ 4 ], "paragraphs": new_p5, "tables": [], "charts": ([new_charts[ "parse_errors" ]] if "parse_errors" in new_charts else []), "lists": []},
        {"title": new_toc[ 5 ], "paragraphs": new_p6, "tables": [{"title": "DuckDB Materialization", "columns": ["Table", "Rows"], "rows": new_hot_rows}] if new_hot_rows else [], "charts": ([new_charts[ "duckdb" ]] if "duckdb" in new_charts else []), "lists": []},
        {"title": new_toc[ 6 ], "paragraphs": new_p7, "tables": [], "charts": ([new_charts[ "signals" ]] if "signals" in new_charts else []), "lists": []},
        {"title": new_toc[ 7 ], "paragraphs": new_p8, "tables": [], "charts": ([new_charts[ "scores" ]] if "scores" in new_charts else []), "lists": []},
        {"title": new_toc[ 8 ], "paragraphs": new_p9, "tables": [{"title": "Top Alerts (First 15)", "columns": ["Entity", "Risk Score", "Risk Level", "Key Triggers"], "rows": new_alert_rows}] if new_alert_rows else [], "charts": ([new_charts[ "top_entities" ]] if "top_entities" in new_charts else []), "lists": []},
        {"title": new_toc[ 9 ], "paragraphs": new_p10, "tables": [], "charts": ([new_charts[ "timeline" ]] if "timeline" in new_charts else []), "lists": [{"title": "Peak Windows (Top 5)", "items": new_peak_lines} if new_peak_lines else {"title": "Peak Windows", "items": ["N/A"]}, {"title": "Recommended Actions", "items": new_rec_actions}]},
    ]
    return {
        "meta": {"case_id": new_case_id, "generated_at": new_generated_at, "verdict": new_verdict_text, "verdict_reason": new_verdict_reason, "cover_b64": _get_cover_b64()},
        "toc": [{"no": k + 1, "title": new_toc[ k ], "page": "-"} for k in range(len(new_toc))],
        "pages": new_pages
    }

def build_report_preview(raw_data_object, new_gstyle="classic", selected_graphs=None):
    new_raw= _safe_dict(raw_data_object)
    new_preview= _build_pages(new_raw, new_gstyle, selected_graphs)
    return _enforce_no_blank_sections(new_preview, new_raw)

def generate_forensic_report(
    raw_data_object: Dict[str, Any],
    language="English",
    custom_color=None,
    output_path: Optional[str] = None,
    cover_path: Optional[str] = None,
    new_gstyle="classic",
    selected_graphs=None
) -> str:
    new_preview= build_report_preview(raw_data_object, new_gstyle, selected_graphs)
    new_case_id= new_preview[ "meta" ][ "case_id" ]
    new_filename= output_path or f"FULL_REPORT_{new_case_id}.pdf"
    new_doc= SimpleDocTemplate(new_filename, pagesize=A4, topMargin=40, bottomMargin=40, leftMargin=40, rightMargin=40)
    new_theme_color= colors.HexColor(custom_color) if custom_color else colors.HexColor("#003366")
    new_styles= getSampleStyleSheet()
    new_h2= ParagraphStyle("H2", parent=new_styles[ "Heading2" ], fontSize=12, textColor=new_theme_color, spaceBefore=10, spaceAfter=6)
    new_body= ParagraphStyle("Body", parent=new_styles[ "Normal" ], fontSize=10, leading=14, alignment=TA_JUSTIFY)
    new_story: List[Any]= []

    def _draw_cover_dynamic(canvas, doc_obj):
        new_path_to_use= cover_path if cover_path and os.path.exists(cover_path) else os.path.join(os.path.dirname(__file__), "assets", "cover.png")
        new_w, new_h= A4
        canvas.saveState()
        if new_path_to_use and os.path.exists(new_path_to_use):
            canvas.drawImage(ImageReader(new_path_to_use), 0, 0, width=new_w, height=new_h, mask="auto")
        else:
            canvas.setFillColor(new_theme_color)
            canvas.rect(0, 0, new_w, new_h, fill=1)
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", 32)
            canvas.drawCentredString(new_w/2, new_h/2 + 60, "DYNAMITE DYNASTY")
            canvas.setFont("Helvetica", 18)
            canvas.drawCentredString(new_w/2, new_h/2 + 20, "OFFICIAL FORENSIC DOSSIER")
            canvas.setFont("Helvetica", 12)
            canvas.drawCentredString(new_w/2, new_h/2 - 40, f"Target: {new_case_id}")
            canvas.drawCentredString(new_w/2, 50, "CONFIDENTIAL & RESTRICTED ACCESS")
        canvas.restoreState()

    new_story.append(Spacer(1, 1))
    new_story.append(PageBreak())
    new_story.append(Paragraph("TABLE OF CONTENTS", new_h2))
    new_toc_rows= [["#", "SECTION TITLE", "PAGE"]]
    for new_r in _safe_list(new_preview.get("toc")):
        if isinstance(new_r, dict):
            new_toc_rows.append([str(new_r.get("no", "")), str(new_r.get("title", "")), str(new_r.get("page", ""))])
    new_tt= Table(new_toc_rows, colWidths=[30, 380, 50])
    new_tt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    new_story.append(new_tt)
    new_story.append(PageBreak())
    new_pages= _safe_list(new_preview.get("pages"))
    for new_i, new_sec in enumerate(new_pages, start=1):
        if not isinstance(new_sec, dict):
            continue
        new_story.append(Paragraph(f"{new_i}. {new_sec.get('title', 'Untitled')}", new_h2))
        for new_para in _safe_list(new_sec.get("paragraphs")):
            new_story.append(Paragraph(str(new_para), new_body))
            new_story.append(Spacer(1, 8))
        for new_ch in _safe_list(new_sec.get("charts")):
            if not isinstance(new_ch, dict):
                continue
            new_b64= new_ch.get("b64")
            if not new_b64:
                continue
            new_img_bytes= base64.b64decode(str(new_b64).encode("utf-8"))
            new_buf= io.BytesIO(new_img_bytes)
            new_story.append(Image(new_buf, width=5.5 * inch, height=2.75 * inch))
            new_story.append(Spacer(1, 10))
        for new_tb in _safe_list(new_sec.get("tables")):
            if not isinstance(new_tb, dict):
                continue
            new_story.append(Paragraph(new_tb.get("title", ""), ParagraphStyle("TBH", parent=new_styles[ "Normal" ], fontSize=10, textColor=new_theme_color, spaceBefore=6, spaceAfter=6)))
            new_cols= new_tb.get("columns", [])
            new_rows= new_tb.get("rows", [])
            new_cols= new_cols if isinstance(new_cols, list) else []
            new_rows= new_rows if isinstance(new_rows, list) else []
            new_table_data= [new_cols] + new_rows if new_cols else new_rows
            new_col_widths= None
            if new_cols and len(new_cols) == 4:
                new_col_widths= [220, 60, 70, 120]
            elif new_cols and len(new_cols) == 3:
                new_col_widths= [260, 140, 80]
            elif new_cols and len(new_cols) == 2:
                new_col_widths= [300, 150]
            new_rt= Table(new_table_data, colWidths=new_col_widths)
            new_rt.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), new_theme_color if new_cols else colors.white),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            new_story.append(new_rt)
            new_story.append(Spacer(1, 10))
        for new_ls in _safe_list(new_sec.get("lists")):
            if not isinstance(new_ls, dict):
                continue
            new_story.append(Paragraph(new_ls.get("title", ""), ParagraphStyle("LSH", parent=new_styles[ "Normal" ], fontSize=10, textColor=new_theme_color, spaceBefore=6, spaceAfter=4)))
            for new_item in _safe_list(new_ls.get("items")):
                new_story.append(Paragraph("• " + str(new_item), new_body))
            new_story.append(Spacer(1, 6))
        if new_i != len(new_pages):
            new_story.append(Spacer(1, 20))
    new_doc.build(new_story, onFirstPage=_draw_cover_dynamic)
    return new_filename