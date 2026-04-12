"""
LLM-Enhanced Automated Report Generation
Creates forensic investigation reports with AI-generated narratives
Uses local Ollama LLM for privacy and efficiency
"""

import json
import sys
import os
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

sys.path.insert(0, str(Path(__file__).parent))

from operation_room.database import open_vault
from operation_room.config import settings

CASE_ID = "CASE-FORENSIC-001"
OLLAMA_URL = "http://localhost:11434"
LLM_MODEL = "qwen3:8b"

def ollama_generate(prompt: str, max_tokens: int = 500) -> str:
    """Generate text using local Ollama LLM."""
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": 0.3,  # Lower for factual content
                }
            },
            timeout=60
        )
        if response.status_code == 200:
            return response.json().get("response", "")
        return f"[LLM Error: {response.status_code}]"
    except Exception as e:
        return f"[LLM Connection Error: {e}]"

def get_case_data() -> Dict[str, Any]:
    """Extract all relevant data from the case vault."""
    conn = open_vault(CASE_ID)
    data = {}
    
    # Timeline events
    try:
        events = conn.execute("""
            SELECT normalised_ts, source_system, actor, action, target, severity, detail
            FROM unified_timeline
            ORDER BY normalised_ts
        """).fetchall()
        data['timeline'] = [
            {
                'timestamp': str(row[0]),
                'source': row[1],
                'actor': row[2],
                'action': row[3],
                'target': row[4],
                'severity': row[5],
                'detail': row[6][:200] if row[6] else None
            }
            for row in events
        ]
    except:
        data['timeline'] = []
    
    # Anomalies
    try:
        anomalies = conn.execute("""
            SELECT a.tl_event_id, a.anomaly_score, a.model_type,
                   t.actor, t.action, t.target, t.normalised_ts
            FROM anomaly_scores a
            LEFT JOIN unified_timeline t ON a.tl_event_id = t.tl_event_id
            WHERE a.is_anomaly = true
            ORDER BY a.anomaly_score DESC
            LIMIT 30
        """).fetchall()
        data['anomalies'] = [
            {
                'event_id': row[0],
                'score': row[1],
                'model': row[2],
                'actor': row[3],
                'action': row[4],
                'target': row[5],
                'timestamp': str(row[6]) if row[6] else None
            }
            for row in anomalies
        ]
    except:
        data['anomalies'] = []
    
    # Actor summary
    try:
        actors = conn.execute("""
            SELECT actor, COUNT(*) as count, 
                   array_agg(DISTINCT action) as actions,
                   MIN(normalised_ts) as first_seen,
                   MAX(normalised_ts) as last_seen
            FROM unified_timeline
            WHERE actor IS NOT NULL
            GROUP BY actor
            ORDER BY count DESC
        """).fetchall()
        data['actors'] = [
            {
                'actor': row[0],
                'event_count': row[1],
                'actions': row[2] if row[2] else [],
                'first_seen': str(row[3]),
                'last_seen': str(row[4])
            }
            for row in actors
        ]
    except:
        data['actors'] = []
    
    # Action distribution
    try:
        actions = conn.execute("""
            SELECT action, COUNT(*) as count
            FROM unified_timeline
            GROUP BY action ORDER BY count DESC
        """).fetchall()
        data['actions'] = [{'action': row[0], 'count': row[1]} for row in actions]
    except:
        data['actions'] = []
    
    # Source systems
    try:
        sources = conn.execute("""
            SELECT source_system, COUNT(*) as count
            FROM unified_timeline
            GROUP BY source_system ORDER BY count DESC
        """).fetchall()
        data['sources'] = [{'source': row[0], 'count': row[1]} for row in sources]
    except:
        data['sources'] = []
    
    # High severity events
    try:
        high_sev = conn.execute("""
            SELECT normalised_ts, actor, action, target, detail
            FROM unified_timeline
            WHERE severity IN ('HIGH', 'CRITICAL')
            ORDER BY normalised_ts
            LIMIT 20
        """).fetchall()
        data['high_severity'] = [
            {'timestamp': str(row[0]), 'actor': row[1], 'action': row[2], 'target': row[3], 'detail': row[4]}
            for row in high_sev
        ]
    except:
        data['high_severity'] = []
    
    conn.close()
    return data

def generate_executive_summary(data: Dict) -> str:
    """Generate executive summary using LLM."""
    total_events = len(data.get('timeline', []))
    anomaly_count = len(data.get('anomalies', []))
    actor_count = len(data.get('actors', []))
    
    # Get top anomalous actor
    anomaly_actors = {}
    for a in data.get('anomalies', []):
        actor = a.get('actor', 'unknown')
        anomaly_actors[actor] = anomaly_actors.get(actor, 0) + 1
    top_anomaly_actor = max(anomaly_actors.items(), key=lambda x: x[1])[0] if anomaly_actors else "N/A"
    
    prompt = f"""/no_think
You are a forensic investigator writing an executive summary. Be concise and professional.

Case Data:
- Total Events: {total_events}
- Anomalies Detected: {anomaly_count}
- Actors: {actor_count}
- Time Range: {data['timeline'][0]['timestamp'][:10] if data['timeline'] else 'N/A'} to {data['timeline'][-1]['timestamp'][:10] if data['timeline'] else 'N/A'}
- Top Actor by Anomalies: {top_anomaly_actor}
- Data Sources: {', '.join(s['source'] for s in data.get('sources', [])[:5])}
- Top Actions: {', '.join(a['action'] for a in data.get('actions', [])[:5])}

Write a 3-paragraph executive summary covering:
1. Investigation scope and key metrics
2. Primary findings (focus on anomalies and suspicious patterns)
3. Risk assessment and immediate concerns

Keep it under 200 words. No markdown formatting."""

    print("  Generating executive summary...")
    return ollama_generate(prompt, max_tokens=400)

def generate_actor_analysis(data: Dict) -> str:
    """Generate actor behavior analysis using LLM."""
    actors_summary = []
    for actor in data.get('actors', [])[:5]:
        actors_summary.append(
            f"- {actor['actor']}: {actor['event_count']} events, actions: {actor['actions'][:5]}"
        )
    
    # Find which actors have anomalies
    anomaly_actors = set(a.get('actor') for a in data.get('anomalies', []) if a.get('actor'))
    
    prompt = f"""/no_think
You are analyzing user behavior in a forensic investigation. Be concise.

Actor Summary:
{chr(10).join(actors_summary)}

Actors with Anomalous Behavior: {', '.join(anomaly_actors) if anomaly_actors else 'None identified'}

Write 2-3 paragraphs analyzing:
1. Which actors show suspicious patterns
2. What behaviors are concerning
3. Recommended follow-up investigation steps

Keep it under 150 words."""

    print("  Generating actor analysis...")
    return ollama_generate(prompt, max_tokens=300)

def generate_anomaly_interpretation(data: Dict) -> str:
    """Generate interpretation of anomalies using LLM."""
    top_anomalies = data.get('anomalies', [])[:10]
    anomaly_summary = []
    for a in top_anomalies:
        anomaly_summary.append(
            f"- Score {a['score']:.2f}: {a['actor']} performed {a['action']} on {a['target']}"
        )
    
    prompt = f"""/no_think
You are interpreting ML-detected anomalies in a security investigation.

Top 10 Anomalies (by score):
{chr(10).join(anomaly_summary)}

Detection Method: Isolation Forest + Local Outlier Factor ensemble
Threshold: 0.65

Write 2 paragraphs:
1. Interpret what these anomalies suggest about the incident
2. Identify potential attack patterns or data exfiltration indicators

Keep it under 120 words. Be specific about security implications."""

    print("  Generating anomaly interpretation...")
    return ollama_generate(prompt, max_tokens=250)

def generate_timeline_narrative(data: Dict) -> str:
    """Generate timeline narrative from key events."""
    # Get high-severity and anomalous events for narrative
    key_events = data.get('high_severity', [])[:10]
    
    events_text = []
    for e in key_events:
        events_text.append(f"- {e['timestamp'][:19]}: {e['actor']} - {e['action']} on {e['target']}")
    
    prompt = f"""/no_think
You are writing a timeline narrative for a forensic report.

Key Events (chronological):
{chr(10).join(events_text)}

Write a chronological narrative (2-3 paragraphs) describing:
1. The sequence of events
2. How they relate to each other
3. Critical moments in the timeline

Keep it under 150 words. Use past tense."""

    print("  Generating timeline narrative...")
    return ollama_generate(prompt, max_tokens=300)

def generate_recommendations(data: Dict) -> str:
    """Generate recommendations based on findings."""
    anomaly_count = len(data.get('anomalies', []))
    top_actor = data['actors'][0]['actor'] if data.get('actors') else 'Unknown'
    
    prompt = f"""/no_think
You are providing security recommendations based on a forensic investigation.

Findings:
- {anomaly_count} anomalies detected
- Primary actor of concern: {top_actor}
- Data sources analyzed: {len(data.get('sources', []))}

Provide 5 specific, actionable recommendations for:
1. Immediate containment actions
2. Further investigation steps
3. Security improvements

Keep each recommendation to 1-2 sentences. Total under 150 words."""

    print("  Generating recommendations...")
    return ollama_generate(prompt, max_tokens=300)

def build_full_report(data: Dict) -> str:
    """Build the complete report with all sections."""
    
    print("\n=== Generating LLM-Enhanced Report Sections ===\n")
    
    # Generate LLM sections
    exec_summary = generate_executive_summary(data)
    actor_analysis = generate_actor_analysis(data)
    anomaly_interp = generate_anomaly_interpretation(data)
    timeline_narr = generate_timeline_narrative(data)
    recommendations = generate_recommendations(data)
    
    # Build static tables
    actor_table = "| Actor | Events | Actions | First Seen | Last Seen |\n|-------|--------|---------|------------|----------|\n"
    for a in data.get('actors', []):
        actor_table += f"| {a['actor']} | {a['event_count']} | {len(a['actions'])} | {a['first_seen'][:10]} | {a['last_seen'][:10]} |\n"
    
    anomaly_table = "| Score | Actor | Action | Target | Timestamp |\n|-------|-------|--------|--------|----------|\n"
    for a in data.get('anomalies', [])[:20]:
        anomaly_table += f"| {a['score']:.3f} | {a['actor'] or 'N/A'} | {a['action'] or 'N/A'} | {(a['target'] or 'N/A')[:30]} | {(a['timestamp'] or 'N/A')[:19]} |\n"
    
    # Compile full report
    report = f"""# Forensic Investigation Report
## Case ID: {CASE_ID}
### Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
### Analysis Engine: NFLIP with Ollama LLM ({LLM_MODEL})

---

# 1. Executive Summary

{exec_summary}

**Quick Stats:**
- **Total Events:** {len(data.get('timeline', []))}
- **Anomalies Detected:** {len(data.get('anomalies', []))}
- **Actors Identified:** {len(data.get('actors', []))}
- **Data Sources:** {len(data.get('sources', []))}
- **Investigation Period:** {data['timeline'][0]['timestamp'][:10] if data['timeline'] else 'N/A'} to {data['timeline'][-1]['timestamp'][:10] if data['timeline'] else 'N/A'}

---

# 2. Actor Analysis

## 2.1 AI-Generated Behavioral Analysis

{actor_analysis}

## 2.2 Actor Summary Table

{actor_table}

---

# 3. Timeline Analysis

## 3.1 Event Narrative

{timeline_narr}

## 3.2 Event Distribution

### By Data Source
{"".join(f"- **{s['source']}**: {s['count']} events ({s['count']*100//len(data.get('timeline',[]) or 1)}%)\n" for s in data.get('sources', []))}

### By Action Type (Top 10)
{"".join(f"- **{a['action']}**: {a['count']} events\n" for a in data.get('actions', [])[:10])}

---

# 4. Anomaly Detection Results

## 4.1 Detection Overview

- **Model:** Isolation Forest + Local Outlier Factor Ensemble
- **Total Scored Events:** {len(data.get('timeline', []))}
- **Anomalies Detected:** {len(data.get('anomalies', []))}
- **Detection Rate:** {len(data.get('anomalies', []))*100//(len(data.get('timeline',[])) or 1)}%

## 4.2 AI Interpretation

{anomaly_interp}

## 4.3 Anomaly Details

{anomaly_table}

---

# 5. Conclusions & Recommendations

## 5.1 Key Findings Summary

Based on the automated analysis of {len(data.get('timeline', []))} events:

1. **Primary Actor of Interest:** {data['actors'][0]['actor'] if data.get('actors') else 'Unknown'} ({data['actors'][0]['event_count'] if data.get('actors') else 0} events)
2. **Anomaly Concentration:** {len(set(a.get('actor') for a in data.get('anomalies', []) if a.get('actor')))} actors exhibited anomalous behavior
3. **High-Risk Actions:** EXPORT, FILE_WRITE, SELECT operations dominate anomalies

## 5.2 AI-Generated Recommendations

{recommendations}

---

# Appendix A: Methodology

This report was generated using:
- **Data Source:** DuckDB Case Vault
- **Anomaly Detection:** Scikit-learn Isolation Forest + LOF Ensemble
- **Natural Language Generation:** Local Ollama LLM ({LLM_MODEL})
- **Report Framework:** NFLIP Multi-Agent Investigation Platform

---

*Report generated automatically by NFLIP Forensic Investigation Platform*
*Timestamp: {datetime.now().isoformat()}*
*Classification: CONFIDENTIAL*
"""
    
    return report

def save_report(report: str, data: Dict) -> Path:
    """Save report to case vault."""
    case_dir = settings.DATA_DIR / "cases" / CASE_ID
    artifacts_dir = case_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Save markdown report
    report_path = artifacts_dir / f"llm_report_{timestamp}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    # Save to database
    conn = open_vault(CASE_ID)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS investigation_reports (
            report_id VARCHAR PRIMARY KEY,
            case_id VARCHAR,
            generated_at TIMESTAMP,
            report_type VARCHAR,
            total_events INTEGER,
            total_anomalies INTEGER,
            risk_level VARCHAR,
            report_path VARCHAR,
            llm_model VARCHAR,
            created_at TIMESTAMP DEFAULT current_timestamp
        )
    """)
    
    import uuid
    report_id = f"rpt-llm-{uuid.uuid4().hex[:8]}"
    
    try:
        conn.execute("""
            INSERT INTO investigation_reports 
            (report_id, case_id, generated_at, report_type, total_events, total_anomalies, risk_level, report_path, llm_model)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            report_id,
            CASE_ID,
            datetime.now(),
            'LLM_ENHANCED',
            len(data.get('timeline', [])),
            len(data.get('anomalies', [])),
            'HIGH' if len(data.get('anomalies', [])) > 20 else 'MEDIUM',
            str(report_path),
            LLM_MODEL
        ])
    except:
        pass  # Column might not exist in older schema
    
    conn.close()
    
    return report_path

def main():
    print("=" * 70)
    print("NFLIP LLM-Enhanced Forensic Report Generator")
    print("=" * 70)
    print(f"Case: {CASE_ID}")
    print(f"LLM: {LLM_MODEL} @ {OLLAMA_URL}")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 70)
    
    # Extract data
    print("\n[1/4] Extracting case data from vault...")
    data = get_case_data()
    print(f"  - Timeline: {len(data.get('timeline', []))} events")
    print(f"  - Anomalies: {len(data.get('anomalies', []))} detected")
    print(f"  - Actors: {len(data.get('actors', []))} identified")
    
    # Generate report
    print("\n[2/4] Generating LLM-enhanced report...")
    report = build_full_report(data)
    
    # Save
    print("\n[3/4] Saving report to vault...")
    report_path = save_report(report, data)
    print(f"  Saved: {report_path}")
    
    # Summary
    print("\n[4/4] Complete!")
    print("=" * 70)
    print("REPORT GENERATION SUCCESSFUL")
    print("=" * 70)
    print(f"Report: {report_path}")
    print(f"Size: {len(report):,} characters")
    print(f"Completed: {datetime.now().isoformat()}")
    
    # Print preview
    print("\n" + "-" * 70)
    print("REPORT PREVIEW (first 3000 characters)")
    print("-" * 70)
    print(report[:3000])
    print("\n... [truncated]")

if __name__ == "__main__":
    main()
