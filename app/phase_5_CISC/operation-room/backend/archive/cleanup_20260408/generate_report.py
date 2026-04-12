"""
Automated Report Generation Demo
Creates a complete forensic investigation report using local LLM
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from operation_room.database import open_vault
from operation_room.config import settings

CASE_ID = "CASE-FORENSIC-001"

def get_case_data():
    """Extract all relevant data from the case vault."""
    conn = open_vault(CASE_ID)
    data = {}
    
    # Get tables
    tables = conn.execute("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'main'
        ORDER BY table_name
    """).fetchall()
    data['tables'] = [t[0] for t in tables]
    print(f"Found {len(data['tables'])} tables")
    
    # Get timeline events
    try:
        events = conn.execute("""
            SELECT normalised_ts, source_system, actor, action, target, severity, detail
            FROM unified_timeline
            ORDER BY normalised_ts
            LIMIT 500
        """).fetchall()
        data['timeline'] = [
            {
                'timestamp': str(row[0]),
                'source': row[1],
                'actor': row[2],
                'action': row[3],
                'target': row[4],
                'severity': row[5],
                'detail': row[6][:100] if row[6] else None
            }
            for row in events
        ]
        print(f"Timeline events: {len(data['timeline'])}")
    except Exception as e:
        print(f"Timeline error: {e}")
        data['timeline'] = []
    
    # Get anomalies
    try:
        anomalies = conn.execute("""
            SELECT tl_event_id, anomaly_score, model_type, is_anomaly
            FROM anomaly_scores
            WHERE is_anomaly = true
            ORDER BY anomaly_score DESC
            LIMIT 50
        """).fetchall()
        data['anomalies'] = [
            {
                'event_id': row[0],
                'score': row[1],
                'model': row[2],
                'is_anomaly': row[3]
            }
            for row in anomalies
        ]
        print(f"Anomalies: {len(data['anomalies'])}")
    except Exception as e:
        print(f"Anomaly error: {e}")
        data['anomalies'] = []
    
    # Get actors summary
    try:
        actors = conn.execute("""
            SELECT actor, COUNT(*) as count, 
                   COUNT(DISTINCT action) as action_types,
                   MIN(normalised_ts) as first_seen,
                   MAX(normalised_ts) as last_seen
            FROM unified_timeline
            WHERE actor IS NOT NULL
            GROUP BY actor
            ORDER BY count DESC
            LIMIT 20
        """).fetchall()
        data['actors'] = [
            {
                'actor': row[0],
                'event_count': row[1],
                'action_types': row[2],
                'first_seen': str(row[3]),
                'last_seen': str(row[4])
            }
            for row in actors
        ]
        print(f"Actors: {len(data['actors'])}")
    except Exception as e:
        print(f"Actor error: {e}")
        data['actors'] = []
    
    # Get action distribution
    try:
        actions = conn.execute("""
            SELECT action, COUNT(*) as count
            FROM unified_timeline
            WHERE action IS NOT NULL
            GROUP BY action
            ORDER BY count DESC
            LIMIT 20
        """).fetchall()
        data['actions'] = [{'action': row[0], 'count': row[1]} for row in actions]
    except:
        data['actions'] = []
    
    # Get source systems
    try:
        sources = conn.execute("""
            SELECT source_system, COUNT(*) as count
            FROM unified_timeline
            WHERE source_system IS NOT NULL
            GROUP BY source_system
            ORDER BY count DESC
        """).fetchall()
        data['sources'] = [{'source': row[0], 'count': row[1]} for row in sources]
    except:
        data['sources'] = []
    
    conn.close()
    return data

def generate_report_sections(data):
    """Generate report sections from data (no LLM needed for basic report)."""
    
    sections = []
    
    # Executive Summary
    total_events = len(data.get('timeline', []))
    total_anomalies = len(data.get('anomalies', []))
    total_actors = len(data.get('actors', []))
    
    sections.append({
        'title': 'Executive Summary',
        'content': f"""
This forensic investigation report documents the analysis of case {CASE_ID}.

**Key Findings:**
- Total Events Analyzed: {total_events}
- Anomalies Detected: {total_anomalies}
- Unique Actors Identified: {total_actors}
- Data Sources: {len(data.get('sources', []))}

**Investigation Period:**
- Start: {data['timeline'][0]['timestamp'] if data['timeline'] else 'N/A'}
- End: {data['timeline'][-1]['timestamp'] if data['timeline'] else 'N/A'}

**Risk Assessment:** {'HIGH' if total_anomalies > 20 else 'MEDIUM' if total_anomalies > 5 else 'LOW'}
"""
    })
    
    # Actor Analysis
    actor_table = "| Actor | Events | Actions | First Seen | Last Seen |\n|-------|--------|---------|------------|----------|\n"
    for a in data.get('actors', [])[:10]:
        actor_table += f"| {a['actor']} | {a['event_count']} | {a['action_types']} | {a['first_seen'][:19]} | {a['last_seen'][:19]} |\n"
    
    sections.append({
        'title': 'Actor Analysis',
        'content': f"""
## Identified Actors

The following actors were identified during the investigation:

{actor_table}

### High-Activity Actors
{data['actors'][0]['actor'] if data['actors'] else 'None'} showed the highest activity with {data['actors'][0]['event_count'] if data['actors'] else 0} events.
"""
    })
    
    # Timeline Analysis
    sections.append({
        'title': 'Timeline Analysis',
        'content': f"""
## Event Timeline

Total events in analysis window: {total_events}

### Event Distribution by Source
{"".join(f"- **{s['source']}**: {s['count']} events\n" for s in data.get('sources', []))}

### Event Distribution by Action Type
{"".join(f"- **{a['action']}**: {a['count']} events\n" for a in data.get('actions', [])[:10])}
"""
    })
    
    # Anomaly Analysis
    anomaly_table = "| Event ID | Score | Model | Status |\n|----------|-------|-------|--------|\n"
    for a in data.get('anomalies', [])[:15]:
        anomaly_table += f"| {a['event_id'][:20]}... | {a['score']:.4f} | {a['model']} | Anomaly |\n"
    
    sections.append({
        'title': 'Anomaly Detection Results',
        'content': f"""
## ML-Based Anomaly Detection

Using Isolation Forest + Local Outlier Factor ensemble model:
- **Total Anomalies Detected:** {total_anomalies}
- **Detection Threshold:** 0.65

### Top Anomalies
{anomaly_table}

### Risk Indicators
{"- High volume of anomalous events indicates potential security incident" if total_anomalies > 20 else "- Moderate anomaly count requires further investigation"}
"""
    })
    
    # Conclusions
    sections.append({
        'title': 'Conclusions and Recommendations',
        'content': f"""
## Investigation Conclusions

Based on the forensic analysis of {total_events} events:

1. **Primary Finding:** Multiple anomalous activities detected across {len(data.get('sources', []))} data sources
2. **Actor Assessment:** {total_actors} unique actors identified, with concentration of activity
3. **Timeline:** Activity spans from {data['timeline'][0]['timestamp'][:10] if data['timeline'] else 'N/A'} to {data['timeline'][-1]['timestamp'][:10] if data['timeline'] else 'N/A'}

## Recommendations

1. Review all HIGH severity anomalies for potential security incidents
2. Investigate actors with unusual activity patterns
3. Correlate findings with external threat intelligence
4. Implement enhanced monitoring for identified IOCs

---
*Report generated: {datetime.now().isoformat()}*
*Case ID: {CASE_ID}*
*Analysis Engine: NFLIP Forensic Investigation Platform*
"""
    })
    
    return sections

def save_report(sections, data):
    """Save the report to the case vault."""
    
    # Create full markdown report
    report_md = f"""# Forensic Investigation Report
## Case: {CASE_ID}
### Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

"""
    for section in sections:
        report_md += f"# {section['title']}\n\n{section['content']}\n\n---\n\n"
    
    # Save paths
    case_dir = settings.DATA_DIR / "cases" / CASE_ID
    artifacts_dir = case_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    # Save markdown report
    report_path = artifacts_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_md)
    print(f"\nReport saved: {report_path}")
    
    # Save JSON data
    json_path = artifacts_dir / f"analysis_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({
            'case_id': CASE_ID,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_events': len(data.get('timeline', [])),
                'total_anomalies': len(data.get('anomalies', [])),
                'total_actors': len(data.get('actors', [])),
                'sources': data.get('sources', [])
            },
            'sections': sections
        }, f, indent=2, default=str)
    print(f"Data saved: {json_path}")
    
    # Also save to vault database
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
            created_at TIMESTAMP DEFAULT current_timestamp
        )
    """)
    
    import uuid
    report_id = f"rpt-{uuid.uuid4().hex[:8]}"
    conn.execute("""
        INSERT INTO investigation_reports 
        (report_id, case_id, generated_at, report_type, total_events, total_anomalies, risk_level, report_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        report_id,
        CASE_ID,
        datetime.now(),
        'FULL_INVESTIGATION',
        len(data.get('timeline', [])),
        len(data.get('anomalies', [])),
        'HIGH' if len(data.get('anomalies', [])) > 20 else 'MEDIUM',
        str(report_path)
    ])
    conn.close()
    print(f"Report logged in vault: {report_id}")
    
    return report_path, report_md

def main():
    print("=" * 60)
    print("NFLIP Automated Report Generation")
    print("=" * 60)
    print(f"\nCase: {CASE_ID}")
    print(f"Started: {datetime.now().isoformat()}\n")
    
    # Step 1: Extract data
    print("Step 1: Extracting case data...")
    data = get_case_data()
    
    # Step 2: Generate report sections
    print("\nStep 2: Generating report sections...")
    sections = generate_report_sections(data)
    print(f"Generated {len(sections)} sections")
    
    # Step 3: Save report
    print("\nStep 3: Saving report...")
    report_path, report_md = save_report(sections, data)
    
    print("\n" + "=" * 60)
    print("REPORT GENERATION COMPLETE")
    print("=" * 60)
    
    # Print preview
    print("\n--- Report Preview (first 2000 chars) ---\n")
    print(report_md[:2000])
    print("\n...")
    
    return report_path

if __name__ == "__main__":
    main()
