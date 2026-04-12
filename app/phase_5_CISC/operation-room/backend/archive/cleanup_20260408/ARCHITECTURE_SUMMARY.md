# NFLIP Investigation Agent - Complete Architecture Summary

## System Status: ✅ OPERATIONAL

### Test Results
- **30/30 integration tests passing**
- **63 MCP tools registered**
- **End-to-end workflow verified**

---

## 1. SYSTEM OVERVIEW

NFLIP is a **multi-agent forensic investigation platform** that automates the generation of detailed forensic reports from evidence logs. 

### Core Principle
> **"AI reasons about evidence, never generates it."**
> 
> All factual data (IPs, MACs, timestamps, file paths) comes from actual log evidence with SHA-256 hash verification. AI only generates narratives and summaries.

---

## 2. DIRECTORY STRUCTURE

```
operation-room/backend/
├── app/
│   ├── main.py                    # FastAPI entry point
│   ├── config.py                  # Environment configuration
│   ├── database.py                # DuckDB case vaults
│   │
│   ├── mcp/                       # Model Context Protocol Layer
│   │   ├── registry.py            # Tool registration (63 tools)
│   │   ├── schemas.py             # Pydantic models
│   │   ├── decorators.py          # @mcp_tool, @with_coc_logging, etc.
│   │   ├── server.py              # MCP JSON-RPC server
│   │   └── tools/                 # Tool implementations
│   │       ├── investigation.py   # investigation.* tools
│   │       ├── clarification.py   # clarification.* tools
│   │       ├── planning.py        # planning.* tools
│   │       ├── hypothesis.py      # hypothesis.* tools
│   │       ├── evidence.py        # evidence.* tools + EvidenceVault
│   │       ├── analysis.py        # anomaly.*, correlation.*, etc.
│   │       ├── report.py          # report.* tools
│   │       └── llm.py             # LLM provider tools
│   │
│   ├── agents/                    # Multi-Agent System
│   │   ├── base.py                # BaseAgent abstract class
│   │   ├── integration_layer.py   # Pipeline coordination
│   │   ├── orchestrator/          # Master orchestrator (LangGraph)
│   │   ├── investigator/          # Main investigation agent
│   │   │   ├── agent.py           # InvestigationAgent
│   │   │   ├── planner.py         # PlanningEngine
│   │   │   ├── summary.py         # SummaryGenerator
│   │   │   └── hypothesis_tree.py # HypothesisTree
│   │   ├── hypothesis/            # Hypothesis analysis agent
│   │   ├── evidence/              # Evidence collection agent
│   │   ├── confidence/            # Confidence scoring agent
│   │   ├── synthesis/             # Report synthesis agent
│   │   └── evaluators/            # 6 module evaluators
│   │
│   ├── models/                    # Pydantic data models
│   ├── routes/                    # FastAPI endpoints
│   ├── services/                  # Business logic
│   └── utils/                     # Utilities
│
├── data/
│   └── cases/{case_id}/           # Per-case DuckDB vaults
│
└── tests/
    └── test_mcp_integration.py    # Integration tests (30 tests)
```

---

## 3. INVESTIGATION WORKFLOW

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     INVESTIGATION LIFECYCLE                              │
└──────────────────────────────────────────────────────────────────────────┘

PHASE 1: INTAKE
├─ Investigator submits scenario (natural language)
├─ System extracts entities (IPs, MACs, emails, file paths)
├─ Creates InvestigationContext
└─ State: AWAITING_CLARIFICATION

PHASE 2: CLARIFICATION  
├─ Generate clarification questions (time range, scope, mode)
├─ Questions prioritized: BLOCKING > HIGH > MEDIUM > LOW
├─ Investigator answers blocking questions
└─ State: PLANNING

PHASE 3: PLANNING
├─ Create investigation plan with phases:
│   ├─ Data Collection
│   ├─ Timeline Analysis
│   ├─ Anomaly Detection
│   ├─ Correlation Analysis
│   ├─ Hypothesis Generation/Testing
│   ├─ Impact Assessment
│   └─ Report Generation
└─ State: EXECUTING

PHASE 4: ANALYSIS (Multi-Agent)
├─ HypothesisAnalysisAgent → Generate competing hypotheses
├─ EvidenceCollectionAgent → Query all analysis modules
├─ ModuleEvaluators (6x) → Score module findings
├─ ConfidenceScoringAgent → Bayesian confidence scoring
└─ SynthesisAgent → Generate report sections

PHASE 5: HYPOTHESIS TESTING
├─ Build hypothesis tree
├─ Traverse (BFS/DFS/HYBRID)
├─ Test each hypothesis against evidence
└─ Update verdicts: CONFIRMED/REJECTED/INCONCLUSIVE

PHASE 6: EVIDENCE SYNTHESIS
├─ Aggregate into Evidence Vault
├─ Create immutable evidence cards
├─ Compute SHA-256 integrity hashes
└─ Record Chain of Custody

PHASE 7: REPORT GENERATION
├─ Select template (technical/executive/regulatory)
├─ LLM generates narratives for each section
├─ Insert evidence citations
├─ Generate PDF/DOCX/JSON exports
└─ State: COMPLETE
```

---

## 4. MCP TOOLS (63 Total)

### Investigation Tools
- `investigation.start` - Initialize investigation
- `investigation.context` - Get/update context
- `investigation.list` - List all investigations
- `investigation.pause/resume` - Control execution

### Clarification Tools
- `clarification.list` - Get pending questions
- `clarification.answer` - Answer questions

### Planning Tools
- `planning.generate` - Generate investigation plan
- `planning.get` - Retrieve plan details
- `planning.execute_step` - Execute single phase

### Hypothesis Tools
- `hypothesis.generate` - Generate competing hypotheses
- `hypothesis.test` - Test hypothesis against evidence
- `hypothesis.tree` - Get full hypothesis tree
- `hypothesis.update_verdict` - Update verdict

### Evidence Tools
- `evidence.query` - Query evidence vault
- `evidence.snapshot` - Create evidence snapshot
- `evidence.verify` - Verify integrity hash
- `evidence.cite` - Create citation
- `evidence.card_create` - Create immutable card

### Analysis Tools
- `anomaly.detect` - Run anomaly detection
- `correlation.build` - Build correlation graph
- `correlation.find_chains` - Find attack chains
- `crud.analyze` - Analyze data access patterns
- `network.analyze` - Analyze network flows
- `depth.assess` - Assess impact

### Report Tools
- `report.doc.create` - Create report document
- `report.canvas.add_page` - Add canvas page
- `report.canvas.add_element` - Add element
- `report.narrative.generate` - AI generate narrative
- `report.export` - Export (PDF/DOCX/HTML)
- `report.validate` - Validate integrity

### LLM Tools
- `llm.generate_text` - Call LLM
- `llm.config` - Get configuration

---

## 5. EVIDENCE VAULT & CHAIN OF CUSTODY

### Vault Architecture (Per-Case DuckDB)
```sql
-- Raw imported events
CREATE TABLE raw_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT,
    source_type TEXT,  -- AUTH, VPN, FW, DB, APP, EPP, FILE
    timestamp TIMESTAMP,
    actor TEXT,
    action TEXT,
    target TEXT,
    detail JSON
);

-- Evidence tracking
CREATE TABLE evidence_vault (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT,
    evidence_type TEXT,
    content_hash TEXT,  -- SHA-256
    anchor_type TEXT,   -- TIMELINE_EVENT, ANOMALY, etc.
    anchor_id TEXT
);

-- Immutable evidence cards
CREATE TABLE evidence_cards (
    card_id TEXT PRIMARY KEY,
    evidence_id TEXT,
    content_hash TEXT,
    snapshot_json TEXT  -- Immutable snapshot
);

-- Chain of Custody (tamper-evident)
CREATE TABLE chain_of_custody (
    event_id TEXT PRIMARY KEY,
    timestamp TIMESTAMP,
    actor TEXT,
    action TEXT,  -- TOOL_EXECUTION, EVIDENCE_IMPORT, etc.
    hash_before TEXT,
    hash_after TEXT,
    details JSON
);
```

### CoC Logging Flow
1. **EVIDENCE_IMPORT** - When logs are imported
2. **TOOL_EXECUTION** - Every MCP tool call
3. **EVIDENCE_VAULTED** - When evidence is anchored
4. **EVIDENCE_CITED** - When cited in report
5. **REPORT_GENERATED** - Final report creation

---

## 6. KEY COMPONENTS

### InvestigationAgent
```python
class InvestigationAgent:
    """Main investigation controller."""
    
    async def start_investigation(scenario, case_id)
    async def get_pending_clarifications()
    async def submit_clarification(question_id, answer)
    async def generate_plan()
    async def run_analysis_phase(phase_id, module)
    async def generate_hypotheses_for_scenario()
    async def test_hypothesis_by_id(hypothesis_id)
    async def generate_report()
    async def export_report(format)
```

### PlanningEngine
```python
class PlanningEngine:
    """Phase planning state machine."""
    
    def create_plan_from_scenario(scenario, case_type)
    def get_next_executable_phase()
    def mark_phase_complete(phase_id)
    def is_complete()
```

### HypothesisTree
```python
class HypothesisTree:
    """Hypothesis management with BFS/DFS traversal."""
    
    def add_root_hypothesis(hypothesis_id, description)
    def add_child_hypothesis(parent_id, hypothesis_id, description)
    def get_node(hypothesis_id)
    def bfs_traverse()
    def dfs_traverse()
```

### SummaryGenerator
```python
class SummaryGenerator:
    """Summary card generation."""
    
    def generate_finding_card(finding, evidence_refs)
    def generate_timeline_card(events)
    def generate_phase_summary(phase_results)
```

### EvidenceVault
```python
class EvidenceVault:
    """Static class for evidence operations."""
    
    @classmethod
    def add(evidence_item) -> str
    
    @classmethod
    def get(evidence_id) -> Optional[Evidence]
    
    @classmethod
    def verify_hash(evidence_id, expected_hash) -> bool
```

---

## 7. LLM INTEGRATION

### Supported Providers
- **Ollama** (local) - Qwen3:8b default
- **Gemini** (cloud) - Google Gemini API

### Configuration
```python
LLM_PROVIDER = "gemini"  # or "ollama"
LLM_MODEL = "qwen3:8b"
GEMINI_API_KEY = "<your-key>"
```

### Usage in Agents
```python
# Hypothesis generation
prompt = "Generate 5 competing hypotheses for this scenario..."
hypotheses = await llm.generate(prompt, json_mode=True)

# Report narrative
prompt = "Write a technical section on timeline analysis..."
narrative = await llm.generate(prompt, temperature=0.3)
```

---

## 8. API ENDPOINTS

### Investigation
- `POST /api/agents/start` - Start investigation
- `GET /api/agents/status/{investigation_id}` - Get status
- `POST /api/agents/clarification` - Submit answers
- `POST /api/agents/generate-plan` - Generate plan
- `POST /api/agents/run-analysis` - Run analysis phase

### Report
- `POST /api/studio/create` - Create report
- `POST /api/studio/add-page` - Add page
- `POST /api/studio/generate-narrative` - Generate AI text
- `POST /api/studio/export` - Export report

### Evidence
- `GET /api/evidence/{case_id}` - Query evidence
- `POST /api/evidence/cite` - Create citation
- `GET /api/evidence/verify/{evidence_id}` - Verify hash

---

## 9. KNOWN ISSUES & WARNINGS

### 1. Google Generative AI Deprecation
```
FutureWarning: All support for the `google.generativeai` package has ended.
Please switch to the `google.genai` package.
```
**Status**: Warning only, functionality works. Migration recommended.

### 2. Plan Generation Returns Empty
In some scenarios, `generate_investigation_plan` returns empty phases.
**Cause**: LLM may not be returning structured plan in expected format.
**Workaround**: Use default plan template.

### 3. Systems/Channels Extraction
Entity extraction sometimes returns empty arrays.
**Cause**: Regex patterns may not match all input formats.
**Impact**: Low - clarification questions will gather this info.

---

## 10. RUNNING THE SYSTEM

### Start Backend
```bash
cd operation-room/backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Run Tests
```bash
cd operation-room/backend
python -m pytest tests/test_mcp_integration.py -v
```

### Verify Tools
```python
from app.mcp import registry
print(f"Tools: {len(registry.list_tools())}")  # 63 tools
```

### Run E2E Demo
```python
import asyncio
from app.mcp.tools import start_investigation, generate_hypotheses

async def demo():
    result = await start_investigation(
        case_id="demo-001",
        scenario="Suspected data exfiltration..."
    )
    print(f"Investigation: {result['investigation_id']}")
    
    hyp = await generate_hypotheses(result['investigation_id'])
    print(f"Hypotheses: {len(hyp['hypotheses'])}")

asyncio.run(demo())
```

---

## 11. CONFIDENCE SCORING (ODNI ICD 203)

### 6-Factor Scoring Model
| Factor | Weight | Description |
|--------|--------|-------------|
| Evidence Coverage | 0.25 | % of entities covered by evidence |
| Module Agreement | 0.20 | Consistency across analysis modules |
| Temporal Consistency | 0.15 | Timeline coherence |
| Cross Validation | 0.20 | Evidence from multiple sources |
| Pattern Match | 0.10 | Match to known attack patterns |
| Research Alignment | 0.10 | Alignment with research methodologies |

### Confidence Levels
| Score | Level | Description |
|-------|-------|-------------|
| 0.90+ | ALMOST_CERTAIN | Virtually no doubt |
| 0.80-0.89 | HIGHLY_LIKELY | Strong evidence |
| 0.65-0.79 | LIKELY | More likely than not |
| 0.50-0.64 | ROUGHLY_EVEN | About even odds |
| 0.35-0.49 | UNLIKELY | Less likely than not |
| 0.20-0.34 | HIGHLY_UNLIKELY | Strong evidence against |
| <0.20 | REMOTE | Almost certainly not |

---

## 12. REPORT TEMPLATES

### Technical Report
- Executive Summary
- Case Overview
- Timeline Narrative
- Anomaly Findings
- Attack Chain
- Data Access Analysis
- Network Analysis
- Impact Assessment
- Hypothesis Analysis
- Findings & Conclusions
- Recommendations
- Chain of Custody

### Executive Report
- Executive Summary
- Impact Assessment
- Key Findings
- Remediation Steps

### Regulatory Report
- Executive Summary
- Personal Data Affected
- Timeline
- Impact Assessment
- Containment
- Evidence Integrity

---

## Summary

NFLIP is a comprehensive forensic investigation platform with:

✅ **63 MCP tools** for investigation, analysis, and reporting  
✅ **Multi-agent architecture** with specialized agents  
✅ **Evidence vault** with SHA-256 integrity verification  
✅ **Chain of custody** tamper-evident logging  
✅ **LLM integration** for narrative generation  
✅ **30 passing integration tests**  
✅ **Complete E2E workflow verified**  

The system transforms a natural language investigation scenario into a comprehensive forensic report with full evidence citation and audit trails.
