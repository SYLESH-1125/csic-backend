# PhaseExecutor Agent - Visual Workflow

## Planning Workflow Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                     USER INVOKES PHASEEXECUTOR                       │
│              @PhaseExecutor {software development task}              │
└────────────────────────────────┬─────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    PHASE 1: DISCOVERY (Automated)                      │
├────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  Explore     │  │  Explore     │  │  Explore     │               │
│  │  Agent 1:    │  │  Agent 2:    │  │  Agent 3:    │  (Parallel)  │
│  │  Architecture│  │  Dependencies│  │  Testing     │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│                                                                        │
│  • Research codebase patterns                                         │
│  • Analyze tech stack & dependencies                                  │
│  • Identify constraints & risks                                       │
│  • Calculate task complexity → determine phase count                 │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│              PHASE 2: CLARIFICATION (Interactive)                      │
├────────────────────────────────────────────────────────────────────────┤
│  PhaseExecutor asks targeted questions:                               │
│                                                                        │
│  ❓ What's in-scope vs out-of-scope?                                  │
│  ❓ What's critical path vs nice-to-have?                             │
│  ❓ How do we measure success?                                        │
│  ❓ Any technical constraints (performance, security, compatibility)? │
│                                                                        │
│  User provides answers ───────────────────────────────────────────┐  │
└────────────────────────────────┬───────────────────────────────────┼──┘
                                 │                                   │
                                 ▼                                   │
┌────────────────────────────────────────────────────────────────────┼──┐
│                PHASE 3: PLAN CREATION (Automated)                  │  │
├────────────────────────────────────────────────────────────────────┼──┤
│                                                                    │  │
│  1. Define Phase Boundaries                                        │  │
│     ├─ Vertical slicing (end-to-end features)                      │  │
│     ├─ Horizontal layering (foundational dependencies)             │  │
│     ├─ Risk-based ordering (high-risk first)                       │  │
│     └─ Value-based prioritization (critical path first)            │  │
│                                                                    │  │
│  2. Calculate Effort Distribution                                  │  │
│     ├─ Complexity points per phase                                 │  │
│     ├─ Balance check (15-25% per phase)                            │  │
│     └─ Rebalance if needed                                         │  │
│                                                                    │  │
│  3. Generate Comprehensive Plan                                    │  │
│     ├─ Executive summary                                           │  │
│     ├─ Phase structure rationale                                   │  │
│     ├─ Dependency graph                                            │  │
│     ├─ Risk assessment & mitigation                                │  │
│     └─ Detailed phase definitions                                  │  │
│                                                                    │  │
│  4. Save & Present                                                 │  │
│     ├─ Save to: /memories/session/phased-plan.md                   │  │
│     └─ Present scannable summary to user                           │  │
│                                                                    │  │
└────────────────────────────────┬───────────────────────────────────┼──┘
                                 │                                   │
                                 ▼                                   │
┌────────────────────────────────────────────────────────────────────┼──┐
│              PHASE 4: REFINEMENT (Iterative)                       │  │
├────────────────────────────────────────────────────────────────────┼──┤
│                                                                    │  │
│  User Feedback ────────> PhaseExecutor Response                    │  │
│                                                                    │  │
│  "Rebalance phases"  ──> Adjust boundaries, recalculate ──────────┼──┘
│                          Present revised plan ─────────────────────┼──┐
│                                                                    │  │
│  "More detail Phase N" ─> Launch Explore agent ───────────────────┼──┘
│                          Expand that phase ────────────────────────┼──┐
│                                                                    │  │
│  "Change scope"  ───────> Loop back to Discovery ─────────────────┼──┘
│                          Create revised plan ──────────────────────┼──┐
│                                                                    │  │
│  "Alternative approach" ─> Research alternatives ─────────────────┼──┘
│                           Compare & recommend ─────────────────────┼──┐
│                                                                    │  │
│  "Approved"  ───────────> Offer handoff buttons ──────────────────┘  │
│                                                                       │
└────────────────────────────────┬──────────────────────────────────────┘
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        HANDOFF TO IMPLEMENTATION                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  🚀 Start Phase 1 ─────────────────> Default agent implements         │
│                                       following detailed plan           │
│                                                                        │
│  📋 View Full Plan ────────────────> Opens plan in editor             │
│                                                                        │
│  📊 Generate Phase Tracker ─────────> Creates PHASE_TRACKER.md        │
│                                       with progress checkboxes         │
│                                                                        │
│  🔍 Deep Dive Phase ────────────────> Get detailed guidance           │
│                                       for specific phase               │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

## Phase Structure Example

```
┌─────────────────────────────────────────────────────────────────┐
│              4-PHASE BALANCED IMPLEMENTATION                    │
│          (Example: User Profile REST API with Auth)             │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│    Phase 1 (26%)     │  ← FOUNDATION
│  Database & Models   │     (Sequential - must go first)
│                      │
│  • PostgreSQL schema │
│  • SQLAlchemy models │     Deliverables:
│  • Migrations        │     ✅ Working DB connection
│  • Unit tests        │     ✅ All migrations applied
│                      │     ✅ Model tests passing
└──────────┬───────────┘
           │
           ├──────────────────┬──────────────────┐
           ▼                  ▼                  ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  Phase 2 (24%)   │  │  Phase 3 (25%)   │  │    (Waiting)     │
│  API Endpoints   │  │  Authentication  │  │                  │
│   (PARALLEL)     │  │   (PARALLEL)     │  │                  │
│                  │  │                  │  │                  │
│  • CRUD routes   │  │  • JWT service   │  │                  │
│  • Validation    │  │  • Login/Logout  │  │                  │
│  • Error handling│  │  • Middleware    │  │                  │
│  • API tests     │  │  • Auth tests    │  │                  │
└────────┬─────────┘  └─────────┬────────┘  │                  │
         │                      │            │                  │
         └──────────┬───────────┘            │                  │
                    ▼                        │                  │
           ┌──────────────────┐              │                  │
           │  Phase 4 (25%)   │ ◄────────────┘                  │
           │ Testing & Docs   │  ← INTEGRATION
           │                  │     (Sequential - needs 2 & 3)
           │  • Integration   │
           │  • E2E tests     │     Deliverables:
           │  • OpenAPI spec  │     ✅ 100% test coverage
           │  • README        │     ✅ API documentation
           │                  │     ✅ Deployment ready
           └──────────────────┘

PARALLEL OPPORTUNITY:
With 2 developers → Phase 2 & 3 simultaneously (saves 25% time)
With 1 developer  → Sequential (Phase 2 then 3)

RISK DISTRIBUTION:
Phase 1 → Database design risk (validate schema early)
Phase 3 → Security risk (JWT implementation, auth flows)
Phase 4 → Integration risk (caught by comprehensive testing)
```

## Complexity Points Calculation Example

```
┌────────────────────────────────────────────────────────────────┐
│              EFFORT ESTIMATION MODEL                           │
└────────────────────────────────────────────────────────────────┘

PHASE 1: Database & Models
─────────────────────────────────────────────────────────
• Database schema design       2 pts  (2-4 hours)
• SQLAlchemy model classes     2 pts  (2-4 hours)
• Migration scripts            1 pt   (1-2 hours)
• Model unit tests             2 pts  (2-4 hours)
• Seed data scripts            1 pt   (1-2 hours)
                              ─────
                              8 pts  (26% of total)

PHASE 2: API Endpoints
─────────────────────────────────────────────────────────
• FastAPI route handlers       2 pts  (2-4 hours)
• Request/response schemas     1 pt   (1-2 hours)
• Input validation             2 pts  (2-4 hours)
• Error handling middleware    1 pt   (1-2 hours)
• API unit tests              1 pt   (1-2 hours)
                              ─────
                              7 pts  (24% of total)

PHASE 3: Authentication
─────────────────────────────────────────────────────────
• JWT token service            3 pts  (4-6 hours)
• Login/logout endpoints       2 pts  (2-4 hours)
• Auth middleware              2 pts  (2-4 hours)
• Password hashing             1 pt   (1-2 hours)
                              ─────
                              8 pts  (25% of total)

PHASE 4: Testing & Documentation
─────────────────────────────────────────────────────────
• Integration tests            2 pts  (2-4 hours)
• E2E API tests                3 pts  (4-6 hours)
• OpenAPI spec generation      1 pt   (1-2 hours)
• README & setup docs          1 pt   (1-2 hours)
                              ─────
                              7 pts  (25% of total)

═════════════════════════════════════════════════════════
TOTAL:                        30 pts  (100%)

BALANCE CHECK: ✅ All phases 24-26% (within 15-25% target)
```

## Quality Checklist Visualization

```
┌────────────────────────────────────────────────────────────────┐
│          PHASE QUALITY GATES (All must pass)                   │
└────────────────────────────────────────────────────────────────┘

For EACH Phase, verify:

[1] DELIVERABLE QUALITY
    ✅ Testable outputs (not vague goals)
    ✅ Working functionality (can demo)
    ✅ Persistent value (code/tests/docs)
    ✅ Specific & measurable

[2] EFFORT BALANCE
    ✅ 15-25% of total effort
    ✅ Complexity points calculated
    ✅ Fits in one iteration (1-2 days)
    ✅ Not oversized/undersized

[3] DEPENDENCIES
    ✅ Explicit prerequisites listed
    ✅ Parallel opportunities noted
    ✅ Rationale explained
    ✅ No circular dependencies

[4] VERIFICATION
    ✅ Unit test commands
    ✅ Integration test procedures
    ✅ Manual validation steps
    ✅ Expected outcomes stated

[5] PROCESS TRANSPARENCY
    ✅ WHY explained (rationale)
    ✅ Decisions documented
    ✅ Alternatives considered
    ✅ Implementation approach clear

[6] RISK COVERAGE
    ✅ Risks mitigated identified
    ✅ Risks introduced noted
    ✅ Contingency plans included
    ✅ High-risk items front-loaded

[7] IMPLEMENTATION GUIDANCE
    ✅ Specific file paths listed
    ✅ Function/class names referenced
    ✅ Code examples/patterns provided
    ✅ Learning resources linked

[8] EXIT CRITERIA
    ✅ Completion checklist
    ✅ Observable/measurable criteria
    ✅ Covers functionality/tests/docs
    ✅ Realistic & achievable

═══════════════════════════════════════════════════════════
IF ALL ✅ → Present plan to user
IF ANY ❌ → Revise before presenting
```

## Risk Assessment Matrix

```
                    IMPACT ON PROJECT
                    
        LOW             MEDIUM            HIGH
      ┌──────────────┬──────────────┬──────────────┐
      │              │              │              │
  H   │   MEDIUM     │     HIGH     │   CRITICAL   │
  I   │              │              │              │
  G   │  Monitor     │  Address     │  Phase 1     │
  H   │              │  Phase 1-2   │  (immediate) │
      ├──────────────┼──────────────┼──────────────┤
P     │              │              │              │
R  M  │     LOW      │    MEDIUM    │     HIGH     │
O  E  │              │              │              │
B  D  │  Document    │  Monitor     │  Address     │
A     │    only      │  actively    │  Phase 1-2   │
B     ├──────────────┼──────────────┼──────────────┤
I     │              │              │              │
L  L  │     LOW      │     LOW      │    MEDIUM    │
I  O  │              │              │              │
T  W  │  Ignore      │  Document    │  Contingency │
Y     │              │    only      │  plan ready  │
      └──────────────┴──────────────┴──────────────┘

EXAMPLES:
────────────────────────────────────────────────────────
• JWT implementation (High prob, High impact) = CRITICAL
  → Address in Phase 1 with POC/spike

• Database performance (Medium prob, High impact) = HIGH  
  → Validate in Phase 1 with benchmarks

• UI polish issues (Low prob, Medium impact) = LOW
  → Document, address if time permits
```

## Progress Tracker Format

```
┌────────────────────────────────────────────────────────────────┐
│           PHASE EXECUTION TRACKER                              │
│    (Generated by: @PhaseExecutor generate phase tracker)       │
└────────────────────────────────────────────────────────────────┘

OVERALL PROGRESS: ████████░░░░░░░░░░ 40% (2 of 5 phases complete)

─────────────────────────────────────────────────────────────────
PHASE 1: Database & Models [✅ COMPLETE]
─────────────────────────────────────────────────────────────────
Deliverables:
  ✅ PostgreSQL schema created
  ✅ SQLAlchemy models implemented
  ✅ Migration scripts working
  ✅ Unit tests passing

Verification:
  ✅ pytest tests/test_models.py -v (12/12 passed)
  ✅ Coverage: 95% (exceeds 80% target)

Exit Criteria:
  ✅ All tests passing
  ✅ Code reviewed & approved
  ✅ Documentation updated

Completed: 2026-04-04
Notes: Schema design took extra time due to normalization

─────────────────────────────────────────────────────────────────
PHASE 2: API Endpoints [🔄 IN PROGRESS - 60%]
─────────────────────────────────────────────────────────────────
Deliverables:
  ✅ CRUD route handlers
  ✅ Request/response schemas
  ⏳ Input validation (in progress)
  ❌ Error handling middleware
  ❌ API unit tests

Verification:
  ⏳ curl tests (3/5 endpoints working)
  ❌ pytest tests/test_api.py -v (not started)

Exit Criteria:
  ✅ FastAPI app runs successfully
  ⏳ All endpoints functional
  ❌ Tests passing
  ❌ OpenAPI docs auto-generated

Blockers: Need to resolve pydantic validation edge case
Next steps: Implement error middleware, write tests

─────────────────────────────────────────────────────────────────
PHASE 3: Authentication [📋 NOT STARTED]
─────────────────────────────────────────────────────────────────
Dependencies: Phase 1 ✅ complete
Start after: Phase 2 complete OR parallel with Phase 2

{Deliverables, Verification, Exit Criteria listed...}

─────────────────────────────────────────────────────────────────

ROLLBACK LOG:
• 2026-04-03: Rolled back Phase 2 - pydantic schema issue
  Resolved by: Upgrading to pydantic v2

LESSONS LEARNED:
• Validate pydantic compatibility before starting API work
• Add database indices earlier (found during testing)
• Team prefers FastAPI over Flask (faster development)
```

---

## Summary

This visual guide shows:

1. **Planning Workflow**: 4-phase iterative process
2. **Phase Structure**: How phases are organized and balanced
3. **Effort Calculation**: Complexity points system
4. **Quality Gates**: Comprehensive checklist
5. **Risk Matrix**: Severity and prioritization
6. **Progress Tracking**: Monitoring implementation

Use these visuals to understand how PhaseExecutor works!
