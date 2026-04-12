# ProjectStatusAnalyzer Agent - Usage Guide

## What is ProjectStatusAnalyzer?

ProjectStatusAnalyzer is a specialized AI agent that **analyzes your project's implementation status** by comparing actual code files against planning documents. It provides comprehensive progress reports showing what's complete, what's in progress, and what's missing.

### Key Features

✅ **Multi-Plan Discovery** - Finds all plan files (plan.md, TODO.md, phased-plan.md, PHASE_TRACKER.md, ROADMAP.md)  
✅ **Deep Verification** - Checks file content, not just existence (functions, classes, implementations)  
✅ **Test Execution** - Runs verification commands from plans (tests, builds, lints)  
✅ **Precise Metrics** - Calculates real completion percentages based on actual data  
✅ **Comprehensive Reports** - Generates STATUS_REPORT.md with file tables, test results, git analysis  
✅ **Actionable Insights** - Prioritized next steps, blocker identification, risk assessment  

---

## Installation

### Location
The agent is installed globally at:
```
%USERPROFILE%\.vscode\agents\ProjectStatusAnalyzer.agent.md
```

### Verify Installation
1. Reload VS Code (Ctrl+Shift+P → "Reload Window")
2. Open GitHub Copilot Chat
3. Type `@` - you should see **ProjectStatusAnalyzer** in the list

---

## How to Use

### Basic Usage

Simply invoke the agent in Copilot Chat:
```
@ProjectStatusAnalyzer
```

The agent will:
1. Find all plan documents in your project
2. Analyze actual implementation files
3. Run verification commands from plans
4. Present summary in chat
5. Generate `STATUS_REPORT.md` in project root

### With Specific Focus

```
@ProjectStatusAnalyzer Check authentication implementation status
```

```
@ProjectStatusAnalyzer Analyze Phase 2 completion
```

```
@ProjectStatusAnalyzer Verify all tests are passing
```

---

## What the Agent Does

### 1. Plan Discovery

Automatically finds and reads:
- `plan.md`, `phased-plan.md`
- `TODO.md`, `TASKS.md`, `BACKLOG.md`
- `PHASE_TRACKER.md`
- `ROADMAP.md`, `MILESTONES.md`
- Plans in `/memories/session/`

### 2. Deep Code Analysis

Verifies implementation by:
- Checking if planned files exist
- Reading file contents to verify functions/classes mentioned in plans
- Distinguishing stubs from complete implementations
- Searching for TODO/FIXME comments
- Analyzing git status (modified files, recent commits)

### 3. Test Execution

Automatically runs verification commands from plans:
- Unit tests (`pytest`, `npm test`, etc.)
- Integration tests
- Build commands (`npm run build`, `cargo build`, etc.)
- Linting (`eslint`, `pylint`, etc.)
- Coverage reports (if specified in plan)

### 4. Cross-Reference Verification

Matches plan items to actual code:
- For each deliverable: "Working feature X" → searches for implementation
- For each file: `path/to/file.py` → verifies existence + content
- For each test: Checks test file exists + can execute
- For each exit criterion: Validates objectively

### 5. Comprehensive Reporting

Generates detailed STATUS_REPORT.md with:

**Executive Summary**
- Overall completion percentage
- Status (On Track / At Risk / Delayed)
- Key metrics (phases, tasks, files, tests)
- Top 3 priority actions

**Phase Breakdown**
- Per-phase completion status
- Deliverable verification (✅ complete, 🔄 partial, ❌ missing)
- File verification table
- Test status
- Exit criteria checklist

**Detailed Analysis**
- File creation status table
- Recent modifications
- Test execution results
- Build/lint output
- Git analysis

**Blockers & Risks**
- Critical blockers with impact + mitigation
- Medium risks with probability
- Technical debt items

**Discrepancies**
- Planned but not implemented
- Implemented but not planned (flagged for plan update)
- Different implementations than planned

**Next Steps**
- Immediate actions (prioritized)
- Short-term tasks
- Long-term considerations

---

## Configuration (Based on Your Preferences)

The agent is configured with:

✅ **Plan Discovery**: All common plan files (plan.md, phased-plan.md, TODO.md, PHASE_TRACKER.md, ROADMAP.md)

✅ **Verification Depth**: Deep analysis
- File content verification
- Function/class existence checks
- Test execution
- Coverage metrics

✅ **Report Format**: Comprehensive
- Phase breakdown
- File verification tables
- Test results
- Git analysis

✅ **Output Location**: 
- Summary in chat (executive overview, top priorities)
- Detailed report in `STATUS_REPORT.md` (project root)

✅ **Command Execution**: Automatic
- Runs all verification commands from plans
- Tests, builds, lints
- Captures output for reporting

✅ **Unplanned Work Handling**: Flag as incomplete
- Suggests adding unplanned files to plan
- Highlights in discrepancies section

---

## Example Scenarios

### Scenario 1: Check Overall Project Status

**Command:**
```
@ProjectStatusAnalyzer
```

**What happens:**
1. Finds `phased-plan.md` with 4 phases
2. Analyzes codebase for all deliverables
3. Runs `pytest tests/` and `npm test` (from plan verification steps)
4. Generates STATUS_REPORT.md

**Chat Output:**
```
📊 Project Status Report

Overall Completion: 62% complete

Status: ON TRACK ✅

Key Metrics:
• Phases Complete: 2 of 4 (50%)
• Tasks Complete: 18 of 27 (67%)
• Files Implemented: 24 of 32 (75%)
• Tests Passing: 142 of 142 (100%)

Top Priority Actions:
1. Complete input validation in Phase 2 (3 files remaining)
2. Implement error handling middleware
3. Write API integration tests (15 test cases needed)

📄 Full report saved to: STATUS_REPORT.md
```

### Scenario 2: Verify Specific Phase

**Command:**
```
@ProjectStatusAnalyzer Check Phase 3 authentication status
```

**What happens:**
1. Focuses on Phase 3 from plan
2. Verifies JWT implementation, auth endpoints, middleware
3. Runs auth-specific tests
4. Reports completion status

**Chat Output:**
```
Phase 3: Authentication - 85% complete 🔄

✅ Completed:
  - JWT token service (src/auth/jwt.py)
  - Login/logout endpoints (src/routes/auth.py)
  - Password hashing (bcrypt implementation)
  - Unit tests (24/24 passing)

🔄 In Progress:
  - Auth middleware (partially implemented)
  - Missing: Token refresh endpoint

❌ Not Started:
  - Integration tests for auth flows

Next Steps:
1. Complete auth middleware (add role-based access control)
2. Implement token refresh endpoint
3. Write integration tests
```

### Scenario 3: After Making Changes

**Command:**
```
@ProjectStatusAnalyzer
```

**What happens:**
1. Detects recent git changes
2. Cross-references with plan tasks
3. Updates completion percentages
4. Highlights newly completed items

**Chat Output:**
```
📈 Progress Update (since last report)

New Completions:
✅ Input validation middleware (Phase 2)
✅ Error handling for API routes (Phase 2)
✅ API unit tests (15 new tests added)

Phase 2: Now 90% complete (was 60%)
Overall: Now 70% complete (was 62%)

Remaining Phase 2 Tasks:
  - Documentation for API endpoints (OpenAPI spec)

Phase 2 completion expected this iteration ✅
```

---

## Understanding the Reports

### Chat Summary

Quick, scannable overview:
- Overall completion %
- Status indicator (On Track / At Risk / Delayed)
- Key metrics table
- Top 3 priority actions
- Link to detailed STATUS_REPORT.md

### STATUS_REPORT.md Structure

**Section 1: Executive Summary**
- High-level metrics and status

**Section 2: Phase Breakdown**
- Each phase with completion %
- Deliverable verification
- File and test status
- Exit criteria checklist

**Section 3: Detailed Task Status**
- Completed tasks with file references
- In-progress tasks with what's missing
- Not started tasks with blockers

**Section 4: File Analysis**
- Table of created files (status, notes)
- Recently modified files
- Missing files from plan

**Section 5: Verification Results**
- Test execution output
- Build status
- Lint results

**Section 6: Blockers & Risks**
- Critical blockers
- Medium risks
- Technical debt

**Section 7: Discrepancies**
- Planned but not implemented
- Implemented but not planned (flagged)
- Different implementations

**Section 8: Next Steps**
- Immediate actions (prioritized)
- Short-term tasks
- Long-term items

---

## Handoff Options

After analysis, the agent provides handoff buttons:

### 📊 **Generate Status Report**
- Creates STATUS_REPORT.md in project root
- Comprehensive markdown report
- Sharable with team

### 🔄 **Update Plan**
- Hands off to PhaseExecutor
- Updates plan based on current progress
- Adjusts remaining work estimates

### 🚀 **Continue Implementation**
- Hands off to default agent
- Starts next incomplete phase/task
- References plan for guidance

---

## Best Practices

### ✅ DO:

1. **Run regularly** (daily or after major changes)
   - Track progress over time
   - Catch drift from plan early

2. **Review discrepancies section**
   - Update plan for unplanned work
   - Ensures plan stays in sync with reality

3. **Use STATUS_REPORT.md for standups**
   - Share completion metrics with team
   - Discuss blockers from report

4. **Act on priority recommendations**
   - Agent prioritizes based on plan dependencies
   - Follow suggested next steps

5. **Check verification results**
   - If tests fail, investigate immediately
   - Don't ignore build/lint errors

### ❌ DON'T:

1. **Don't ignore "Implemented but not planned"**
   - These need plan updates
   - Could indicate scope creep

2. **Don't treat percentages as exact**
   - Use as indicators, not absolutes
   - Context matters (complexity varies)

3. **Don't skip phases based on %**
   - 90% complete ≠ production ready
   - Verify exit criteria, not just %

4. **Don't run during active development**
   - Tests might be temporarily broken
   - Run during stable states

---

## Troubleshooting

### "No plan files found"

**Problem**: Agent can't locate plan documents

**Solutions**:
1. Check plan files exist: `plan.md`, `phased-plan.md`, `TODO.md`, etc.
2. Verify files are in project root or `/memories/session/`
3. Check file naming (must match expected patterns)

### "Verification commands failing"

**Problem**: Tests or builds failing during analysis

**Solutions**:
1. Run commands manually to verify they work: `npm test`, `pytest`, etc.
2. Check dependencies are installed
3. Ensure commands in plan are correct

### "Percentages seem wrong"

**Problem**: Completion % doesn't match your perception

**Solutions**:
1. Review STATUS_REPORT.md for calculation details
2. Check if agent is finding all files (might be in different locations)
3. Verify plan has up-to-date deliverable list

### "Report shows unplanned work"

**Problem**: Agent flags files not in plan

**Solutions**:
1. Update plan to include these files (if intentional)
2. Remove files if they're experimental/temporary
3. Create tech debt backlog for unplanned features

---

## Tips for Maximum Value

### 1. Keep Plans Updated

Agent accuracy depends on plan quality:
- Update plans when scope changes
- Mark completed tasks in PHASE_TRACKER.md
- Add verification commands to plans

### 2. Run Before Standups/Reviews

Generate fresh status reports:
```
@ProjectStatusAnalyzer
```
Use STATUS_REPORT.md for team discussions.

### 3. Track Progress Over Time

Save historical reports:
- Rename STATUS_REPORT.md to STATUS_REPORT_2026-04-05.md
- Compare week-over-week progress
- Identify velocity trends

### 4. Use with PhaseExecutor

Workflow:
1. **@PhaseExecutor** - Create phased plan
2. Implement Phase 1
3. **@ProjectStatusAnalyzer** - Check progress
4. **@PhaseExecutor** - Update plan if needed
5. Repeat for next phase

### 5. Integrate into CI/CD

Generate status reports automatically:
- Add agent invocation to PR checks
- Include STATUS_REPORT.md in commit messages
- Track completion in project docs

---

## Comparison with Manual Status Checks

| Task | Manual | ProjectStatusAnalyzer |
|------|--------|----------------------|
| Find all plan files | ⚠️ Might miss some | ✅ Searches entire project |
| Verify file existence | ✅ Easy | ✅ Automated |
| Check file contents | ⚠️ Time-consuming | ✅ Automated + deep analysis |
| Run tests | ✅ Manual commands | ✅ Runs all from plan |
| Calculate completion % | ⚠️ Guesswork | ✅ Precise metrics |
| Identify blockers | ⚠️ Subjective | ✅ Objective analysis |
| Generate report | ❌ Must write manually | ✅ Comprehensive markdown |
| Track over time | ⚠️ Spreadsheets | ✅ Versioned reports |

---

## FAQ

**Q: How long does analysis take?**  
A: Depends on project size and plan complexity. Typically 1-3 minutes for medium projects. Deep analysis with test execution takes longer.

**Q: Will it run tests that might break things?**  
A: It only runs commands specified in plan verification steps. If you included destructive commands in your plan, remove them first.

**Q: Can I run this on partial plans?**  
A: Yes! It analyzes whatever plans it finds. If you only have TODO.md, it will work with that.

**Q: What if my project has no plan files?**  
A: Agent will report "No plans found" and suggest creating one with @PhaseExecutor.

**Q: Does it modify my code?**  
A: No. It's read-only analysis. It only reads files, runs commands, and generates reports.

**Q: Can it track multiple projects?**  
A: It analyzes the current workspace. For multiple projects, run separately in each workspace.

**Q: How does it calculate completion %?**  
A: Weighted formula:
- Phase completion × 50%
- Task completion × 30%
- File completion × 20%
= Overall completion %

---

## Quick Reference Card

```
┌──────────────────────────────────────────────────────────┐
│       PROJECTSTATUSANALYZER QUICK REFERENCE              │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  BASIC:   @ProjectStatusAnalyzer                         │
│                                                          │
│  FOCUSED: @ProjectStatusAnalyzer Check Phase 2           │
│           @ProjectStatusAnalyzer Verify tests            │
│           @ProjectStatusAnalyzer Analyze auth module     │
│                                                          │
│  OUTPUT:  • Summary in chat (metrics, priorities)        │
│           • STATUS_REPORT.md (comprehensive details)     │
│                                                          │
│  FINDS:   plan.md, phased-plan.md, TODO.md,             │
│           PHASE_TRACKER.md, ROADMAP.md                   │
│                                                          │
│  VERIFIES: • File existence + content                    │
│            • Function/class implementation               │
│            • Test execution (runs tests)                 │
│            • Build/lint status                           │
│                                                          │
│  REPORTS:  • Phase breakdown                             │
│            • File verification tables                    │
│            • Test results                                │
│            • Blockers & risks                            │
│            • Prioritized next steps                      │
│                                                          │
│  HANDOFF:  📊 Generate Status Report                     │
│            🔄 Update Plan                                │
│            🚀 Continue Implementation                    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Related Agents

**PhaseExecutor** - Create detailed phased plans  
Use together: PhaseExecutor creates plans → ProjectStatusAnalyzer tracks progress

**Explore** - Deep codebase exploration  
ProjectStatusAnalyzer uses Explore agents internally for analysis

---

**Created**: 2026-04-05  
**Version**: 1.0  
**Location**: %USERPROFILE%\.vscode\agents\ProjectStatusAnalyzer.agent.md
