# PhaseExecutor Agent - Complete Usage Guide

## What is PhaseExecutor?

PhaseExecutor is a specialized AI agent that creates **detailed, balanced, phased implementation plans** for software development tasks. Unlike basic planning tools, PhaseExecutor:

✅ **Balances effort** - Ensures each phase is 15-25% of total work  
✅ **Maximizes value** - Every phase delivers testable, working functionality  
✅ **Explains process** - Shows WHY decisions were made, not just WHAT to do  
✅ **Identifies risks** - Assesses and mitigates risks across all phases  
✅ **Enables parallelism** - Shows which phases can run simultaneously  
✅ **Provides verification** - Exact commands and expected outcomes for testing  

---

## Installation & Setup

### Step 1: Copy the Agent File

The agent was created in the project at:
```
C:\CISC\PhaseExecutor.agent.md
```
It has been moved to the global VS Code agents folder for system-wide availability. The current recommended location is:
```
%USERPROFILE%\.vscode\agents\PhaseExecutor.agent.md
```

For VS Code to recognize it, you need to either:
- **Option A**: Keep it in your project root (C:\CISC\)
- **Option B**: Move it to your global VS Code agents folder:
  ```
  %USERPROFILE%\.vscode\agents\PhaseExecutor.agent.md
  ```

### Step 2: Verify Agent is Loaded

1. Open VS Code
2. Open GitHub Copilot Chat (Ctrl+Shift+I or Cmd+Shift+I)
3. Type `@` in the chat
4. You should see **PhaseExecutor** in the agent list

### Step 3: Ready to Use!

No additional configuration needed. The agent is ready to plan your projects.

---

## How to Use PhaseExecutor

### Basic Usage Pattern

```
@PhaseExecutor {describe your software development task}
```

**Example:**
```
@PhaseExecutor Build a REST API for managing user profiles with authentication
```

### The Planning Workflow

PhaseExecutor follows a 4-phase planning workflow:

#### 1️⃣ **Discovery** (PhaseExecutor does this automatically)
- Launches multiple Explore agents to research your codebase
- Analyzes existing patterns and architecture
- Identifies dependencies and constraints
- Determines optimal number of phases (2-6)

#### 2️⃣ **Clarification** (Interactive - you answer questions)
- PhaseExecutor asks targeted questions to clarify:
  - Scope boundaries (what's in/out)
  - Priority ordering (what's critical vs. nice-to-have)
  - Success criteria (how to measure "done")
  - Technical constraints (performance, security, compatibility)

#### 3️⃣ **Plan Creation** (PhaseExecutor generates the plan)
- Creates comprehensive phased plan
- Saves to `/memories/session/phased-plan.md`
- Presents scannable summary with:
  - Phase overview and effort distribution
  - Dependency graph
  - Risk assessment
  - Key technical decisions

#### 4️⃣ **Refinement** (Iterative - based on your feedback)
- You can request:
  - Rebalancing phases
  - More detail on specific phase
  - Scope changes
  - Alternative approaches
- PhaseExecutor refines until you approve

---

## Example Usage Scenarios

### Scenario 1: New Feature Development

**Task:** Add real-time notifications to web app

```
@PhaseExecutor Implement real-time push notifications for our web application. 
Users should receive instant notifications for messages, alerts, and updates.
```

**What PhaseExecutor will do:**
1. Research your current tech stack (WebSocket support, backend framework)
2. Ask clarification questions (browser support, notification types, storage)
3. Create phased plan, likely:
   - Phase 1: Backend notification service (WebSocket server, event handlers)
   - Phase 2: Frontend notification UI (toast components, sound alerts)
   - Phase 3: Notification persistence (database schema, history)
   - Phase 4: Testing & optimization (E2E tests, performance tuning)

### Scenario 2: Refactoring Complex Code

**Task:** Modernize legacy authentication module

```
@PhaseExecutor Refactor our legacy authentication system from session-based 
to JWT tokens while maintaining backward compatibility during transition.
```

**What PhaseExecutor will do:**
1. Explore current authentication code patterns
2. Ask about migration timeline and user impact tolerance
3. Create risk-aware phased plan:
   - Phase 1: JWT infrastructure (token generation, validation)
   - Phase 2: Dual-mode support (both session and JWT work)
   - Phase 3: Frontend migration (update API calls)
   - Phase 4: Deprecation & cleanup (remove session code)

### Scenario 3: Data Pipeline Development

**Task:** Build ETL pipeline for analytics

```
@PhaseExecutor Create an ETL pipeline that ingests CSV files from S3, 
transforms the data, and loads into PostgreSQL for reporting.
```

**What PhaseExecutor will do:**
1. Research your current data processing setup
2. Ask about data volume, frequency, and transformation rules
3. Create balanced phased plan:
   - Phase 1: Extract layer (S3 connector, file parsing)
   - Phase 2: Transform layer (data validation, business rules)
   - Phase 3: Load layer (database insertion, error handling)
   - Phase 4: Orchestration (scheduling, monitoring, alerting)

---

## Advanced Features

### 1. Request Deep Dive on Specific Phase

After seeing the plan:
```
@PhaseExecutor I need more detail on Phase 2 - the frontend notification UI
```

PhaseExecutor will:
- Launch dedicated Explore agent for that phase
- Expand implementation steps with code examples
- Add more verification procedures
- Update the plan with enhanced details

### 2. Generate Progress Tracker

During or after planning:
```
@PhaseExecutor Generate a phase tracker
```

PhaseExecutor creates `PHASE_TRACKER.md` with:
- Checkbox for every deliverable
- Checkbox for every verification step
- Checkbox for every exit criterion
- Space for notes and blockers
- Progress percentage calculation

### 3. Rebalance Phases

If phases seem uneven:
```
@PhaseExecutor Phase 2 looks too big - can you rebalance?
```

PhaseExecutor will:
- Analyze complexity points
- Split oversized phase into smaller phases
- Recalculate effort distribution
- Update dependency graph
- Re-present balanced plan

### 4. Alternative Approaches

If you want to explore options:
```
@PhaseExecutor Show me an alternative approach using microservices 
instead of monolithic architecture
```

PhaseExecutor will:
- Launch Explore agent for alternative research
- Create comparison table (pros/cons)
- Recommend best approach
- Let you choose, then generate plan accordingly

---

## Understanding the Plan Output

### Plan Structure

PhaseExecutor plans include these sections:

#### **Executive Summary**
- What, Why, How, When, Success Criteria

#### **Phase Structure Rationale**
- Why this many phases?
- Which boundary strategy used?
- Effort distribution table

#### **Dependency Graph**
- Visual representation of phase relationships
- Which phases are parallel vs. sequential

#### **Risk Assessment**
- High-risk items identified
- Mitigation strategies per phase

#### **Phase Definitions** (for each phase)
- Duration estimate (% of effort)
- Goals (primary, secondary, risk mitigation)
- Dependencies (blocking, preferred, parallel)
- Entry criteria (pre-conditions)
- Detailed implementation steps
- Deliverables (concrete outputs)
- Verification procedures (unit, integration, manual, performance)
- Exit criteria (completion checklist)
- Process notes (rationale, alternatives, decisions)

#### **Critical Files**
- Files to create with purpose
- Files to modify with specific functions

#### **Cross-Phase Considerations**
- Architecture decisions
- Testing strategy
- Documentation requirements

#### **Parallel Opportunities**
- How to organize work with multiple developers

---

## Handoff Options

After plan approval, PhaseExecutor provides handoff buttons:

### 🚀 **Start Phase 1**
- Hands off to default agent to begin implementation
- Default agent will follow the detailed plan
- References `/memories/session/phased-plan.md`

### 📋 **View Full Plan**
- Creates untitled file with complete plan
- Useful for editing or sharing

### 📊 **Generate Phase Tracker**
- Creates `PHASE_TRACKER.md` in project root
- Track progress with checkboxes

### 🔍 **Deep Dive Phase**
- Ask which phase needs more detail
- Get comprehensive implementation guidance

---

## Best Practices

### ✅ DO:

1. **Be specific about your task**
   - Good: "Build REST API for user profiles with JWT auth and CRUD operations"
   - Bad: "Make an API"

2. **Answer clarification questions thoughtfully**
   - PhaseExecutor asks to save time later
   - Better to clarify now than refactor later

3. **Request more detail if needed**
   - Don't hesitate to ask for deep dives
   - Better over-prepared than under-prepared

4. **Review the risk assessment**
   - PhaseExecutor identifies risks early
   - Consider mitigation strategies seriously

5. **Use the phase tracker**
   - Track progress as you implement
   - Catch blockers early

### ❌ DON'T:

1. **Don't ask PhaseExecutor to implement**
   - It only plans, doesn't code
   - Use handoff buttons to start implementation

2. **Don't skip clarification questions**
   - Assumptions lead to rework
   - Answer questions to get accurate plan

3. **Don't ignore phase balance warnings**
   - Unbalanced phases cause delays
   - Let PhaseExecutor rebalance

4. **Don't treat plan as rigid**
   - Plans should adapt to reality
   - Request changes as you learn more

---

## Troubleshooting

### "PhaseExecutor doesn't appear in @ menu"

**Solution:**
1. Ensure `PhaseExecutor.agent.md` is in project root or `~/.vscode/agents/`
2. Reload VS Code window (Ctrl+Shift+P → "Reload Window")
3. Check file has correct YAML frontmatter

### "Plan is too vague / not enough detail"

**Solution:**
```
@PhaseExecutor This needs more detail. Can you expand Phase {N} with 
specific code examples and file paths?
```

### "Phases are unbalanced"

**Solution:**
```
@PhaseExecutor Phase 1 is 40% of effort while Phase 2 is only 10%. 
Please rebalance to make phases more equal.
```

### "I need to change the scope mid-planning"

**Solution:**
```
@PhaseExecutor Scope change: we also need to add {new feature}. 
Please update the plan.
```

PhaseExecutor will loop back to Discovery and create revised plan.

---

## Tips for Maximum Value

### 1. **Front-load Risk**
Ask PhaseExecutor to:
```
@PhaseExecutor Prioritize high-risk items early. I want to validate 
feasibility before investing heavily.
```

### 2. **Optimize for Parallel Work**
If you have multiple developers:
```
@PhaseExecutor We have 3 developers. Show me how to parallelize phases 
for maximum throughput.
```

### 3. **Integrate with Existing Workflows**
Tell PhaseExecutor about your practices:
```
@PhaseExecutor Our team requires 80% test coverage and code review before 
merging. Include these in exit criteria.
```

### 4. **Learn from Plans**
PhaseExecutor explains WHY decisions are made:
- Read "Process Notes" sections
- Understand "Alternatives Considered"
- Review "Risk Mitigation" strategies

### 5. **Iterate on the Plan**
Don't settle for first draft:
```
@PhaseExecutor This is good, but could we do Phase 2 and 3 in parallel? 
They don't seem to depend on each other.
```

---

## Comparison with Other Planning Tools

| Feature | PhaseExecutor | Standard Plan Agent | Manual Planning |
|---------|---------------|---------------------|-----------------|
| Effort balancing | ✅ Automated | ❌ Manual | ❌ Manual |
| Process explanations | ✅ Detailed | ⚠️ Basic | ❌ None |
| Risk assessment | ✅ Built-in | ❌ Not included | ⚠️ Ad-hoc |
| Dependency tracking | ✅ Graph + details | ⚠️ List only | ❌ Mental model |
| Parallel opportunities | ✅ Identified | ❌ Not tracked | ⚠️ Implicit |
| Verification procedures | ✅ Exact commands | ⚠️ Generic | ⚠️ Varies |
| Complexity estimation | ✅ Points system | ❌ Time only | ⚠️ Guesswork |
| Progress tracking | ✅ Generated tracker | ❌ None | ⚠️ Separate tool |

---

## Example Output

Here's what a PhaseExecutor plan summary looks like:

```
## Phased Implementation Plan: User Profile REST API

4 phases identified (balanced at ~25% effort each)

📊 Phase Overview:
├─ Phase 1: Database & Models (26%) - Foundation
├─ Phase 2: API Endpoints (24%) - Core (parallel ready)  
├─ Phase 3: Authentication (25%) - Security (parallel ready)
└─ Phase 4: Testing & Docs (25%) - Quality (depends on 1,2,3)

🔗 Dependencies:
• Sequential: Phase 1 must complete first
• Parallel: Phase 2 & 3 can run simultaneously after Phase 1
• Final: Phase 4 requires all previous phases

⚠️ Top Risks:
1. JWT implementation complexity → Mitigated in Phase 3 with POC
2. Database performance at scale → Validated in Phase 1 with benchmarks
3. API security vulnerabilities → Addressed in Phase 4 with security scan

🎯 Key Decisions:
• Using PostgreSQL with SQLAlchemy ORM (existing stack)
• JWT for stateless auth (scalability over sessions)
• OpenAPI spec for API documentation (industry standard)

✅ Next Steps: Approve plan to start implementation
```

---

## FAQ

**Q: Can PhaseExecutor write code?**  
A: No, PhaseExecutor only creates plans. Use handoff buttons to start implementation with the default agent.

**Q: How long does planning take?**  
A: Typically 2-5 minutes depending on task complexity and codebase size.

**Q: Can I modify the plan manually?**  
A: Yes! The plan is saved in `/memories/session/phased-plan.md`. Edit directly or ask PhaseExecutor to revise.

**Q: What if I'm already mid-implementation?**  
A: PhaseExecutor can create plans for remaining work. Just describe what's left to do.

**Q: Can PhaseExecutor handle non-coding tasks?**  
A: It's optimized for software development. For other domains, use the standard Plan agent.

**Q: How does PhaseExecutor know my codebase?**  
A: It launches Explore agents that search your code, read files, and understand patterns.

---

## Support & Feedback

**Created:** 2026-04-04  
**Version:** 1.0 Enhanced  
**Location:** C:\CISC\PhaseExecutor.agent.md  

For issues or enhancement requests, modify the agent file directly or create a new version.

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│          PHASEEXECUTOR QUICK REFERENCE              │
├─────────────────────────────────────────────────────┤
│                                                     │
│  START:  @PhaseExecutor {your development task}    │
│                                                     │
│  MODIFY: @PhaseExecutor rebalance phases           │
│          @PhaseExecutor more detail on Phase N     │
│          @PhaseExecutor add {feature} to scope     │
│                                                     │
│  TOOLS:  @PhaseExecutor generate phase tracker     │
│          @PhaseExecutor show alternative approach  │
│                                                     │
│  OUTPUT: /memories/session/phased-plan.md          │
│                                                     │
│  HANDOFF: 🚀 Start Phase 1                         │
│           📋 View Full Plan                        │
│           📊 Generate Phase Tracker                │
│           🔍 Deep Dive Phase                       │
│                                                     │
└─────────────────────────────────────────────────────┘
```
