---
mode: agent
model: Claude Sonnet 4
---

<!-- markdownlint-disable-file -->

# Implementation Prompt: Report Studio V4 Enhancements

## Implementation Instructions

### Step 1: Create Changes Tracking File

You WILL create \20260411-report-studio-v4-enhancements-changes.md\ in #file:../changes/ if it does not exist.

### Step 2: Execute Implementation

You WILL systematically implement #file:../plans/20260411-report-studio-v4-enhancements-plan.instructions.md task-by-task.
You WILL install \slate\, \lexical\, or target NPM package, as well as Python dependencies \weasyprint\ inside the backend.
Ensure the canvas auto-paginates content exceeding 842px.
Ensure evidence UI nodes in the rich text editor cannot be partially deleted to corrupt the UUID.
Implement WeasyPrint HTML/CSS generation matching the React styling precisely.

**CRITICAL**: If stop conditions are true, you WILL stop after each Phase for user review.

### Step 3: Cleanup

When ALL Phases are completed, you WILL:
1. Provide a markdown summary of all changes from the changes file.
2. Provide links to the tracking documents.
3. Recommend cleaning up implementation prompts.

## Success Criteria

- [ ] Slate/Lexical Editor safely encapsulates UUID AST nodes.
- [ ] Overflowing narrative blocks push child layout containers gracefully onto Page 2.
- [ ] WeasyPrint native Python PDF prints identical HTML boundaries relative to the frontend React layout.
- [ ] Prompt critique layer applied to Celery text generation workers.
