<!-- markdownlint-disable-file -->

# Task Details: Report Studio V4 Court-Ready Enhancements

## Research Reference

**Source Research**: #file:../research/20260411-report-studio-v4-enhancements-research.md

## Phase 1: Dynamic Flow Engine & Layout Updates

### Task 1.1: Auto-Pagination Algorithm

Replace absolute coords in Canvas. Build a Bounded Flow grid. React mounts hidden paragraphs, calculates height >= 842px (A4), and pushes overflow nodes to Page 2.

- **Files**:
  - \operation-room/frontend/src/components/studio-v4/canvas/DocumentCanvas.tsx\ - Swap absolute nodes for flex containers.
- **Success**: Text gracefully breaks across pages without breaking charts.

## Phase 2: Evidence Binding Immutability (AST Editor)

### Task 2.1: Implement Slate.js / Lexical

Map the backend JSON syntax AST directly to Slate UI nodes. Make \vidence_citation\ blocks atomic nodes. 

- **Files**:
  - \operation-room/frontend/src/components/studio-v4/editor/RichTextEditor.tsx\ (Create New)
- **Success**: Users can edit report text but backspacing inside a UUID block deletes the entire block uniformly.

## Phase 3: WeasyPrint Headless Fidelity Export

### Task 3.1: Replace ReportLab

Switch PDF export backend logic to cast the AST to HTML strings formatted with Tailwind logic identical to the React UI, piped into Python \weasyprint\ library.

- **Files**:
  - \operation-room/backend/app/services/pdf_service.py\ (Create/Refactor)
- **Success**: Output PDFs perfectly mirror the screen.

## Phase 4: Red Team Critique Agent

### Task 4.1: Implement Self-Correction Loop

Update Celery loops generating context. Drafts go to an adversarial LLM prompt ("Defense Attorney") looking for unsupported claims or high temperature variances.

- **Files**:
  - \operation-room/backend/app/worker/tasks.py\ - Intercept generation.
- **Success**: Extraneous LLM "chat" and unsourced conclusions are natively removed.

## Dependencies
- npm i slate slate-react weasyprint
