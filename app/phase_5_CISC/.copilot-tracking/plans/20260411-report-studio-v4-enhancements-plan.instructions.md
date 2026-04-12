---
applyTo: ".copilot-tracking/changes/20260411-report-studio-v4-enhancements-changes.md"
---

<!-- markdownlint-disable-file -->

# Task Checklist: Report Studio V4 Court-Ready Enhancements

## Overview

Implement dynamic auto-pagination layout, immutable evidence binding via AST-aware rich text editor, WeasyPrint high-fidelity export, and self-critique agents to elevate the pipeline to true court-ready standards.

## Objectives

- Replace absolute Canva-style (X,Y) positioning with a relative Flexbox Bounded Flow grid.
- Replace fragile \<textarea>\ editing with an AST editor (Lexical/Slate.js) to preserve evidence UUIDs.
- Replace \ReportLab\ with \WeasyPrint\ (HTML/CSS to PDF) for 100% pixel matching between UI and PDF.
- Inject a "Red Team Critique Agent" to review AI drafts before binding to the report AST.

## Research Summary

### Project Files

- c:\CISC\operation-room\backend\app\services\reportlab_pdf_service.py - Current PDF exporter causing visual mismatches.
- c:\CISC\operation-room\frontend\src\components\studio-v4\canvas\DocumentCanvas.tsx - Current absolute canvas layout.

### External References

- #file:../research/20260411-report-studio-v4-enhancements-research.md - Detailed trade-off and architecture analysis (WeasyPrint over Playwright).

## Implementation Checklist

### [ ] Phase 1: Dynamic Flow Engine & Layout Updates

- [ ] Task 1.1: Migrate \DocumentCanvas.tsx\ to use Bounded Flow Flexbox (Auto-Pagination algorithm).
  - Details: .copilot-tracking/details/20260411-report-studio-v4-enhancements-details.md (Lines 11-15)

### [ ] Phase 2: Evidence Binding Immutability (AST Editor)

- [ ] Task 2.1: Integrate an AST Rich Text Editor (e.g., Slate.js or Lexical) in Studio V4.
  - Details: .copilot-tracking/details/20260411-report-studio-v4-enhancements-details.md (Lines 20-25)

### [ ] Phase 3: WeasyPrint Headless Fidelity Export

- [ ] Task 3.1: Replace \ReportLab\ with WeasyPrint for pristine PDF generation.
  - Details: .copilot-tracking/details/20260411-report-studio-v4-enhancements-details.md (Lines 30-35)

### [ ] Phase 4: Red Team Critique Agent 

- [ ] Task 4.1: Intercept Celery tasks with a secondary LLM critique pass (temperature=0.0).
  - Details: .copilot-tracking/details/20260411-report-studio-v4-enhancements-details.md (Lines 40-45)

## Dependencies

- WeasyPrint (Python)
- Slate.js or Lexical (React)

## Success Criteria

- Text correctly spills over page boundaries automatically without breaking structure.
- User can backspace inside a report editor without destroying the underlying evidence UUID.
- Exported PDF matches the Studio UI React layout 1:1.
