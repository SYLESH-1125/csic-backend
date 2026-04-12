<!-- markdownlint-disable-file -->

# Task Research Notes: Report Studio V4 Quality & Effectiveness Enhancements

## Research Executed

### External Research
- #codebase:"Report Studio V4 Architecture"
  - Investigated frontend (React) vs backend (ReportLab) rendering mismatches.
  - Investigated evidence UUID binding fragility in standard textareas.

## Key Discoveries
- **Dynamic Flow Engine:** Canvas X/Y absolute positioning causes text overflow. A hybrid "Bounded Flow" (Flexbox paginated grid) is required.
- **Export Fidelity:** ReportLab causes 10-30% visual mismatch. WeasyPrint (HTML/CSS to PDF natively in backend) is the optimal hybrid solution to replace ReportLab.
- **Immutability of Evidence:** Standard textareas break inline UUIDs (`[evidence-1234]`). An AST-aware editor (Slate.js/Lexical) is required to treat citations as immutable nodes.
- **Content Quality:** Zero-shot drafts hallucinate. A Red Team Critique Agent and Few-Shot Gold Standard prompts are needed.

## Recommended Approach
Migrate Studio V4 to a flex-grid layout, adopt WeasyPrint for Python-based 1:1 PDF exports, replace the textarea with Lexical/Slate for AST-based editing, and weave a Critique Agent into `tasks.py`.

