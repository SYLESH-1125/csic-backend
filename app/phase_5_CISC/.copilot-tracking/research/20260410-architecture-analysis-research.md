<!-- markdownlint-disable-file -->

# Task Research Notes: Architecture Implementation Analysis

## Research Executed

### File Analysis

- c:\CISC\operation-room\backend\app\worker\celery_app.py
  - Confirmed new Celery application factory configured with Redis as broker, task routing setup, and timezone/serialization configs.
- c:\CISC\operation-room\backend\app\worker\tasks.py
  - Discovered auto-discovered tasks (`generate_report_task`, `generate_section_task`).
- c:\CISC\operation-room\backend\app\routes\deep_research.py
  - Found integration of `generate_report_task.delay()` transitioning the system from synchronous to asynchronous celery dispatches.
- c:\CISC\operation-room\backend\app\services\pdf_signer.py
  - Analyzed cryptographic signature application layer (PAdES-B-LT X.509 + RFC3161 timestamps).

### External Research

- #codebase:"complete architecture"
  - The architecture aligns heavily with the "Event-Driven State Machine" required for deterministic, court-ready reporting as described in `CANONICAL_COURT_PIPELINE.md`.

### Project Conventions

- Standards referenced: India-Compliant Court Readability, X.509 PAdES-B-LT signatures, Event-driven architecture.
- Instructions followed: ./plan/architecture-canonical-court-pipeline-2.md

## Key Discoveries

### Project Structure

You have completely shifted the core report generation engine to a message-broker pattern.
- **Asynchronous Execution:** By introducing `celery_app.py` and `tasks.py`, the fragile, timeout-prone synchronous HTTP AI generation loop is now isolated into a background worker system (`nflip_worker` queue). 
- **API Offloading:** `app/routes/deep_research.py` now specifically triggers `.delay()` calls to launch background threads.

### Implementation Patterns

The pipeline currently sits at Phase 6 of the canonical blueprint: 
1. **Intake** -> Local DB Normalize 
2. **Clarification** -> Hypothesis Rubric 
3. **Plan/Evaluate** -> AST Generation 
4. **Execution** -> Celery Workers via Redis
5. **Validation gates** -> AI redaction / Citation integrity checked by canonical contracts.
6. **Export** -> Cryptographic signatures with RFC3161 timestamps.

### Technical Requirements

- **Async Stability:** Celery requires Redis/RabbitMQ infrastructure running locally or in Docker. 
- **Signatures:** The `pdf_signer.py` infrastructure is set up but needs actual HSM/KeyVault key resolution for true legal admissibility, currently likely relying on self-signed/mock certificates in dev.

## Recommended Approach

Focus on stabilizing the Celery/Redis container topology for local-dev and production loops, and wiring up the front-end to listen continuously to the WebSocket/Polling status from the Celery tasks rather than HTTP responses.

## Implementation Guidance

- **Objectives**: Stabilize event-driven worker topology.
- **Key Tasks**: 1. Test full end-to-end report dispatch over Redis. 2. Address PKI configuration mock for signatures. 3. Manage Dead Letter Queues for Celery tasks in case of LLM hallucinations.
- **Dependencies**: Redis, Celery Worker Process.
- **Success Criteria**: Celery worker successfully picks up task from API dispatch, runs deep research completely in the background without UI blocking, and emits legally signed PDF artifacts.
