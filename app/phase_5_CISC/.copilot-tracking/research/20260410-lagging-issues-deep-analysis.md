<!-- markdownlint-disable-file -->

# Task Research Notes: Deep Analysis of Current Architecture Issues

## Research Executed

### File Analysis

- c:\CISC\operation-room\backend\app\services\unified_orchestrator.py
  - Evaluated UnifiedInvestigationOrchestrator state management. Discovered it relies on an in-memory dictionary (self.active_investigations).
- c:\CISC\operation-room\backend\app\worker\tasks.py
  - Evaluated generate_report_task and the implementation of _publish_status(), which proves the system shifts from direct yield streaming to Redis Pub/Sub for Celery tasks.

### External Research

- #codebase:"WebSocket disconnect"
  - Investigated frontend-backend bridge for nflip:report:channel Pub/Sub stream routing.

### Project Conventions

- Standards referenced: Event-Driven State Machine, Zero Trust Validation.
- Instructions followed: ./plan/architecture-canonical-court-pipeline-2.md

## Key Discoveries

### Project Structure

A deep disconnect exists between the legacy UnifiedInvestigationOrchestrator design and the newly introduced Canonical Celery Worker pattern. The architecture lives in a split-brain state.

### Implementation Patterns

**The Splintered Orchestrator Problem:**
1. **In-Memory State Loss:** The UnifiedInvestigationOrchestrator stores state heavily in an instance-level dictionary: self.active_investigations.
   - *Impact:* Because Celery runs in separate spawned worker processes, any task executed by a worker does not share memory with the FastAPI app. Thus, requesting investigation state via normal HTTP routes will fail to return the updated state.
   - *Failure Point:* Resumability (a key goal of the canonical pipeline) is broken because state is not persisted to a persistent store like Redis or Postgres.

**The Streaming Bridge Disconnect:**
2. **WebSocket Publisher Gap:**
   - *Detail:* The generate_report_task utilizes _publish_status() targeting Redis Pub/Sub channels.
   - *Impact:* app/services/websocket_manager.py or unified_orchestrator.py requires an asynchronous listener subscription hooked to this Redis PubSub channel that explicitly pipes incoming JSON events into the connected client. If this daemon loop is not implemented, the frontend spinner will hang endlessly post-launch because the Celery updates simply log into Redis and go unread.

**The Cryptographic Dependency Tunnel:**
3. **PKI Key Rotations (pdf_signer.py):**
   - *Detail:* India-compliant signature requirements strictly mandate deterministic trusted timestamps and HSM-bound private keys. The new signer assumes these keys are universally present in local dev environments.
   - *Impact:* Will cause late-stage generation crashes for any developer without the explicitly mapped certificate files.

## Recommended Approach

Do not alter the canonical blueprint. Rather, enforce explicit state synchronization (Redis/DB) in the Orchestrator, and wire a PubSub listener inside the FastAPI WebSocket endpoint.

## Implementation Guidance

- **Objectives**: Resolve split-brain state and unblock the event stream.
- **Key Tasks**: 
   - Analyze if websocket_manager.py loops over Redis PubSub.
   - Audit UnifiedInvestigationOrchestrator to switch self.active_investigations to a Redis store cache.
- **Dependencies**: Redis PubSub, Celery.
- **Success Criteria**: Clear definition of the precise synchronization flaws in the architecture without mutating code.
