# Forensic AI Engine — Ingestion Phase: Deep Technical Documentation

> All changes made across Phase-1 (build) and Phase-2 (validation).  
> Audience: developers who need to understand **exactly** what happens  
> from the moment a file enters the system to the moment it is sealed.

---

## Table of Contents

1. [What Changed and Why](#1-what-changed-and-why)
2. [High-Level Ingestion Flow](#2-high-level-ingestion-flow)
3. [Step-by-Step: Manual Upload Flow](#3-step-by-step-manual-upload-flow)
4. [Node 1 — Entry Routes (3 paths in)](#4-node-1--entry-routes-3-paths-in)
5. [Node 2 — JIT Authentication Gateway](#5-node-2--jit-authentication-gateway)
6. [Node 3 — WebSocket Chunk Streaming](#6-node-3--websocket-chunk-streaming)
7. [Node 4 — Merkle Tree Sealing](#7-node-4--merkle-tree-sealing)
8. [Node 5 — Sandbox Triage (3 filters)](#8-node-5--sandbox-triage-3-filters)
9. [Node 6 — Ledger Commit + WORM Storage](#9-node-6--ledger-commit--worm-storage)
10. [Legacy Ingestion (upload-log)](#10-legacy-ingestion-upload-log)
11. [Database Changes Explained](#11-database-changes-explained)
12. [What Every New File Does](#12-what-every-new-file-does)
13. [Security Properties Guaranteed](#13-security-properties-guaranteed)
14. [Failure Modes and What Happens](#14-failure-modes-and-what-happens)
15. [Data at Rest — Directory Layout](#15-data-at-rest--directory-layout)

---

## 1. What Changed and Why

### Before Phase-1

The system had a single ingestion path:

```
POST /api/ingestion/upload-log
  → reads entire file into RAM
  → SHA-256 hash
  → writes AuditLog row
  → done
```

**Problems with this:**
- No authentication before accepting data
- Entire file loaded into RAM (dangerous for large files)
- No tamper-evidence at chunk level
- No malware/bomb detection before storage
- Files stored with normal permissions (overwriteable)
- No IP-binding or session replay prevention

### After Phase-1

Nine-step cryptographically sealed pipeline:

```
REST entry route  →  JIT session  →  WebSocket stream
  →  per-chunk SHA-256  →  Merkle seal  →  ZIP/magic/malware sandbox
  →  ledger commit (hash chain)  →  WORM storage  →  async deep scan
```

**Every step is independent and will abort the pipeline on failure.**  
No partial writes. No ledger entries for quarantined files.

---

## 2. High-Level Ingestion Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser / Agent)                        │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │  POST /api/ingestion/manual  │  ← Entry Route (Node 1)
                  │  POST /api/ingestion/cloud   │
                  │  POST /ingestion/telemetry   │
                  └──────────────┬──────────────┘
                                 │  Returns: session_id + websocket_url
                                 │
                  ┌──────────────▼──────────────┐
                  │  JIT Auth Gateway (Node 2)  │
                  │  • IP binding check          │
                  │  • TTL check (30 min)        │
                  │  • Burn-on-use (OTP)         │
                  └──────────────┬──────────────┘
                                 │  Session consumed (marked used=True)
                                 │
                  ┌──────────────▼──────────────┐
                  │  WS /ws/secure-stream/{id}  │  ← Node 3
                  │  • JSON chunk envelope       │
                  │  • SHA-256 per chunk         │
                  │  • Sequence enforcement      │
                  │  • Size limit (5 MB/chunk)   │
                  │  • Disk-only (no RAM buffer) │
                  └──────────────┬──────────────┘
                                 │  All chunks on disk in data/temp/
                                 │
                  ┌──────────────▼──────────────┐
                  │  Merkle + SHA-256 (Node 4)  │
                  │  • build_merkle_root()       │
                  │  • streaming SHA-256         │
                  └──────────────┬──────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │  Sandbox Triage (Node 5)    │
                  │  • ZIP bomb check            │
                  │  • Magic byte check          │
                  │  • YARA/entropy scan         │
                  └───────┬──────────────┬──────┘
                          │              │
                     CLEAN │        FLAGGED → QuarantineLog + ABORT
                          │
                  ┌────────▼──────────────────────┐
                  │  Ledger + WORM (Node 6)       │
                  │  • AuditLog chain-append       │
                  │  • File → data/worm/ (0o444)  │
                  │  • async deep scan (bgd task) │
                  └───────────────────────────────┘
```

---

## 3. Step-by-Step: Manual Upload Flow

This is the full lifecycle of a file uploaded through the browser UI.

### Step 1 — Client calls `POST /api/ingestion/manual`

```
POST /api/ingestion/manual
Content-Type: application/json
(no body required)
```

Server reads `request.client.host` (or `X-Forwarded-For` behind a proxy).  
Creates an `IngestionSession` row in SQLite:

```
session_id  = "a1b2c3d4-..."   (UUID v4)
bound_ip    = "192.168.1.10"   (locked to THIS client IP)
expires_at  = now + 30 minutes
used        = False
mode        = "manual"
```

Response:
```json
{
  "session_id": "a1b2c3d4-...",
  "websocket_url": "ws://host/ws/secure-stream/a1b2c3d4-...",
  "expires_at": "2026-03-04T10:30:00Z",
  "mode": "manual"
}
```

The client has **30 minutes** to use this URL. It will only work from **the same IP**.

---

### Step 2 — Client opens WebSocket (`WS /ws/secure-stream/{session_id}`)

The WebSocket upgrade request hits `ws_router.py`.

**First action: `await websocket.accept()`** — the TCP handshake must complete before any close frames can be sent. This is a WebSocket spec requirement.

Then authentication happens immediately:

```python
session = store.get(session_id)   # DB lookup
client_ip = _extract_ws_client_ip(websocket)
_enforce_rules(session, client_ip, context="WS")
```

`_enforce_rules` checks **in this exact order**:

| Check | What is compared | Failure code |
|-------|-----------------|--------------|
| Session exists | `session is None` | `4001` |
| IP binding | `client_ip != session.bound_ip` | `4003` |
| TTL | `now_utc() > session.expires_at` | `4008` (mapped via PermissionError) |
| Burn-on-use | `session.used == True` | `4003` |

If all pass: `store.mark_used(session)` sets `used = True` atomically.  
**No second connection can ever reuse the same session_id.**

---

### Step 3 — Client streams chunks

Client splits the file into chunks (recommended: 1 MB each) and sends each as:

```json
{
  "chunk_number": 0,
  "chunk_hash": "e3b0c44298fc1c149afb...",
  "data": "SGVsbG8gV29ybGQ=",
  "is_final": false
}
```

**`data`** is `base64.b64encode(raw_bytes)`.  
**`chunk_hash`** is `sha256(raw_bytes)` — computed **before** encoding.

Server-side for each chunk:

```
1. Parse JSON
2. Check chunk_number == expected  →  else close 4400
3. Check encoded length <= 5 MB × 4/3  →  else close 4413
4. base64.b64decode(data)
5. sha256(decoded) == chunk_hash  →  else close 4422 "HASH MISMATCH"
6. write bytes to data/temp/{session_id}/chunk_000000.bin
7. append server_hash to chunk_hashes[]
8. send {"status": "ok", "chunk_number": 0}
```

**Why write to disk immediately?** Memory safety. A 10 GB log file in RAM would crash the server. Each chunk is written and freed immediately.

On final chunk (`"is_final": true`) the chunk loop exits.

---

### Step 4 — Reconstruction

```python
with open(reconstructed_path, "wb") as out_fh:
    for i in range(len(chunk_hashes)):
        chunk_path = session_dir / f"chunk_{i:06d}.bin"
        with open(chunk_path, "rb") as chunk_fh:
            out_fh.write(chunk_fh.read())
        chunk_path.unlink()   # delete chunk immediately after reading
```

Individual chunk files are deleted as they are assembled to free disk space.  
Result: `data/temp/{session_id}/{filename}` — the full reconstructed file.

---

### Step 5 — Merkle Root + SHA-256

**Merkle root** (chunk-level tamper detection):
```python
merkle_root = build_merkle_root(chunk_hashes)
```
The ordered list of chunk hashes forms the leaves of the tree.  
`build_merkle_root` pairs adjacent hashes, SHA-256s each pair, repeats until one root remains.  
Stored in `AuditLog.merkle_root`.  
If **any single chunk** was modified, the root will be different.

**Monolithic SHA-256** (file-level integrity):
```python
def _compute_sha256_file(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()
```
Reads in 64 KB blocks — never loads whole file into RAM.  
Stored in `AuditLog.sha256_hash`.

---

### Step 6 — Sandbox Triage

`run_sync_triage()` runs three filters in sequence:

#### Filter 1 — ZIP Bomb

```python
def check_zip_bomb(file_path) -> bool:
    if not zipfile.is_zipfile(file_path):
        return False   # not a ZIP, skip
    compressed_size = file_path.stat().st_size
    uncompressed_size = sum(info.file_size for info in zip.infolist())
    ratio = uncompressed_size / compressed_size
    return ratio > 100.0   # True = IS a bomb
```

**Why 100×?** A 1 MB ZIP that would expand to 100 MB+ is a resource exhaustion attack. Normal ZIPs rarely exceed 10× compression.

#### Filter 2 — Magic Byte Inspection

```python
DANGEROUS_MAGIC = {b"MZ", b"\x7fELF"}
# MZ  = Windows PE executable (.exe, .dll)
# ELF = Linux executable
```

If detected in a file **whose extension is NOT `.exe`/`.dll`/`.elf`** → flagged.  
Example: a file named `access.log` that starts with `MZ` is an executable disguised as a log.  
The rule: **extension must match actual binary header**.

#### Filter 3 — Async Deep Scan (background)

Run **after** the WebSocket closes (non-blocking):
- **Entropy** check: Shannon entropy > 7.2 bits/byte → likely encrypted/packed malware
- **Extension blacklist**: `.exe`, `.dll`, `.bat`, `.ps1`, `.jar`, etc.
- **YARA-style patterns**: scans for `cmd.exe`, `powershell`, `CreateRemoteThread`, `VirtualAlloc`, NOP sleds (`\x90\x90\x90\x90`), etc.

If **any filter fires**, `_quarantine_file()` runs:
```python
# 1. Mark file read-only before moving
os.chmod(file_path, stat.S_IRUSR)   # 0o400

# 2. Move to quarantine directory
shutil.move(file_path, QUARANTINE_DIR / filename)

# 3. Create QuarantineLog DB record
QuarantineLog(
    original_filename=filename,
    quarantine_path=str(dest),
    sha256_hash=sha256_of_file,
    reason="zip_bomb" | "magic_byte" | "malware_scan",
    risk_score=0.0-1.0,
    details=json_details,
    source_ip=source_ip,
    ingestion_mode=ingestion_mode,
    session_id=session_id,
)

# 4. Pipeline aborts — NO AuditLog entry written
return quarantine_record
```

**Clean files** return `None` from `run_sync_triage()` — pipeline continues.

---

### Step 7 — WORM Storage

```python
dest = WORM_DIR / filename
shutil.move(str(reconstructed_path), str(dest))
os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 0o444
```

`0o444` = read-only for owner, group, and others. No write bit for anyone.  
Any attempt to open the file for writing raises `PermissionError`.  
The file cannot be silently overwritten by the application.

If a filename collision occurs, the server prepends a UTC microsecond timestamp:
```python
dest = WORM_DIR / f"20260304103000123456_{filename}"
```

---

### Step 8 — Ledger Commit (Hash Chain)

```python
previous_hash = db.query(AuditLog).order_by(upload_time.desc()).first().sha256_hash

entry = AuditLog(
    filename       = filename,
    sha256_hash    = mono_sha256,       # current file hash
    previous_hash  = previous_hash,     # last committed file's hash
    merkle_root    = merkle_root,
    source_ip      = client_ip,
    ingestion_mode = session.mode,
    upload_time    = datetime.utcnow(),
    file_size      = worm_path.stat().st_size,
)
```

**Why `previous_hash`?**  
Every record links to the one before it. This creates a blockchain-style chain:

```
Record 1: sha256="aaa", previous_hash=NULL
Record 2: sha256="bbb", previous_hash="aaa"
Record 3: sha256="ccc", previous_hash="bbb"
```

If an attacker modifies Record 2's hash to `"xxx"`, Record 3's `previous_hash="bbb"` no longer matches — the chain is detectably broken.  
`GET /api/ingestion/verify-chain` walks the entire chain and reports any break.

---

### Step 9 — Async Malware Scan + WebSocket Close

After ledger commit, before closing:

```python
asyncio.create_task(async_malware_scan(file_path=worm_path, ...))
```

This runs the deep entropy + YARA scan in the background.  
The WebSocket sends the final ACK and closes **immediately** — client is not blocked.

Final message to client:
```json
{
  "status": "done",
  "audit_id": "uuid",
  "merkle_root": "sha256hex",
  "sha256": "sha256hex",
  "filename": "access.log"
}
```

WebSocket closes with code `1000` (normal closure).

### Cleanup

In the `finally` block of the WebSocket handler:
```python
shutil.rmtree(session_dir, ignore_errors=True)
db.close()
```

All temp files for this session are deleted. Only the WORM file and the DB record remain.

---

## 4. Node 1 — Entry Routes (3 paths in)

### Manual (`POST /api/ingestion/manual`)
- No body required
- Extracts `request.client.host`
- Creates `IngestionSession(mode="manual")`
- Returns `session_id + ws_url`

### Cloud (`POST /api/ingestion/cloud`)
```json
{
  "oauth_token": "ya29.xxx",
  "cloud_provider": "gdrive"
}
```
- Validates token is non-empty (provider-specific validation is a future integration point)
- Creates `IngestionSession(mode="cloud")`
- Returns `session_id + ws_url + cloud_provider`

### Telemetry (`POST /api/ingestion/generate-telemetry-link`)
- For agentless victim/endpoint artefact collection
- Creates `IngestionSession(mode="telemetry")`
- Returns `ephemeral_token + ws_url + instructions`
- The instruction text tells the remote endpoint exactly how to stream data without installing software

---

## 5. Node 2 — JIT Authentication Gateway

**File:** `app/ingestion/auth_gateway.py`

### SessionStore class

Wraps all DB operations. Can be swapped for Redis without changing call-sites:

```python
store = SessionStore(db)
session = store.create(bound_ip="1.2.3.4", mode="manual")
session = store.get(session_id)
store.mark_used(session)
store.link_audit(session, audit_id)
```

### IP Extraction (proxy-aware)

```python
def _extract_client_ip(request):
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host
```

Works correctly behind NGINX / Cloudflare.

### The three rules (enforced in order)

```
RULE 1 — IP BINDING
  client_ip != session.bound_ip  →  PermissionError  →  WS close 4403

RULE 2 — TTL
  now_utc() > session.expires_at  →  PermissionError  →  WS close 4403/4408

RULE 3 — BURN ON USE
  session.used == True  →  PermissionError  →  WS close 4403
```

All three rules are checked **on every connection attempt**, including replays.  
A session that passes rules 1 and 2 but fails rule 3 is rejected — the attacker does not learn which rule failed.

---

## 6. Node 3 — WebSocket Chunk Streaming

**File:** `app/ingestion/ws_router.py`

### Protocol

| Direction | Message | When |
|-----------|---------|------|
| Client → Server | `{chunk_number, chunk_hash, data, is_final}` | Each chunk |
| Client → Server | `{type: "meta", filename: "..."}` | Optional, before chunks |
| Server → Client | `{status: "ok", chunk_number: N}` | Each valid chunk |
| Server → Client | `{status: "error", detail: "..."}` | Fatal error |
| Server → Client | `{status: "done", audit_id, merkle_root, sha256}` | Success |

### Guards

| Guard | Limit | Close code |
|-------|-------|-----------|
| Sequence | `chunk_number` must be exactly `expected` | `4400` |
| Size | `len(encoded_data) > 5MB × 4/3 + 4` | `4413` |
| Count | `chunk_number >= 10,000` | `4400` |
| Hash | `sha256(decoded) != chunk_hash` | `4422` |
| Framing | Binary WebSocket frame | `4415` |

### Why base64?

WebSocket text frames carry UTF-8. Raw binary log bytes may not be valid UTF-8.  
Base64 encodes arbitrary binary as ASCII-safe text.  
The `chunk_hash` is computed on the **raw bytes before encoding** so the server can verify the payload before decoding.

---

## 7. Node 4 — Merkle Tree Sealing

**File:** `app/core/merkle.py`

### Algorithm

Given chunk hashes `[h0, h1, h2, h3]`:

```
Layer 0 (leaves):   h0    h1    h2    h3
Layer 1:         sha256(h0+h1)  sha256(h2+h3)
Layer 2 (root):  sha256(sha256(h0+h1) + sha256(h2+h3))
```

For **odd** number of nodes, the last node is duplicated (Bitcoin-style padding):
```
Layer 0: h0  h1  h2
         → normalize → h0  h1  h2  h2
Layer 1: sha256(h0+h1)  sha256(h2+h2)
Layer 2: sha256(...)
```

For a **single chunk**: `len(layer) == 1`, the while loop `while len > 1` never runs, so root equals the leaf hash directly.

### What it proves

If you know the `merkle_root` stored in the DB and you have the original file:
1. Re-split into same chunk sizes
2. Recompute chunk hashes
3. Rebuild tree
4. Compare root → if different, **exactly which chunk was modified** can be isolated via Merkle proof

**`verify_merkle_proof(leaf, proof, root)`** allows single-chunk verification without the entire file.

---

## 8. Node 5 — Sandbox Triage (3 Filters)

**File:** `app/ingestion/sandbox.py`

### Filter 1 — ZIP Bomb Detection

```python
ZIP_BOMB_RATIO_THRESHOLD = 100.0

with zipfile.ZipFile(file_path) as z:
    compressed   = file_path.stat().st_size
    uncompressed = sum(info.file_size for info in z.infolist())
    ratio        = uncompressed / compressed
    if ratio > 100.0:  # BOMB
```

**Only runs if `zipfile.is_zipfile(path)` returns True.** Non-ZIP files skip this entirely.

### Filter 2 — Magic Byte Inspection

```python
MAGIC_SIGNATURES = {
    ".exe":  b"MZ",        # Windows PE
    ".dll":  b"MZ",
    ".elf":  b"\x7fELF",   # Linux ELF
    ".pdf":  b"%PDF",
    ".zip":  b"PK\x03\x04",
    ".png":  b"\x89PNG",
    ...
}
```

Rule: **non-executable extensions (`.txt`, `.log`, `.csv`)** must NOT start with `MZ` or `\x7fELF`.  
Read only the first 8 bytes — no full file scan needed.

### Filter 3 — Async Malware Scan

Runs as a background `asyncio.Task` after the WebSocket closes:

```python
asyncio.create_task(async_malware_scan(file_path=worm_path, ...))
```

Checks:
1. **Shannon entropy**: `H = -Σ p(b) × log2(p(b))` over all 256 byte values  
   → `H > 7.2` indicates encrypted payload or packer shell
2. **Extension blacklist**: `.exe .dll .bat .cmd .sh .ps1 .vbs .js .jar ...`
3. **YARA-style scan**: searches for known malicious strings:
   - `cmd.exe`, `powershell`, `WScript.Shell`
   - `eval(`, `exec(`, `system(`, `os.system`, `subprocess`
   - `CreateRemoteThread`, `VirtualAlloc` (Windows shellcode)
   - `\x90\x90\x90\x90` (NOP sled — shellcode indicator)

### Quarantine workflow (triggered by any filter)

```
1. sha256(file) computed
2. os.chmod(file, 0o400)         → read-only before move
3. shutil.move(file, quarantine/) → physically relocated
4. QuarantineLog record created  → full forensic trail
5. return quarantine_record      → pipeline aborts
6. NO AuditLog entry written     → tampered file never enters the evidence chain
```

`risk_score` values: ZIP bomb = 1.0, MZ/ELF magic = 0.9, async flags = 0.5–0.9

---

## 9. Node 6 — Ledger Commit + WORM Storage

**Files:** `app/ingestion/secure_ledger.py`, `app/ingestion/ws_router.py`

### Hash chain construction

Every new ledger entry includes the SHA-256 of the **previous** entry:

```python
previous_hash = db.query(AuditLog)
    .order_by(AuditLog.upload_time.desc())
    .first().sha256_hash
```

First record ever: `previous_hash = NULL` (genesis entry).  
Subsequent records: `previous_hash = sha256_of_previous_file`.

This creates an **append-only chain** where any historical modification breaks all subsequent records.

### WORM permission model

```python
os.chmod(dest, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
# = 0o444 = r--r--r--
```

| Permission | Owner | Group | Others |
|-----------|-------|-------|--------|
| Read      | ✓     | ✓     | ✓      |
| Write     | ✗     | ✗     | ✗      |
| Execute   | ✗     | ✗     | ✗      |

Any application code (or attacker with app-level access) attempting `open(worm_file, "wb")` gets `PermissionError`. The file cannot be silently replaced.

---

## 10. Legacy Ingestion (upload-log)

`POST /api/ingestion/upload-log` still works — backward-compatible.

Differences from secure pipeline:
- No JIT session required
- No WebSocket — file sent as multipart form
- Entire file read into RAM at once
- No Merkle tree (only SHA-256)
- No sandbox triage
- Still writes to AuditLog with `ingestion_mode="legacy"`
- No WORM storage

**Use this only for small files or backward compatibility. New integrations should use the WebSocket pipeline.**

---

## 11. Database Changes Explained

### `audit_logs` — 3 columns added

| Column | Why added |
|--------|-----------|
| `merkle_root` | Store the tamper-evident root after chunk-stream uploads |
| `source_ip` | Track which IP submitted the file (forensic attribution) |
| `ingestion_mode` | Know which entry point was used: `manual/cloud/telemetry/legacy` |

**Migration required for existing databases:**
```sql
ALTER TABLE audit_logs ADD COLUMN merkle_root VARCHAR;
ALTER TABLE audit_logs ADD COLUMN source_ip VARCHAR;
ALTER TABLE audit_logs ADD COLUMN ingestion_mode VARCHAR;
```
(These columns are `NULL` for legacy records — that is correct and expected.)

### `ingestion_sessions` — NEW table

Stores ephemeral JIT tokens. One row per issued token:
```sql
CREATE TABLE ingestion_sessions (
    id          INTEGER PRIMARY KEY,
    session_id  VARCHAR UNIQUE,    -- UUID v4 issued to client
    bound_ip    VARCHAR,           -- IP locked to this session
    expires_at  DATETIME,          -- creation + 30 min
    used        BOOLEAN,           -- True after first WS connection
    mode        VARCHAR,           -- manual / cloud / telemetry
    created_at  DATETIME,
    audit_id    VARCHAR            -- linked after pipeline completes
);
```

### `quarantine_logs` — NEW table

Full forensic record for every quarantined file:
```sql
CREATE TABLE quarantine_logs (
    id                 INTEGER PRIMARY KEY,
    original_filename  VARCHAR,
    quarantine_path    VARCHAR,    -- absolute path in data/quarantine/
    sha256_hash        VARCHAR,
    reason             VARCHAR,    -- zip_bomb / magic_byte / malware_scan
    risk_score         FLOAT,      -- 0.0–1.0
    details            TEXT,       -- JSON with exact detection details
    detected_at        DATETIME,
    source_ip          VARCHAR,
    ingestion_mode     VARCHAR,
    session_id         VARCHAR
);
```

---

## 12. What Every New File Does

| File | Role | Called by |
|------|------|-----------|
| `app/core/merkle.py` | Build/verify Merkle trees from chunk hash lists | `ws_router.py` |
| `app/ingestion/auth_gateway.py` | Create and validate JIT sessions | `router.py`, `ws_router.py` |
| `app/ingestion/ws_router.py` | WebSocket endpoint — orchestrates the full 9-step pipeline | `app/main.py` (registered) |
| `app/ingestion/sandbox.py` | ZIP bomb + magic byte + async malware triage | `ws_router.py` |
| `app/ingestion/secure_ledger.py` | Write chain-linked AuditLog entry after all checks pass | `ws_router.py` |
| `tests/conftest.py` | pytest fixtures: isolated DB, patched dirs, TestClient | All test modules |
| `tests/test_phase1_forensic.py` | 57 adversarial security tests covering all 8 guarantees | pytest |
| `pytest.ini` | `asyncio_mode=auto`, `testpaths=tests` | pytest |

---

## 13. Security Properties Guaranteed

| Property | Mechanism | Where |
|----------|-----------|-------|
| Only authorized IPs can upload | IP binding in session | `auth_gateway.py:_enforce_rules` |
| Sessions expire | 30-min TTL checked on every connection | `auth_gateway.py:_enforce_rules` |
| Session tokens are one-time-use | `mark_used()` called before any data flows | `ws_router.py` |
| Chunk-level integrity | SHA-256 verified before writing each chunk | `ws_router.py` |
| Full-file integrity | Monolithic SHA-256 after reconstruction | `ws_router.py:_compute_sha256_file` |
| Tamper-evidence at chunk level | Merkle root covers every chunk | `core/merkle.py` |
| Tamper-evidence across time | Hash chain links every audit entry | `secure_ledger.py` |
| No executable binaries stored | Magic byte + extension checks | `sandbox.py` |
| No zip bombs stored | Decompression ratio check | `sandbox.py` |
| No packed/encrypted malware | Entropy threshold check | `sandbox.py:async_malware_scan` |
| Committed files cannot be modified | WORM permissions (`0o444`) | `ws_router.py:_worm_store` |
| Quarantined files leave a trail | `QuarantineLog` DB record | `sandbox.py:_quarantine_file` |
| Clean evidence chain (no quarantined entries) | `commit_to_ledger` only called after sandbox passes | `ws_router.py` |

---

## 14. Failure Modes and What Happens

| What fails | When it happens | What the client sees | State left on server |
|-----------|----------------|---------------------|----------------------|
| Unknown session | WS connect | `{"status":"error","detail":"Session not found."}` + close `4001` | Nothing |
| Wrong IP | WS connect | close `4003` | Session unchanged |
| Expired session | WS connect | close `4003` (TTL error) | Session unchanged |
| Already-used session | WS connect | close `4403` | Session unchanged |
| Out-of-order chunk | Mid-stream | close `4400` | Partial temp dir deleted in `finally` |
| Oversized chunk | Mid-stream | close `4413` | Partial temp dir deleted |
| Hash mismatch | Mid-stream | close `4422` | Partial temp dir deleted |
| Binary frame | Mid-stream | close `4415` | Partial temp dir deleted |
| ZIP bomb detected | After last chunk | close `4010` + quarantine | `QuarantineLog` row, no `AuditLog`, temp deleted |
| Magic byte detected | After last chunk | close `4010` + quarantine | `QuarantineLog` row, no `AuditLog`, temp deleted |
| DB failure on ledger commit | After sandbox | close `4500` | DB rolled back, WORM file exists but no DB record |
| Unhandled exception | Any point | close `4500` | `finally` cleans temp dir |

---

## 15. Data at Rest — Directory Layout

```
data/
├── ledger.db            — SQLite: AuditLog, IngestionSession, QuarantineLog
├── analytics.duckdb     — DuckDB: columnar analytics queries
├── parquet/
│   └── audit_id=xxx/    — Parquet partition per audit record
├── raw/                 — Legacy upload-log files (unprotected)
├── temp/
│   └── {session_id}/    — IN-FLIGHT ONLY. Deleted immediately on finish.
│       ├── chunk_000000.bin
│       ├── chunk_000001.bin
│       └── (assembled file)
├── worm/
│   └── {filename}       — COMMITTED. Permissions: 0o444 (r--r--r--)
└── quarantine/
    └── {filename}       — FLAGGED. Permissions: 0o400 (r--------) before move.
                            QuarantineLog record links here.
```

**The invariants:**
- `data/temp/` should be empty when no uploads are in progress
- `data/worm/` files are never deleted by application code
- `data/quarantine/` files are never processed again (only inspected)
- `data/raw/` is only written by the legacy upload-log endpoint
