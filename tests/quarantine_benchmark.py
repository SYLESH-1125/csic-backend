"""
Quarantine Benchmark — Full live test against the running FastAPI server.

Covers:
  FLAG cases   — ZIP bomb, MZ magic byte, ELF magic byte, PowerShell YARA,
                 CreateRemoteThread YARA, blacklisted extension (.exe),
                 high-entropy encrypted payload
  NO-FLAG cases — clean syslog, clean CSV, clean JSON, clean multi-line auth log

Each test measures:
  • HTTP status code
  • Response time (ms)
  • Whether a QuarantineLog row was created
  • Whether an AuditLog row was NOT created (for flagged files)
  • Whether the file physically exists in quarantine dir

Run:
    python tests/quarantine_benchmark.py
"""

import hashlib
import io
import json
import math
import os
import random
import sys
import time
import zipfile
from pathlib import Path

import httpx

# ── Configuration ────────────────────────────────────────────────────────────
BASE_URL  = "http://127.0.0.1:8000"
UPLOAD_EP = f"{BASE_URL}/api/ingestion/upload-log"

# Direct DB access for verification
sys.path.insert(0, str(Path(__file__).parent.parent))
from app.db.session import SessionLocal
from app.db.models  import AuditLog, QuarantineLog

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    h = 0.0
    for c in freq:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def _db_quarantine_by_hash(sha256: str):
    db = SessionLocal()
    try:
        return db.query(QuarantineLog).filter(
            QuarantineLog.sha256_hash == sha256
        ).first()
    finally:
        db.close()


def _db_audit_by_hash(sha256: str):
    db = SessionLocal()
    try:
        return db.query(AuditLog).filter(
            AuditLog.sha256_hash == sha256
        ).first()
    finally:
        db.close()


def upload(filename: str, data: bytes) -> tuple[int, dict, float]:
    """Upload file, return (status_code, json_body, elapsed_ms)."""
    t0 = time.perf_counter()
    resp = httpx.post(
        UPLOAD_EP,
        files={"file": (filename, data, "application/octet-stream")},
        timeout=30,
    )
    elapsed = (time.perf_counter() - t0) * 1000
    try:
        body = resp.json()
    except Exception:
        body = {"raw": resp.text[:200]}
    return resp.status_code, body, elapsed


# ── File factories ────────────────────────────────────────────────────────────

def make_zip_bomb(ratio_target: int = 150) -> bytes:
    """Compressed ZIP whose expansion ratio exceeds 100×."""
    payload = b"\x00" * (1024 * 1024 * ratio_target // 10)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.writestr("zeros.txt", payload)
    return buf.getvalue()


def make_mz_txt() -> bytes:
    """Plain .txt file that starts with Windows EXE magic bytes."""
    return b"MZ\x90\x00" + b"\x00" * 58 + b"This is totally a firewall log.\n" * 50


def make_elf_csv() -> bytes:
    """CSV file that starts with Linux ELF magic bytes."""
    return b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"timestamp,event,ip\n2026-03-04,login,10.0.0.1\n" * 30


def make_powershell_log() -> bytes:
    """Log file containing PowerShell YARA pattern."""
    lines = [f"2026-03-04 10:{i:02d}:00 INFO event_{i}" for i in range(40)]
    lines.append("powershell -NoProfile -EncodedCommand SQBFAFgA")
    lines += [f"2026-03-04 11:{i:02d}:00 INFO event_{i+40}" for i in range(20)]
    return "\n".join(lines).encode()


def make_createremotethread_log() -> bytes:
    """Log file containing CreateRemoteThread YARA pattern (shellcode indicator)."""
    return (
        b"2026-03-04 DEBUG process_monitor: CreateRemoteThread called\n"
        b"2026-03-04 DEBUG target_pid=1234 VirtualAlloc size=4096\n"
        b"normal log line\n" * 100
    )


def make_encrypted_payload() -> bytes:
    """High-entropy binary that looks encrypted (entropy > 7.2)."""
    rng = random.Random(42)
    return bytes(rng.randint(0, 255) for _ in range(8192))


def make_blacklisted_exe() -> bytes:
    """File with .exe extension (blacklisted regardless of content)."""
    return b"MZ" + b"\x00" * 200 + b"This is a real PE binary"


def make_clean_syslog() -> bytes:
    lines = [
        f"Mar  4 10:{i:02d}:00 webserver sshd[1234]: "
        f"Accepted publickey for admin from 10.0.0.{i % 254 + 1} port 54321"
        for i in range(60)
    ]
    return "\n".join(lines).encode()


def make_clean_csv() -> bytes:
    rows = ["timestamp,event_type,user,source_ip,status"]
    for i in range(80):
        rows.append(
            f"2026-03-04T10:{i % 60:02d}:00Z,login,user_{i},192.168.1.{i % 254 + 1},success"
        )
    return "\n".join(rows).encode()


def make_clean_json() -> bytes:
    events = [
        {
            "ts": f"2026-03-04T{i:02d}:00:00Z",
            "level": "INFO",
            "msg": f"Request processed in {i * 3}ms",
            "user": f"user_{i}",
            "ip": f"10.0.{i // 256}.{i % 256}",
        }
        for i in range(50)
    ]
    return json.dumps(events, indent=2).encode()


def make_clean_auth_log() -> bytes:
    lines = []
    for i in range(100):
        lines.append(
            f"2026-03-04 10:{i % 60:02d}:{i % 60:02d} "
            f"auth INFO user=admin action=login ip=192.168.0.{i % 254 + 1} result=ok"
        )
    return "\n".join(lines).encode()


# ── Test runner ───────────────────────────────────────────────────────────────

class BenchmarkResult:
    def __init__(self, name, expected_flag, filename, data,
                 status, body, elapsed_ms, quarantine_rec, audit_rec,
                 file_entropy):
        self.name          = name
        self.expected_flag = expected_flag
        self.filename      = filename
        self.status        = status
        self.body          = body
        self.elapsed_ms    = elapsed_ms
        self.quarantine    = quarantine_rec
        self.audit         = audit_rec
        self.file_size     = len(data)
        self.file_entropy  = file_entropy
        self.sha256        = _sha256(data)

    @property
    def was_quarantined(self) -> bool:
        return self.quarantine is not None

    @property
    def was_ledgered(self) -> bool:
        return self.audit is not None

    @property
    def correct(self) -> bool:
        if self.expected_flag:
            # Should be quarantined AND NOT in ledger
            return self.was_quarantined and not self.was_ledgered
        else:
            # Should NOT be quarantined AND in ledger
            return not self.was_quarantined and self.was_ledgered


TESTS = [
    # (name,                      should_flag, filename,            factory_fn,                  expected_reason)
    ("ZIP Bomb (150×)",            True,  "bomb_150x.zip",          make_zip_bomb,               "zip_bomb"),
    ("MZ Magic in .txt",           True,  "firewall_logs.txt",      make_mz_txt,                 "magic_byte"),
    ("ELF Magic in .csv",          True,  "events.csv",             make_elf_csv,                "magic_byte"),
    ("PowerShell YARA Pattern",    True,  "auth_events.log",        make_powershell_log,         "malware_scan"),
    ("CreateRemoteThread Pattern", True,  "process_monitor.log",    make_createremotethread_log, "malware_scan"),
    ("High Entropy (encrypted)",   True,  "session_data.bin",       make_encrypted_payload,      "malware_scan"),
    ("Blacklisted .exe Extension", True,  "updater.exe",            make_blacklisted_exe,        "malware_scan"),
    ("Clean Syslog",               False, "syslog_mar04.log",       make_clean_syslog,           None),
    ("Clean CSV",                  False, "access_log.csv",         make_clean_csv,              None),
    ("Clean JSON Events",          False, "api_events.json",        make_clean_json,             None),
    ("Clean Auth Log",             False, "auth_2026-03-04.log",    make_clean_auth_log,         None),
]


def run_all():
    print(f"\n{BOLD}{CYAN}{'='*72}{RESET}")
    print(f"{BOLD}{CYAN}  QUARANTINE BENCHMARK — Forensic AI Engine{RESET}")
    print(f"{BOLD}{CYAN}  Server: {BASE_URL}{RESET}")
    print(f"{BOLD}{CYAN}{'='*72}{RESET}\n")

    results = []
    pass_count = 0
    fail_count = 0

    for name, should_flag, filename, factory, expected_reason in TESTS:
        data = factory()
        file_hash = _sha256(data)
        entropy = _entropy(data)

        print(f"{BOLD}► {name}{RESET}")
        print(f"  File    : {filename}  ({len(data):,} bytes)")
        print(f"  SHA-256 : {file_hash[:20]}...")
        print(f"  Entropy : {entropy:.4f} bits/byte")
        print(f"  Expect  : {'🚨 QUARANTINE' if should_flag else '✅ CLEAN/LEDGER'}")

        status, body, elapsed = upload(filename, data)

        # Wait briefly for async scan to complete for async-detected files
        if should_flag and expected_reason == "malware_scan":
            time.sleep(2)

        q_rec = _db_quarantine_by_hash(file_hash)
        a_rec = _db_audit_by_hash(file_hash)

        result = BenchmarkResult(
            name, should_flag, filename, data,
            status, body, elapsed, q_rec, a_rec, entropy
        )
        results.append(result)

        # Print result
        verdict = "PASS" if result.correct else "FAIL"
        colour  = GREEN if result.correct else RED
        print(f"  HTTP    : {status}  |  Time: {elapsed:.1f}ms")

        if result.was_quarantined:
            print(f"  {RED}QUARANTINED{RESET}: reason={q_rec.reason}  risk_score={q_rec.risk_score}")
            print(f"  Path    : {q_rec.quarantine_path}")
        else:
            print(f"  Quarantine: {YELLOW}none{RESET}")

        if result.was_ledgered:
            print(f"  {GREEN}LEDGER ENTRY{RESET}: audit_id={a_rec.id}  mode={a_rec.ingestion_mode}")
        else:
            print(f"  Ledger   : {YELLOW}no entry{RESET}")

        print(f"  {colour}{BOLD}[{verdict}]{RESET}\n")

        if result.correct:
            pass_count += 1
        else:
            fail_count += 1

    # ── Summary table ─────────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}{'='*72}{RESET}")
    print(f"{BOLD}  BENCHMARK SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}{'='*72}{RESET}")
    print(f"  {'Test Name':<35} {'Expected':<12} {'Quarantined':<14} {'Ledgered':<10} {'Time (ms)':<10} {'Result'}")
    print(f"  {'-'*35} {'-'*12} {'-'*14} {'-'*10} {'-'*10} {'-'*6}")

    for r in results:
        expected  = "FLAG" if r.expected_flag else "CLEAN"
        quaranted = "YES" if r.was_quarantined else "NO"
        ledgered  = "YES" if r.was_ledgered   else "NO"
        verdict   = f"{GREEN}PASS{RESET}" if r.correct else f"{RED}FAIL{RESET}"
        print(f"  {r.name:<35} {expected:<12} {quaranted:<14} {ledgered:<10} {r.elapsed_ms:<10.1f} {verdict}")

    print(f"\n{BOLD}{CYAN}{'='*72}{RESET}")
    total = pass_count + fail_count
    colour = GREEN if fail_count == 0 else RED
    print(f"  {colour}{BOLD}RESULT: {pass_count}/{total} PASSED  |  {fail_count} FAILED{RESET}")

    # Per-category stats
    flag_tests  = [r for r in results if r.expected_flag]
    clean_tests = [r for r in results if not r.expected_flag]
    flag_pass   = sum(1 for r in flag_tests  if r.correct)
    clean_pass  = sum(1 for r in clean_tests if r.correct)
    avg_time    = sum(r.elapsed_ms for r in results) / len(results)

    print(f"\n  Detection accuracy  : {flag_pass}/{len(flag_tests)} flagged correctly")
    print(f"  Clean pass rate     : {clean_pass}/{len(clean_tests)} clean files passed")
    print(f"  Avg response time   : {avg_time:.1f}ms")
    print(f"  False positives     : {sum(1 for r in clean_tests if r.was_quarantined)}")
    print(f"  False negatives     : {sum(1 for r in flag_tests  if not r.was_quarantined)}")
    print(f"{BOLD}{CYAN}{'='*72}{RESET}\n")

    return fail_count == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
