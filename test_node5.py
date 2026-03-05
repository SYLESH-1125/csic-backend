#!/usr/bin/env python3
"""
Test script for Node 5: Chronograph (Timestamp Sync)
Tests timestamp extraction, parsing, and normalization
"""

import sys
import os
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.phase2.utils.timestamp_parser import (
    extract_timestamp_from_line,
    parse_timestamp,
    normalize_timestamp,
    is_ambiguous_date,
    detect_timezone_offset
)
from app.phase2.node5_chronograph import (
    extract_timestamp,
    process_timestamp_sync
)


def test_timestamp_extraction():
    """Test timestamp extraction from log lines"""
    print("\n[1/5] Testing Timestamp Extraction from Log Lines")
    print("-" * 70)
    
    test_cases = [
        ("2024-01-15T10:30:00Z INFO User logged in", "2024-01-15T10:30:00Z"),
        ("2024-01-15 10:30:00 ERROR Connection failed", "2024-01-15 10:30:00"),
        ("15/Jan/2024:10:30:00 +0530 GET /api/users", "15/Jan/2024:10:30:00 +0530"),
        ("Jan 15 10:30:00 server sshd[1234]: Accepted", "Jan 15 10:30:00"),
        ("1705312200 INFO Process started", "1705312200"),
        ("Mon, 15 Jan 2024 10:30:00 GMT Request received", "Mon, 15 Jan 2024 10:30:00 GMT"),
        ("[2024-01-15 10:30:00.123] DEBUG Message", "[2024-01-15 10:30:00.123]"),
        ("No timestamp here just text", None),
    ]
    
    for log_line, expected in test_cases:
        extracted = extract_timestamp_from_line(log_line)
        status = "✓" if extracted == expected or (expected is None and extracted is None) else "✗"
        print(f"  {status} Line: {log_line[:50]}...")
        print(f"    Extracted: {extracted}")
        print(f"    Expected: {expected}")
        print()


def test_timestamp_parsing():
    """Test timestamp parsing from various formats"""
    print("\n[2/5] Testing Timestamp Parsing (Various Formats)")
    print("-" * 70)
    
    test_cases = [
        # ISO 8601 variants
        ("2024-01-15T10:30:00Z", True),
        ("2024-01-15 10:30:00+05:30", True),
        ("2024-01-15T10:30:00.123Z", True),
        # RFC 2822
        ("Mon, 15 Jan 2024 10:30:00 GMT", True),
        ("Mon, 15 Jan 2024 10:30:00 +0530", True),
        # Apache/Common Log
        ("15/Jan/2024:10:30:00 +0530", True),
        # Syslog
        ("Jan 15 10:30:00", True),
        # Unix timestamps
        ("1705312200", True),  # 10 digits
        ("1705312200000", True),  # 13 digits (milliseconds)
        # Windows Event Log
        ("2024-01-15 10:30:00", True),
        # Date only
        ("2024-01-15", True),
        # Invalid
        ("not a timestamp", False),
        ("", False),
    ]
    
    for timestamp_str, should_parse in test_cases:
        parsed = parse_timestamp(timestamp_str)
        status = "✓" if (parsed is not None) == should_parse else "✗"
        print(f"  {status} {timestamp_str}")
        if parsed:
            print(f"    → {parsed.isoformat()}")
        print()


def test_timezone_detection():
    """Test timezone offset detection"""
    print("\n[3/5] Testing Timezone Detection")
    print("-" * 70)
    
    test_cases = [
        ("2024-01-15T10:30:00+05:30", "+05:30"),
        ("2024-01-15T10:30:00-08:00", "-08:00"),
        ("2024-01-15T10:30:00Z", "UTC"),
        ("2024-01-15T10:30:00 GMT", "UTC"),
        ("15/Jan/2024:10:30:00 +0530", "+05:30"),
        ("2024-01-15T10:30:00", None),  # No timezone
    ]
    
    for timestamp_str, expected_tz in test_cases:
        detected = detect_timezone_offset(timestamp_str)
        if detected:
            tz_str = str(detected)
        else:
            tz_str = None
        
        status = "✓" if (tz_str is not None) == (expected_tz is not None) else "✗"
        print(f"  {status} {timestamp_str}")
        print(f"    Detected: {tz_str}")
        print(f"    Expected: {expected_tz}")
        print()


def test_ambiguous_dates():
    """Test ambiguous date detection and inference"""
    print("\n[4/5] Testing Ambiguous Date Handling")
    print("-" * 70)
    
    ambiguous_cases = [
        "05/04/2024",  # Could be May 4 or April 5
        "12/01/2024",  # Could be Dec 1 or Jan 12
        "01-02-2024",  # Could be Jan 2 or Feb 1
    ]
    
    non_ambiguous_cases = [
        "2024-01-15",  # ISO format, unambiguous
        "15/Jan/2024",  # Day/Month/Year with month name
        "Jan 15 2024",  # Month name, unambiguous
    ]
    
    print("  Ambiguous dates:")
    for date_str in ambiguous_cases:
        is_amb = is_ambiguous_date(date_str)
        print(f"    {'✓' if is_amb else '✗'} {date_str}: {is_amb}")
    
    print("\n  Non-ambiguous dates:")
    for date_str in non_ambiguous_cases:
        is_amb = is_ambiguous_date(date_str)
        print(f"    {'✓' if not is_amb else '✗'} {date_str}: {is_amb}")
    print()


def test_normalization():
    """Test full timestamp normalization"""
    print("\n[5/5] Testing Full Timestamp Normalization")
    print("-" * 70)
    
    test_cases = [
        {
            "input": "2024-01-15T10:30:00Z",
            "expected_format": "ISO-8601",
            "should_normalize": True
        },
        {
            "input": "15/Jan/2024:10:30:00 +0530",
            "expected_format": "Apache/Common Log",
            "should_normalize": True
        },
        {
            "input": "1705312200",
            "expected_format": "Unix timestamp",
            "should_normalize": True
        },
        {
            "input": "Jan 15 10:30:00",
            "expected_format": "Syslog (RFC-3164)",
            "should_normalize": True
        },
        {
            "input": "Mon, 15 Jan 2024 10:30:00 GMT",
            "expected_format": "RFC-2822",
            "should_normalize": True
        },
        {
            "input": "invalid timestamp",
            "expected_format": "unknown",
            "should_normalize": False
        },
    ]
    
    for case in test_cases:
        result = normalize_timestamp(case["input"])
        
        normalized = result.get("normalized") is not None
        format_detected = result.get("format_detected", "unknown")
        
        status = "✓" if normalized == case["should_normalize"] else "✗"
        format_match = "✓" if format_detected == case["expected_format"] else "✗"
        
        print(f"  {status} Input: {case['input']}")
        print(f"    Format: {format_detected} {format_match} (expected: {case['expected_format']})")
        if normalized:
            print(f"    Normalized: {result.get('normalized_iso')}")
        else:
            print(f"    Failed to normalize")
        print()


def test_extract_timestamp_function():
    """Test the extract_timestamp function with variables"""
    print("\n[6/5] Testing extract_timestamp with Variables")
    print("-" * 70)
    
    test_cases = [
        {
            "log_line": "2024-01-15T10:30:00Z INFO User logged in",
            "variables": None,
            "expected": "2024-01-15T10:30:00Z"
        },
        {
            "log_line": "Some log message without timestamp",
            "variables": {"timestamp": "2024-01-15T10:30:00Z"},
            "expected": "2024-01-15T10:30:00Z"  # From variables
        },
        {
            "log_line": "2024-01-15T10:30:00Z INFO Message",
            "variables": {"timestamp": "2024-01-15T11:00:00Z"},  # Variables take priority
            "expected": "2024-01-15T11:00:00Z"
        },
    ]
    
    for case in test_cases:
        extracted = extract_timestamp(case["log_line"], case["variables"])
        status = "✓" if extracted == case["expected"] else "✗"
        print(f"  {status} Line: {case['log_line'][:50]}...")
        print(f"    Variables: {case['variables']}")
        print(f"    Extracted: {extracted}")
        print(f"    Expected: {case['expected']}")
        print()


def main():
    """Run all tests"""
    print("=" * 70)
    print("Node 5: Chronograph (Timestamp Sync) - Test Suite")
    print("=" * 70)
    
    try:
        test_timestamp_extraction()
        test_timestamp_parsing()
        test_timezone_detection()
        test_ambiguous_dates()
        test_normalization()
        test_extract_timestamp_function()
        
        print("\n" + "=" * 70)
        print("All tests completed!")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()


