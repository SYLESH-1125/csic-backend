#!/usr/bin/env python3
"""Test Node 3: DRAIN3 Template Extraction"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from app.db.session import SessionLocal
from app.phase2.node3_drain3 import (
    process_drain3,
    extract_template_simple,
    get_or_create_template,
    create_cache_key
)


def test_node3():
    """Test Node 3 DRAIN3 template extraction."""
    print("=" * 70)
    print("Node 3: Universal Translator (DRAIN3) - Test")
    print("=" * 70)
    
    db = SessionLocal()
    
    try:
        # Test cases
        test_cases = [
            {
                "name": "Simple log with timestamp and IP",
                "log": "2024-01-01 10:00:00 INFO User admin logged in from 192.168.1.100",
                "expected_template_contains": ["<timestamp>", "<ip>"]
            },
            {
                "name": "Error log with port number",
                "log": "2024-01-01 10:00:15 ERROR Connection failed to 10.0.0.50:8080 after 3 retries",
                "expected_template_contains": ["<timestamp>", "<ip>", "<num>"]
            },
            {
                "name": "Log with UUID",
                "log": "2024-01-01 10:00:30 INFO Session 550e8400-e29b-41d4-a716-446655440000 created",
                "expected_template_contains": ["<timestamp>", "<uuid>"]
            },
            {
                "name": "Date format log",
                "log": "01/15/2024 10:00:45 WARN Failed login attempt from 10.0.0.50",
                "expected_template_contains": ["<date>", "<ip>"]
            },
            {
                "name": "Multiple numbers",
                "log": "2024-01-01 10:01:00 INFO Process 12345 completed in 42 seconds",
                "expected_template_contains": ["<timestamp>", "<num>"]
            }
        ]
        
        print("\n[1/3] Testing Template Extraction")
        print("-" * 70)
        
        for i, test in enumerate(test_cases, 1):
            print(f"\nTest {i}: {test['name']}")
            print(f"  Input: {test['log']}")
            
            template, variables = extract_template_simple(test['log'])
            print(f"  Template: {template}")
            print(f"  Variables: {variables}")
            
            # Check expected patterns
            all_found = all(pattern in template for pattern in test['expected_template_contains'])
            if all_found:
                print(f"  ✓ All expected patterns found")
            else:
                print(f"  ⚠ Some patterns missing")
        
        print("\n[2/3] Testing Cache Key Generation")
        print("-" * 70)
        
        test_log = "2024-01-01 10:00:00 INFO Test log"
        cache_key1 = create_cache_key(test_log)
        cache_key2 = create_cache_key(test_log)
        
        print(f"  Log: {test_log}")
        print(f"  Cache key 1: {cache_key1}")
        print(f"  Cache key 2: {cache_key2}")
        
        if cache_key1 == cache_key2:
            print(f"  ✓ Cache keys are consistent")
        else:
            print(f"  ✗ Cache keys differ!")
        
        print("\n[3/3] Testing Full Pipeline (with Database)")
        print("-" * 70)
        
        for i, test in enumerate(test_cases[:3], 1):  # Test first 3
            print(f"\nTest {i}: {test['name']}")
            print(f"  Input: {test['log']}")
            
            # First call (cache miss)
            result1 = process_drain3(db, test['log'], audit_id="test-audit-123")
            print(f"  Template: {result1['template']}")
            print(f"  Variables: {result1['variables']}")
            print(f"  Cache hit: {result1['cache_hit']}")
            print(f"  Template ID: {result1['template_id']}")
            
            # Second call (cache hit)
            result2 = process_drain3(db, test['log'], audit_id="test-audit-123")
            print(f"  Cache hit: {result2['cache_hit']}")
            
            if result1['template_id'] == result2['template_id']:
                print(f"  ✓ Template ID matches (cache working)")
            else:
                print(f"  ✗ Template IDs differ!")
        
        print("\n" + "=" * 70)
        print("✓ Node 3 tests completed")
        print("=" * 70)
        
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        db.close()


if __name__ == "__main__":
    success = test_node3()
    sys.exit(0 if success else 1)


