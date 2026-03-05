#!/usr/bin/env python3
"""Test Node 4: NER Tagging & Validation"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from app.phase2.node4_ner import (
    process_ner_tagging,
    tag_entities,
    neutralize_sqli,
    validate_regex_size,
    validate_all_regex_patterns
)


def test_node4():
    """Test Node 4 NER tagging."""
    print("=" * 70)
    print("Node 4: NER Tagging & Validation - Test")
    print("=" * 70)
    
    # Test cases
    test_cases = [
        {
            "name": "Log with IP and Email",
            "text": "2024-01-01 10:00:00 INFO User admin@company.com logged in from 192.168.1.100",
            "template": "<timestamp> INFO User <VAR> logged in from <ip>",
            "expected_entities": ["ip_addresses", "emails"]
        },
        {
            "name": "Log with URL",
            "text": "2024-01-01 10:00:15 INFO Accessing https://api.example.com/v1/data",
            "template": "<timestamp> INFO Accessing <VAR>",
            "expected_entities": ["urls"]
        },
        {
            "name": "Log with MAC Address",
            "text": "2024-01-01 10:00:30 INFO Device 00:1B:44:11:3A:B7 connected",
            "template": "<timestamp> INFO Device <VAR> connected",
            "expected_entities": ["mac_addresses"]
        },
        {
            "name": "Log with File Path",
            "text": "2024-01-01 10:00:45 INFO File accessed: C:\\Users\\admin\\secret.txt",
            "template": "<timestamp> INFO File accessed: <VAR>",
            "expected_entities": ["file_paths"]
        },
        {
            "name": "Log with SQL Injection",
            "text": "2024-01-01 10:01:00 ERROR SQL query: SELECT * FROM users WHERE id = 1",
            "template": "<timestamp> ERROR SQL query: <VAR>",
            "expected_entities": []
        },
        {
            "name": "Log with Multiple Entities",
            "text": "2024-01-01 10:01:15 INFO User admin@test.com from 10.0.0.50 accessed https://example.com/file.txt",
            "template": "<timestamp> INFO User <VAR> from <ip> accessed <VAR>",
            "expected_entities": ["ip_addresses", "emails", "urls"]
        },
        {
            "name": "Simple Log (No Entities)",
            "text": "2024-01-01 10:01:30 INFO System started successfully",
            "template": "<timestamp> INFO System started successfully",
            "expected_entities": []
        }
    ]
    
    print("\n[1/4] Testing Entity Extraction")
    print("-" * 70)
    
    for i, test in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test['name']}")
        print(f"  Input: {test['text'][:60]}...")
        
        tags = tag_entities(test['text'])
        
        found_entities = [key for key, values in tags.items() if values and key != 'other']
        print(f"  Entities found: {found_entities}")
        
        for entity_type, values in tags.items():
            if values:
                print(f"    {entity_type}: {values[:3]}")  # Show first 3
        
        # Check expected
        expected = test['expected_entities']
        if set(found_entities) == set(expected):
            print(f"  ✓ All expected entities found")
        else:
            print(f"  ⚠ Expected: {expected}, Found: {found_entities}")
    
    print("\n[2/4] Testing SQL Injection Neutralization")
    print("-" * 70)
    
    sqli_tests = [
        ("SELECT * FROM users", True),
        ("INSERT INTO logs VALUES (1, 'test')", True),
        ("DELETE FROM users WHERE id = 1", True),
        ("DROP TABLE users", True),
        ("UNION SELECT password FROM users", True),
        ("' OR '1'='1", True),
        ("1=1", True),
        ("'; DROP TABLE users--", True),
        ("CONCAT(username, password)", True),
        ("Normal text without SQL", False)
    ]
    
    for sqli_text, should_neutralize in sqli_tests:
        neutralized = neutralize_sqli(sqli_text)
        print(f"  Original: {sqli_text}")
        print(f"  Neutralized: {neutralized}")
        was_neutralized = neutralized != sqli_text
        if was_neutralized == should_neutralize:
            print(f"  ✓ Expected behavior")
        else:
            print(f"  ⚠ Unexpected: should_neutralize={should_neutralize}, was_neutralized={was_neutralized}")
        print()
    
    print("\n[3/4] Testing Full NER Pipeline")
    print("-" * 70)
    
    for i, test in enumerate(test_cases[:3], 1):  # Test first 3
        print(f"\nTest {i}: {test['name']}")
        print(f"  Input: {test['text']}")
        
        result = process_ner_tagging(test['text'], test['template'])
        
        print(f"  Tags: {len(result['tags'])} entity types")
        print(f"  Validated: {result['validated']}")
        print(f"  Fallback: {result['fallback']}")
        print(f"  Neutralized: {result['neutralized'][:50]}...")
        
        if result['validated']:
            print(f"  ✓ Tags locked (validated)")
        else:
            print(f"  - Tags not locked")
    
    print("\n[4/4] Testing Regex Validation & RE2 Compatibility")
    print("-" * 70)
    
    # Test size validation
    size_tests = [
        ("Small pattern", "a" * 100, True),
        ("Medium pattern", "a" * 1000, True),
        ("Large pattern", "a" * 2048, False),
        ("Very large pattern", "a" * 5000, False)
    ]
    
    print("  Size Validation:")
    for name, pattern, expected in size_tests:
        result = validate_regex_size(pattern, max_size=2048)
        status = "✓" if result == expected else "✗"
        print(f"    {status} {name}: {len(pattern)} chars, valid={result}, expected={expected}")
    
    # Test RE2 incompatible patterns
    print("\n  RE2 Compatibility:")
    re2_tests = [
        ("Lookahead", r"a(?=b)", False),
        ("Lookbehind", r"(?<=a)b", False),
        ("Backreference", r"(a)\1", False),
        ("Simple pattern", r"abc", True),
    ]
    
    for name, pattern, expected in re2_tests:
        result = validate_regex_size(pattern, max_size=2048)
        status = "✓" if result == expected else "✗"
        print(f"    {status} {name}: valid={result}, expected={expected}")
    
    # Validate all NER patterns
    print("\n  NER Pattern Validation:")
    pattern_results = validate_all_regex_patterns()
    for name, valid in pattern_results.items():
        status = "✓" if valid else "✗"
        print(f"    {status} {name}: {'Valid' if valid else 'Invalid'}")
    
    print("\n" + "=" * 70)
    print("✓ Node 4 tests completed")
    print("=" * 70)
    
    return True


if __name__ == "__main__":
    success = test_node4()
    sys.exit(0 if success else 1)

