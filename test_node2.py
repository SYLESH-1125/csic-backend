#!/usr/bin/env python3
"""Test Node 2: Recursive De-obfuscation"""

from app.phase2.node2_deobfuscation import process_deobfuscation
from app.phase2.utils.entropy import calculate_shannon_entropy, is_high_entropy


def test_node2():
    """Test Node 2 de-obfuscation."""
    print("=" * 70)
    print("Node 2: Recursive De-obfuscation Test")
    print("=" * 70)
    
    # Test cases
    test_cases = [
        {
            "name": "Normal text (low entropy)",
            "data": "2024-01-01 10:00:00 INFO User logged in from 192.168.1.1",
            "expected_obfuscated": False
        },
        {
            "name": "Base64 encoded (high entropy)",
            "data": "SGVsbG8gV29ybGQ=",  # "Hello World" in Base64
            "expected_obfuscated": True
        },
        {
            "name": "URL encoded",
            "data": "Hello%20World%21",
            "expected_obfuscated": True
        },
        {
            "name": "Hex encoded",
            "data": "48656c6c6f20576f726c64",  # "Hello World" in hex
            "expected_obfuscated": True
        },
        {
            "name": "Empty string",
            "data": "",
            "expected_obfuscated": False
        }
    ]
    
    print("\n[Testing De-obfuscation]")
    print("-" * 70)
    
    for i, test in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test['name']}")
        print(f"  Input: {test['data'][:50]}...")
        
        # Calculate entropy
        entropy = calculate_shannon_entropy(test['data'])
        print(f"  Entropy: {entropy:.2f} bits/byte")
        
        # Process through Node 2
        result = process_deobfuscation(test['data'])
        
        print(f"  Is obfuscated: {result['is_obfuscated']}")
        print(f"  Decoded: {result.get('decoded', 'None')}")
        print(f"  Depth: {result.get('depth', 0)}")
        print(f"  Trace steps: {len(result.get('trace', []))}")
        
        if result.get('decoded'):
            print(f"  ✓ Decoding successful: {result['decoded'][:50]}...")
        else:
            print(f"  - No decoding needed or failed")
        
        # Verify expectation
        if result['is_obfuscated'] == test['expected_obfuscated']:
            print(f"  ✓ Expected result")
        else:
            print(f"  ⚠ Unexpected result")
    
    print("\n" + "=" * 70)
    print("✓ Node 2 tests completed")
    print("=" * 70)


if __name__ == "__main__":
    test_node2()


