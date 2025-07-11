#!/usr/bin/env python3
"""
Test runner for sv2-uniffi.

Runs all tests and provides a summary of results.
"""

from test_import import test_import
from test_handshake import test_handshake
from test_message_creation import test_message_creation
from test_encoding_decoding import test_encoding_decoding
from test_error_handling import test_error_handling
from test_extended_channel_server import test_extended_channel_server

def run_all_tests():
    """Run all tests and report results."""
    print("Running sv2-uniffi Tests")
    print("=" * 40)
    
    results = []
    
    # Test 1: Import
    print("\n1. Import Test:")
    results.append(test_import())
    
    # Test 2: Handshake
    print("\n2. Handshake Test:")
    handshake_success, initiator, responder = test_handshake()
    results.append(handshake_success)
    
    # Test 3: Message creation
    print("\n3. Message Creation Test:")
    message_success, message = test_message_creation()
    results.append(message_success)
    
    # Test 4: Encoding/decoding (depends on previous tests)
    print("\n4. Encoding/Decoding Test:")
    results.append(test_encoding_decoding(initiator, responder, message))
    
    # Test 5: Error handling
    print("\n5. Error Handling Test:")
    results.append(test_error_handling())
    
    # Test 6: Extended channel server
    print("\n6. Extended Channel Server Test:")
    results.append(test_extended_channel_server())
    
    # Summary
    print("\n" + "=" * 40)
    passed = sum(results)
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed!")
        return True
    else:
        print("✗ Some tests failed!")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1) 