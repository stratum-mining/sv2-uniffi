#!/usr/bin/env python3
"""
Error handling tests for sv2-uniffi.

Tests that verify proper error handling and exception raising.
"""

import traceback

def test_error_handling():
    """Test error handling."""
    try:
        from sv2 import Sv2CodecState, Sv2CodecError
        
        # Test invalid key size
        try:
            invalid_key = b"too_short"
            Sv2CodecState.new_initiator(invalid_key)
            print("✗ Error handling test failed - should have thrown exception")
            return False
        except Sv2CodecError:
            # Expected error
            pass
        
        # Note: Random 32-byte keys may or may not fail depending on the cryptographic implementation
        # so we don't test that case to avoid flaky tests
        
        print("✓ Error handling test passed")
        return True
    except Exception as e:
        print(f"✗ Error handling test failed: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_error_handling()
    exit(0 if success else 1) 