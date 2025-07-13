#!/usr/bin/env python3
"""
Import tests for sv2-uniffi.

Tests that verify the sv2 module and its components can be imported successfully.
"""

def test_import():
    """Test that we can import the sv2 module successfully."""
    try:
        from sv2 import (
            Sv2CodecState, 
            Sv2Encoder, 
            Sv2Decoder, 
            Sv2Message, 
            SetupConnection,
            Sv2CodecError,
            Sv2MessageError
        )
        print("✓ Import test passed")
        return True
    except ImportError as e:
        print(f"✗ Import test failed: {e}")
        print("Make sure you have built the library with: cargo build --release")
        return False

if __name__ == "__main__":
    success = test_import()
    exit(0 if success else 1) 