#!/usr/bin/env python3
"""
Message creation tests for sv2-uniffi.

Tests that verify message creation and wrapping functionality.
"""

import traceback

def test_message_creation():
    """Test message creation and wrapping."""
    try:
        from sv2 import Sv2Message, SetupConnection
        
        # Create a SetupConnection message
        setup_msg = SetupConnection(
            protocol=1,
            min_version=2,
            max_version=2,
            flags=0,
            endpoint_host="test.example.com",
            endpoint_port=4444,
            vendor="Test Miner",
            hardware_version="v1.0",
            firmware="test-1.0.0",
            device_id="test-device"
        )
        
        # Wrap in Sv2Message enum
        sv2_message = Sv2Message.SETUP_CONNECTION(setup_msg)
        
        print("✓ Message creation test passed")
        return True, sv2_message
    except Exception as e:
        print(f"✗ Message creation test failed: {e}")
        traceback.print_exc()
        return False, None

if __name__ == "__main__":
    success, _ = test_message_creation()
    exit(0 if success else 1) 