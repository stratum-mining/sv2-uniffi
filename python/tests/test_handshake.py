#!/usr/bin/env python3
"""
Handshake tests for sv2-uniffi.

Tests that verify the Noise_NX handshake process works correctly.
"""

import base58
import traceback

def test_handshake():
    """Test the handshake process."""
    try:
        from sv2 import Sv2CodecState, Sv2CodecError
        
        # Use actual Stratum v2 keys (base58 encoded)
        authority_pub_key_b58 = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
        authority_priv_key_b58 = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
        
        # Decode from base58 to bytes and extract 32-byte keys according to SV2 spec
        pub_key_full = base58.b58decode(authority_pub_key_b58)
        priv_key_full = base58.b58decode(authority_priv_key_b58)
        
        # Extract the 32-byte keys according to SV2 specification
        authority_pub_key = pub_key_full[2:34]   # Skip 2-byte version prefix
        authority_priv_key = priv_key_full[:32]  # First 32 bytes
        
        # Create initiator and responder
        initiator = Sv2CodecState.new_initiator(authority_pub_key)
        responder = Sv2CodecState.new_responder(
            authority_pub_key, 
            authority_priv_key, 
            86400  # 24 hours cert validity
        )
        
        # Perform complete handshake
        step_0_frame = initiator.step_0()
        step_1_frame = responder.step_1(step_0_frame)
        initiator.step_2(step_1_frame)
        
        print("✓ Handshake test passed")
        return True, initiator, responder
    except Exception as e:
        print(f"✗ Handshake test failed: {e}")
        traceback.print_exc()
        return False, None, None

if __name__ == "__main__":
    success, _, _ = test_handshake()
    exit(0 if success else 1) 