#!/usr/bin/env python3
"""
Stratum v2 FFI Example

This example demonstrates how to use the sv2-uniffi library to:
1. Set up a handshake between initiator and responder
2. Create and encode/decode messages
3. Handle errors gracefully

The library provides a Python interface to the Rust-based Stratum v2 implementation.
"""

import base58
import secrets
from typing import Optional

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
    print("✓ Successfully imported sv2 FFI bindings")
except ImportError as e:
    print(f"✗ Failed to import sv2 FFI bindings: {e}")
    print("Make sure you have built the library with: cargo build --release")
    exit(1)


def get_test_keypair() -> tuple[bytes, bytes]:
    """Get a test keypair from the Stratum v2 configuration."""
    # Use actual Stratum v2 keys (base58 encoded)
    authority_pub_key_b58 = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
    authority_priv_key_b58 = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
    
    # Decode from base58 to bytes and extract 32-byte keys according to SV2 spec
    pub_key_full = base58.b58decode(authority_pub_key_b58)
    priv_key_full = base58.b58decode(authority_priv_key_b58)
    
    # Extract the 32-byte keys according to SV2 specification
    authority_pub_key = pub_key_full[2:34]   # Skip 2-byte version prefix
    authority_priv_key = priv_key_full[:32]  # First 32 bytes
    
    return authority_pub_key, authority_priv_key


def demonstrate_handshake():
    """Demonstrate the complete 3-step handshake process between initiator and responder."""
    print("\n=== Handshake Demonstration ===")
    
    try:
        # Get test authority keypair
        authority_pub_key, authority_priv_key = get_test_keypair()
        print(f"✓ Got test authority keypair")
        print(f"  Public key: {authority_pub_key.hex()[:16]}...")
        print(f"  Private key: {authority_priv_key.hex()[:16]}...")
        
        # Create initiator (client side)
        initiator = Sv2CodecState.new_initiator(authority_pub_key)
        print("✓ Created initiator")
        
        # Create responder (server side)  
        cert_validity_secs = 86400  # 24 hours
        responder = Sv2CodecState.new_responder(
            authority_pub_key, 
            authority_priv_key, 
            cert_validity_secs
        )
        print("✓ Created responder")
        
        print("\n--- Handshake Process ---")
        print("Following the Noise_NX protocol as specified in SV2...")
        
        # Step 0: Initiator creates first handshake frame
        print("\n--- Step 0: Initiator handshake (-> e) ---")
        step_0_frame = initiator.step_0()
        print(f"✓ Initiator step 0 completed, frame size: {len(step_0_frame)} bytes")
        print(f"  Ephemeral public key sent: {step_0_frame.hex()[:32]}...")
        
        # Step 1: Responder processes initiator frame and creates response
        print("\n--- Step 1: Responder handshake (<- e, ee, s, es, SIGNATURE_NOISE_MESSAGE) ---")
        step_1_frame = responder.step_1(step_0_frame)
        print(f"✓ Responder step 1 completed, frame size: {len(step_1_frame)} bytes")
        print(f"  Response includes: ephemeral key + encrypted static key + signature")
        
        # Step 2: Initiator processes responder frame and completes handshake
        print("\n--- Step 2: Initiator finalizes handshake ---")
        initiator.step_2(step_1_frame)
        print("✓ Initiator step 2 completed")
        
        print("\n✓ Complete handshake successful!")
        print("  Encrypted communication channel established")
        print("  Both parties now have shared encryption keys")
        
        return initiator, responder
        
    except Sv2CodecError as e:
        print(f"✗ Handshake failed with codec error: {e}")
        return None, None
    except Exception as e:
        print(f"✗ Handshake failed with unexpected error: {e}")
        return None, None


def demonstrate_message_creation():
    """Demonstrate creating different types of Stratum v2 messages."""
    print("\n=== Message Creation Demonstration ===")
    
    try:
        # Create a SetupConnection message
        setup_msg = SetupConnection(
            protocol=1,           # Mining protocol
            min_version=2,        # Minimum protocol version  
            max_version=2,        # Maximum protocol version
            flags=0,              # Protocol flags
            endpoint_host="stratum.example.com",
            endpoint_port=4444,
            vendor="Example Miner",
            hardware_version="v1.0",
            firmware="fw-1.2.3",
            device_id="device-12345"
        )
        print("✓ Created SetupConnection message")
        print(f"  - Protocol: {setup_msg.protocol}")
        print(f"  - Version range: {setup_msg.min_version}-{setup_msg.max_version}")
        print(f"  - Endpoint: {setup_msg.endpoint_host}:{setup_msg.endpoint_port}")
        print(f"  - Device: {setup_msg.vendor} {setup_msg.hardware_version}")
        
        # Wrap in Sv2Message enum
        sv2_message = Sv2Message.SETUP_CONNECTION(setup_msg)
        print("✓ Wrapped in Sv2Message enum")
        
        return sv2_message
        
    except Sv2MessagesError as e:
        print(f"✗ Message creation failed: {e}")
        return None
    except Exception as e:
        print(f"✗ Unexpected error in message creation: {e}")
        return None


def demonstrate_encoding_decoding(initiator: Optional[Sv2CodecState], message: Optional[Sv2Message]):
    """Demonstrate encoding and decoding messages."""
    print("\n=== Encoding/Decoding Demonstration ===")
    
    if not initiator or not message:
        print("✗ Skipping encoding/decoding - missing prerequisites")
        return
    
    print("⚠ Note: Message encoding/decoding requires a completed handshake")
    print("  The codec state must be in Transport mode after handshake completion")
    print("  For this demonstration, we'll show the encoder/decoder creation:")
    
    try:
        # Create encoder and decoder
        encoder = Sv2Encoder()
        decoder = Sv2Decoder()
        print("✓ Created encoder and decoder")
        
        # Note about encoding requirements
        print("\n--- Encoding Requirements ---")
        print("1. Completed handshake (codec state in Transport mode)")
        print("2. Valid Sv2Message object")
        print("3. Proper message serialization")
        
        print("\n--- Message Information ---")
        print(f"✓ Message type: {type(message).__name__}")
        if message.is_SETUP_CONNECTION():
            # Access the SetupConnection message content
            try:
                setup_msg = message.SETUP_CONNECTION
                # Handle both tuple and direct access patterns
                if hasattr(setup_msg, '__getitem__') and hasattr(setup_msg, '__len__'):
                    setup_connection = setup_msg[0]
                else:
                    setup_connection = setup_msg
                print(f"  - Protocol: {setup_connection.protocol}")
                print(f"  - Endpoint: {setup_connection.endpoint_host}:{setup_connection.endpoint_port}")
                print(f"  - Vendor: {setup_connection.vendor}")
            except Exception as e:
                print(f"  ⚠ Could not access message details: {e}")
                print("  Message structure may vary - this is normal")
        
        print("\n--- Encoding Process (Conceptual) ---")
        print("1. Serialize message to bytes")
        print("2. Encrypt using transport state")
        print("3. Frame with appropriate headers")
        print("4. Return encoded frame for transmission")
        
        # Try encoding (this may fail without completed handshake)
        print("\n--- Attempting Encoding ---")
        try:
            encoded_frame = encoder.encode(message, initiator)
            print(f"✓ Message encoded successfully")
            print(f"  - Encoded frame size: {len(encoded_frame)} bytes")
            print(f"  - First 32 bytes: {encoded_frame[:32].hex()}")
            
            # Try decoding
            decoded_message = decoder.decode(encoded_frame, initiator)
            print(f"✓ Frame decoded successfully")
            
            return encoded_frame, decoded_message
            
        except Sv2CodecError as e:
            print(f"⚠ Encoding failed (expected): {e}")
            print("  This is normal - encoding requires a completed handshake")
            return None, None
        
    except Exception as e:
        print(f"✗ Encoding/decoding setup failed: {e}")
        return None, None


def demonstrate_error_handling():
    """Demonstrate various error scenarios and how to handle them."""
    print("\n=== Error Handling Demonstration ===")
    
    # Test invalid key size
    print("\n--- Testing Invalid Key Size ---")
    try:
        invalid_key = b"too_short"  # Keys should be 32 bytes
        Sv2CodecState.new_initiator(invalid_key)
        print("✗ Should have failed with invalid key size")
    except Sv2CodecError as e:
        print(f"✓ Correctly caught invalid key error: {e}")
    
    # Test invalid frame data
    print("\n--- Testing Invalid Frame Data ---")
    try:
        valid_key = secrets.token_bytes(32)
        initiator = Sv2CodecState.new_initiator(valid_key)
        
        # Try to decode invalid frame data
        decoder = Sv2Decoder()
        invalid_frame = b"invalid_frame_data"
        decoder.decode(invalid_frame, initiator)
        print("✗ Should have failed with invalid frame data")
    except Sv2CodecError as e:
        print(f"✓ Correctly caught invalid frame error: {e}")
    except Exception as e:
        print(f"✓ Correctly caught error: {e}")
    
    # Test invalid message parameters
    print("\n--- Testing Invalid Message Parameters ---")
    try:
        # Create message with invalid parameters
        invalid_msg = SetupConnection(
            protocol=999,  # Invalid protocol
            min_version=2,
            max_version=2,
            flags=0,
            endpoint_host="",  # Empty host
            endpoint_port=0,   # Invalid port
            vendor="",
            hardware_version="",
            firmware="",
            device_id=""
        )
        print("⚠ Message created with questionable parameters (validation may be minimal)")
    except Exception as e:
        print(f"✓ Correctly caught invalid message error: {e}")


def main():
    """Main demonstration function."""
    print("Stratum v2 FFI Example")
    print("=" * 50)
    
    # Demonstrate handshake
    initiator, responder = demonstrate_handshake()
    
    # Demonstrate message creation
    message = demonstrate_message_creation()
    
    # Demonstrate encoding/decoding
    encoded_frame, decoded_message = demonstrate_encoding_decoding(initiator, message)
    
    # Demonstrate error handling
    demonstrate_error_handling()
    
    print("\n" + "=" * 50)
    print("Example completed!")
    print("\nNext steps:")
    print("1. Integrate this into your application")
    print("2. Handle network communication")
    print("3. Implement proper key management")
    print("4. Add logging and monitoring")
    print("5. Handle connection lifecycle")


if __name__ == "__main__":
    main() 