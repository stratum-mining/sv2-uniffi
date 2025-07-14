#!/usr/bin/env python3
"""
Encoding/decoding tests for sv2-uniffi.

Tests that verify message encoding and decoding functionality.
"""

import traceback

def test_encoding_decoding(initiator, responder, message):
    """Test message encoding and decoding by simulating TCP stream."""
    try:
        from sv2 import Sv2Encoder, Sv2Decoder, Sv2CodecError
        
        if not initiator or not responder or not message:
            print("✗ Skipping encoding/decoding test - missing prerequisites")
            return False
        
        # Create encoder and decoder
        encoder = Sv2Encoder()
        decoder = Sv2Decoder()
        
        # Attempt encoding (may fail if handshake state not in transport mode)
        try:
            encoded_frame = encoder.encode(message, initiator)
            
            # If encoding succeeds, simulate TCP stream by gradually feeding data to decoder
            if len(encoded_frame) == 0:
                print("✗ Encoding produced empty frame")
                return False
            
            # Create a buffer that simulates receiving data over TCP
            stream_buffer = encoded_frame
            buffer_offset = 0
            
            # Use the decoder's proper pattern: buffer_size() -> recv(size) -> try_decode()
            decoded_message = None
            max_iterations = 10  # Prevent infinite loops
            iteration = 0
            
            while decoded_message is None and iteration < max_iterations:
                iteration += 1
                
                # Get the size of buffer that needs to be filled
                buffer_size = decoder.buffer_size()
                
                if buffer_size > 0:
                    # Check if we have enough data in our simulated stream
                    if buffer_offset + buffer_size <= len(stream_buffer):
                        # Extract the needed amount of data from our simulated stream
                        chunk = stream_buffer[buffer_offset:buffer_offset + buffer_size]
                        buffer_offset += buffer_size
                        
                        # Try to decode with this chunk using responder state
                        try:
                            decoded_message = decoder.try_decode(chunk, responder)
                            break  # Successfully decoded
                            
                        except Exception as e:
                            # Check if it's a MissingBytes error
                            error_type = type(e).__name__
                            
                            if "MissingBytes" in error_type:
                                # Decoder needs more data, continue loop
                                continue
                            else:
                                # Other error, fail the test
                                print(f"✗ Decoding error: {e}")
                                return False
                    else:
                        # Not enough data left in simulated stream
                        print(f"✗ Not enough data in stream: need {buffer_size}, have {len(stream_buffer) - buffer_offset}")
                        return False
                        
                else:
                    # If buffer_size is 0, try calling try_decode with empty data to trigger buffer_size calculation
                    try:
                        decoded_message = decoder.try_decode(bytes(), responder)
                        break  # Successfully decoded (shouldn't happen on first call)
                    except Exception as e:
                        # Check if it's a MissingBytes error
                        error_type = type(e).__name__
                        
                        if "MissingBytes" in error_type:
                            # Decoder updated buffer size, continue loop
                            continue
                        else:
                            # Other error, fail the test
                            print(f"✗ Initial decode error: {e}")
                            return False
            
            if decoded_message is None:
                print(f"✗ Failed to decode after {max_iterations} iterations")
                return False

            # Verify the decoded message matches what we encoded
            if decoded_message.is_SETUP_CONNECTION():
                setup_connection = decoded_message[0]  # type: ignore
                if setup_connection.endpoint_host == "test.example.com":
                    print("✓ Encoding/decoding test passed")
                    return True
                else:
                    print(f"✗ Unexpected endpoint host: {setup_connection.endpoint_host}")
                    return False
            else:
                print(f"✗ Unexpected message type: {type(decoded_message).__name__}")
                return False

        except Exception as e:
            print(f"⚠ Encoding/decoding test failed (expected): {e}")
            return False

    except Exception as e:
        print(f"✗ Encoding/decoding test failed: {e}")
        traceback.print_exc()
        return False

def test_encoding_decoding_standalone():
    """Standalone test that sets up its own dependencies."""
    # Import handshake and message creation functions
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    
    from test_handshake import test_handshake
    from test_message_creation import test_message_creation
    
    # Set up dependencies
    handshake_success, initiator, responder = test_handshake()
    if not handshake_success:
        return False
        
    message_success, message = test_message_creation()
    if not message_success:
        return False
    
    # Run the encoding/decoding test
    return test_encoding_decoding(initiator, responder, message)

if __name__ == "__main__":
    success = test_encoding_decoding_standalone()
    exit(0 if success else 1) 