#!/usr/bin/env python3
"""
Stratum v2 Server Example

This example demonstrates how to create a TCP server that:
1. Listens for incoming connections
2. Performs Noise_NX handshake as a responder
3. Receives and decodes Stratum v2 messages
4. Responds with SetupConnectionSuccess to SetupConnection messages

Run this server, then use a client to connect and send messages.
"""

import socket
import base58
import threading
from typing import Optional

from sv2 import (
    Sv2CodecState,
    Sv2Decoder,
    Sv2Encoder,
    Sv2Message,
    SetupConnectionSuccess,
    Sv2CodecError,
    Sv2MessageError
)

def get_authority_keypair() -> tuple[bytes, bytes]:
    """Get authority keypair for the server."""
    # Use actual Stratum v2 keys (base58 encoded) - matching the example.py
    authority_pub_key_b58 = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
    authority_priv_key_b58 = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
    
    # Decode from base58 to bytes and extract 32-byte keys according to SV2 spec
    pub_key_full = base58.b58decode(authority_pub_key_b58)
    priv_key_full = base58.b58decode(authority_priv_key_b58)
    
    # Extract the 32-byte keys according to SV2 specification
    authority_pub_key = pub_key_full[2:34]   # Skip 2-byte version prefix
    authority_priv_key = priv_key_full[:32]  # First 32 bytes
    
    return authority_pub_key, authority_priv_key

def perform_handshake(client_socket: socket.socket, responder: Sv2CodecState) -> bool:
    """
    Perform the 3-step Noise_NX handshake as responder.
    
    Returns True if handshake successful, False otherwise.
    """
    try:
        print("--- Starting Handshake as Responder ---")
        
        # Step 1: Receive initiator's ephemeral public key (64 bytes)
        print("Step 1: Waiting for initiator's ephemeral public key...")
        step_0_data = client_socket.recv(64)
        
        if len(step_0_data) != 64:
            print(f"✗ Expected 64 bytes for step 0, got {len(step_0_data)}")
            return False
            
        print(f"✓ Received step 0 frame: {len(step_0_data)} bytes")
        print(f"  Ephemeral key: {step_0_data.hex()[:32]}...")
        
        # Step 2: Process initiator frame and send response
        print("Step 2: Processing initiator frame and sending response...")
        step_1_frame = responder.step_1(step_0_data)
        client_socket.send(step_1_frame)
        
        print(f"✓ Sent step 1 response: {len(step_1_frame)} bytes")
        print(f"  Response includes: ephemeral key + encrypted static key + signature")
        
        # Step 3: Wait for initiator to complete handshake
        # Note: In Noise_NX, step 2 is sent by initiator, but our current implementation
        # doesn't require the responder to process it. The handshake is complete after step 1.
        print("Step 3: Handshake completed")
        print("✓ Secure channel established")
        
        return True
        
    except Sv2CodecError as e:
        print(f"✗ Handshake failed with codec error: {e}")
        return False
    except Exception as e:
        print(f"✗ Handshake failed with error: {e}")
        return False

def handle_messages(client_socket: socket.socket, responder: Sv2CodecState):
    """
    Handle incoming encrypted messages after handshake.
    """
    decoder = Sv2Decoder()
    encoder = Sv2Encoder()
    print("\n--- Message Handling Phase ---")
    print("Waiting for encrypted messages...")
    
    try:
        while True:
            # Read the complete encrypted frame
            # First, try to read some initial data to see what we get
            print("\nWaiting for encrypted message frame...")
            initial_data = client_socket.recv(4096)  # Read up to 4KB
            
            if not initial_data:
                print("Client disconnected")
                break
                
            print(f"✓ Received encrypted frame: {len(initial_data)} bytes")
            print(f"Frame data: {initial_data.hex()[:64]}...")
            
            # Attempt to decode the complete frame
            try:
                decoded_message = decoder.decode(initial_data, responder)
                print("✓ Message decoded successfully!")
                
                # Check if it's a SetupConnection message
                if decoded_message.is_SETUP_CONNECTION():
                    print("\n🎉 Received SetupConnection Message!")
                    
                    # Extract the SetupConnection data
                    setup_connection = decoded_message[0]
                        
                    print("--- SetupConnection Details ---")
                    print(f"Protocol: {setup_connection.protocol}")
                    print(f"Version Range: {setup_connection.min_version}-{setup_connection.max_version}")
                    print(f"Flags: {setup_connection.flags}")
                    print(f"Endpoint: {setup_connection.endpoint_host}:{setup_connection.endpoint_port}")
                    print(f"Vendor: {setup_connection.vendor}")
                    print(f"Hardware Version: {setup_connection.hardware_version}")
                    print(f"Firmware: {setup_connection.firmware}")
                    print(f"Device ID: {setup_connection.device_id}")
                    
                    # Create and send SetupConnectionSuccess response
                    print("\n--- Creating SetupConnectionSuccess Response ---")
                    
                    # Use the same version and flags from the received message
                    # For used_version, we'll use the max_version from the client's range
                    used_version = setup_connection.max_version
                    flags = setup_connection.flags
                    
                    setup_success = SetupConnectionSuccess(
                        used_version=used_version,
                        flags=flags
                    )
                    
                    # Wrap in Sv2Message enum
                    success_message = Sv2Message.SETUP_CONNECTION_SUCCESS(setup_success)
                    
                    print(f"✓ Created SetupConnectionSuccess:")
                    print(f"  - Used Version: {used_version}")
                    print(f"  - Flags: {flags}")
                    
                    # Encode and send the response
                    try:
                        encoded_response = encoder.encode(success_message, responder)
                        client_socket.send(encoded_response)
                        print(f"✓ Sent SetupConnectionSuccess response: {len(encoded_response)} bytes")
                        print(f"  Response data: {encoded_response.hex()[:64]}...")
                        
                    except Exception as e:
                        print(f"✗ Failed to encode/send response: {e}")
                    
                else:
                    print(f"Received other message type: {type(decoded_message).__name__}")
                    
            except Exception as e:
                print(f"⚠ Failed to decode message: {e}")
                print(f"Raw frame data: {initial_data.hex()}")
                
    except Exception as e:
        print(f"✗ Error handling messages: {e}")

def handle_client(client_socket: socket.socket, client_address: tuple):
    """
    Handle a single client connection.
    """
    print(f"\n🔗 New client connected from {client_address[0]}:{client_address[1]}")
    
    try:
        # Get authority keypair
        authority_pub_key, authority_priv_key = get_authority_keypair()
        print(f"✓ Using authority keys:")
        print(f"  Public key: {authority_pub_key.hex()[:16]}...")
        print(f"  Private key: {authority_priv_key.hex()[:16]}...")
        
        # Create responder
        cert_validity_secs = 86400  # 24 hours
        responder = Sv2CodecState.new_responder(
            authority_pub_key,
            authority_priv_key,
            cert_validity_secs
        )
        print("✓ Responder created successfully")
        
        # Perform handshake
        if perform_handshake(client_socket, responder):
            # Handle messages after successful handshake
            handle_messages(client_socket, responder)
        else:
            print("✗ Handshake failed, closing connection")
            
    except Exception as e:
        print(f"✗ Error handling client: {e}")
        
    finally:
        client_socket.close()
        print(f"🔌 Connection closed for {client_address[0]}:{client_address[1]}")

def start_server(host: str = "0.0.0.0", port: int = 34254):
    """
    Start the Stratum v2 server.
    """
    print("🚀 Starting Stratum v2 Server")
    print("=" * 50)
    print(f"Listening on {host}:{port}")
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"✓ Server listening on {host}:{port}")
        
        while True:
            try:
                # Accept incoming connections
                client_socket, client_address = server_socket.accept()
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except KeyboardInterrupt:
                print("\n🛑 Server shutdown requested")
                break
                
    except Exception as e:
        print(f"✗ Server error: {e}")
        
    finally:
        server_socket.close()
        print("✓ Server socket closed")

def main():
    """
    Main function to start the server.
    """
    print("Stratum v2 Server Example")
    print("This server will:")
    print("1. Listen for TCP connections")
    print("2. Perform Noise_NX handshake as responder")
    print("3. Receive and decode SetupConnection messages")
    print()
    
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"✗ Server failed to start: {e}")

if __name__ == "__main__":
    main() 