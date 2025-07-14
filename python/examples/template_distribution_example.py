#!/usr/bin/env python3
"""
Stratum v2 Template Distribution Example

This example demonstrates how to create a TCP client that:
1. Connects to a Stratum v2 Template Distribution Server
2. Performs Noise_NX handshake as an initiator
3. Sends a SetupConnection message
4. Waits for SetupConnectionSuccess message
5. Sends a CoinbaseOutputConstraints message
6. Prints all messages it receives
"""

import socket
import base58
import time
from typing import Optional

from sv2 import (
    Sv2CodecState,
    Sv2Decoder,
    Sv2Encoder,
    Sv2Message,
    SetupConnection,
    CoinbaseOutputConstraints,
    Sv2CodecError,
    Sv2MessageError
)

def get_server_ip() -> str:
    """Get template distribution server IP address from user input."""
    print("\n--- Template Distribution Server IP ---")
    print("Please enter the server IP address or hostname.")
    print("Default is 127.0.0.1 (localhost)")
    print("Examples: 127.0.0.1, localhost, mining.example.com")
    
    while True:
        try:
            server_ip = input("Server IP/hostname (default 127.0.0.1): ").strip()
            
            # Use default if empty
            if not server_ip:
                server_ip = "127.0.0.1"
                print(f"✓ Using default IP: {server_ip}")
                return server_ip
            
            # Basic validation - allow both IP addresses and hostnames
            if len(server_ip) > 253:  # Max hostname length
                print("✗ Server IP/hostname too long. Please try again.")
                continue
            
            # Try to resolve the hostname to validate it
            try:
                socket.gethostbyname(server_ip)
                print(f"✓ Server IP/hostname accepted: {server_ip}")
                return server_ip
            except socket.gaierror:
                print(f"✗ Cannot resolve hostname '{server_ip}'. Please check and try again.")
                continue
                
        except KeyboardInterrupt:
            print("\n🛑 Cancelled by user")
            exit(1)
        except Exception as e:
            print(f"✗ Error: {e}")
            continue

def get_server_port() -> int:
    """Get template distribution server port from user input."""
    print("\n--- Template Distribution Server Port ---")
    print("Please enter the server port number.")
    print("Default Stratum v2 Template Distribution port is 8442")
    
    while True:
        try:
            port_input = input("Server port (default 8442): ").strip()
            
            # Use default if empty
            if not port_input:
                port = 8442
                print(f"✓ Using default port: {port}")
                return port
            
            # Validate port number
            try:
                port = int(port_input)
                if port < 1 or port > 65535:
                    print("✗ Port must be between 1 and 65535. Please try again.")
                    continue
                
                print(f"✓ Server port accepted: {port}")
                return port
                
            except ValueError:
                print("✗ Port must be a valid number. Please try again.")
                continue
                
        except KeyboardInterrupt:
            print("\n🛑 Cancelled by user")
            exit(1)
        except Exception as e:
            print(f"✗ Error: {e}")
            continue

def get_authority_public_key() -> bytes:
    """Get authority public key for connecting to the server."""
    print("\n--- Authority Public Key Required ---")
    print("Please enter the authority public key in base58 format.")
    print("Example: 9af8kW9NvZLihSL8efV88GR6xrNwvHbef1ySBrzHP2WBHRoFo4m")
    
    while True:
        try:
            authority_pub_key_b58 = input("Authority public key (base58): ").strip()
            
            if not authority_pub_key_b58:
                print("✗ Authority public key cannot be empty. Please try again.")
                continue
            
            # Decode from base58 to bytes and extract 32-byte key according to SV2 spec
            pub_key_full = base58.b58decode(authority_pub_key_b58)
            
            # Validate the decoded key length
            if len(pub_key_full) < 34:
                print(f"✗ Invalid key length: {len(pub_key_full)} bytes (expected at least 34 bytes)")
                print("  Please enter a valid base58 encoded authority public key.")
                continue
            
            authority_pub_key = pub_key_full[2:34]   # Skip 2-byte version prefix
            
            print(f"✓ Authority public key accepted: {authority_pub_key.hex()[:16]}...")
            return authority_pub_key
            
        except Exception as e:
            print(f"✗ Invalid base58 format: {e}")
            print("  Please enter a valid base58 encoded authority public key.")
            continue

def perform_handshake(client_socket: socket.socket, initiator: Sv2CodecState) -> bool:
    """
    Perform the 3-step Noise_NX handshake as initiator.
    
    Returns True if handshake successful, False otherwise.
    """
    try:
        print("--- Starting Handshake as Initiator ---")
        
        # Step 0: Send initiator's ephemeral public key
        print("Step 0: Sending ephemeral public key...")
        step_0_frame = initiator.step_0()
        client_socket.send(step_0_frame)
        
        print(f"✓ Sent step 0 frame: {len(step_0_frame)} bytes")
        print(f"  Ephemeral key: {step_0_frame.hex()[:32]}...")
        
        # Step 1: Receive responder's response
        print("Step 1: Waiting for responder's response...")
        step_1_data = client_socket.recv(4096)  # Receive responder's frame
        
        if not step_1_data:
            print("✗ No response received from responder")
            return False
            
        print(f"✓ Received step 1 response: {len(step_1_data)} bytes")
        print(f"  Response includes: ephemeral key + encrypted static key + signature")
        
        # Step 2: Complete handshake
        print("Step 2: Completing handshake...")
        initiator.step_2(step_1_data)
        
        print("✓ Handshake completed successfully")
        print("✓ Secure channel established")
        
        return True
        
    except Exception as e:  # Catch all exceptions since Sv2CodecError might be a subclass
        # Check if it's a codec error by checking the type name
        if 'Sv2CodecError' in str(type(e)):
            print(f"✗ Handshake failed with codec error: {e}")
        else:
            print(f"✗ Handshake failed with error: {e}")
        return False

def create_setup_connection_message():
    """Create a SetupConnection message to send to the server."""
    try:
        print("\n--- Creating SetupConnection Message ---")
        
        setup_connection = SetupConnection(
            protocol=2,         # Template Distribution protocol
            min_version=2,
            max_version=2,
            flags=0,
            endpoint_host="template-client.example.com",
            endpoint_port=0,
            vendor="Template Distribution Client",
            hardware_version="v1.0.0",
            firmware="py-template-client-1.0",
            device_id="template-client-001"
        )
        
        # Create the message using the proper UniFFI syntax
        return Sv2Message.SETUP_CONNECTION(setup_connection)
        
    except Exception as e:
        print(f"✗ Failed to create SetupConnection message: {e}")
        return None

def create_coinbase_output_constraints_message():
    """Create a CoinbaseOutputConstraints message to send to the server."""
    try:
        print("\n--- Creating CoinbaseOutputConstraints Message ---")
        
        # Create CoinbaseOutputConstraints with typical mining constraints
        coinbase_constraints = CoinbaseOutputConstraints(
            coinbase_output_max_additional_size=32,  # 32 bytes max additional size
            coinbase_output_max_additional_sigops=4   # 4 additional signature operations
        )
        
        print("✓ Created CoinbaseOutputConstraints message:")
        print(f"  - Max Additional Size: {coinbase_constraints.coinbase_output_max_additional_size} bytes")
        print(f"  - Max Additional Sigops: {coinbase_constraints.coinbase_output_max_additional_sigops}")
        
        # Create the message using the proper UniFFI syntax
        return Sv2Message.COINBASE_OUTPUT_CONSTRAINTS(coinbase_constraints)
        
    except Exception as e:
        print(f"✗ Failed to create CoinbaseOutputConstraints message: {e}")
        return None

def send_setup_connection_and_coinbase_output_constraints_messages(client_socket: socket.socket, initiator: Sv2CodecState, encoder: Sv2Encoder, decoder: Sv2Decoder):
    """
    Send SetupConnection message first, then CoinbaseOutputConstraints message.
    """
    print("\n--- Message Exchange Phase ---")
    
    try:
        # Step 1: Create and send SetupConnection message
        setup_message = create_setup_connection_message()
        if not setup_message:
            print("✗ Failed to create SetupConnection message")
            return
        
        print("\n--- Encoding and Sending SetupConnection ---")
        try:
            setup_encoded_frame = encoder.encode(setup_message, initiator)  # type: ignore
            print(f"✓ SetupConnection encoded successfully: {len(setup_encoded_frame)} bytes")
            print(f"  Encoded frame: {setup_encoded_frame.hex()[:64]}...")
            
            client_socket.send(setup_encoded_frame)
            print("✓ SetupConnection message sent to server")
            
            # Print message details
            print("\n--- SetupConnection Message Details ---")
            print(f"Message Type: SetupConnection")
            print(f"Message Size: {len(setup_encoded_frame)} bytes")
            print(f"Encoded Data: {setup_encoded_frame.hex()}")
            
        except Exception as e:
            print(f"✗ Failed to encode/send SetupConnection message: {e}")
            return
        
        # Wait for SetupConnectionSuccess response
        print("\n--- Waiting for SetupConnectionSuccess Response ---")
        try:
            while True:
                # Get the size of buffer that needs to be filled
                buffer_size = decoder.buffer_size()
                
                if buffer_size > 0:
                    # Read exactly the number of bytes the decoder needs
                    response_data = client_socket.recv(buffer_size)
                    
                    if not response_data:
                        print("⚠ No response received for SetupConnection")
                        return
                    
                    if len(response_data) != buffer_size:
                        # For TCP, we might get partial data, so we need to keep reading
                        while len(response_data) < buffer_size:
                            more_data = client_socket.recv(buffer_size - len(response_data))
                            if not more_data:
                                print("⚠ Connection closed while reading response")
                                return
                            response_data += more_data
                    
                    print(f"✓ Received response: {len(response_data)} bytes")
                    print(f"  Raw response: {response_data.hex()}")
                    
                    # Try to decode the response
                    try:
                        decoded_response = decoder.try_decode(response_data, initiator)
                        if decoded_response.is_setup_connection_success():
                            print("✓ Received SetupConnectionSuccess!")
                            break
                        else:
                            print(f"⚠ Received unexpected response: {type(decoded_response).__name__}")
                            print(f"  Response details: {decoded_response}")
                            # Don't continue if we didn't get the expected response
                            return
                        
                    except Exception as e:
                        # Check if it's a MissingBytes error
                        error_type = type(e).__name__
                        
                        # Handle MissingBytes error
                        if "MissingBytes" in error_type:
                            # Decoder needs more data, will check buffer_size again
                            continue
                        else:
                            print(f"⚠ Error decoding response: {e}")
                            print(f"  Raw response data: {response_data.hex()}")
                            return
                            
                else:
                    # If buffer_size is 0, try calling try_decode with empty data to trigger buffer_size calculation
                    try:
                        decoded_response = decoder.try_decode(bytes(), initiator)
                        # If this succeeds, we have a message (shouldn't happen on first call)
                        print("✓ Received response (unexpected initial success)")
                        break
                    except Exception as e:
                        # Check if it's a MissingBytes error
                        error_type = type(e).__name__
                        
                        # Handle MissingBytes error
                        if "MissingBytes" in error_type:
                            # Decoder updated buffer size, will check buffer_size again
                            continue
                        else:
                            print(f"⚠ Error on initial decode: {e}")
                            return
                
        except Exception as e:
            print(f"⚠ Error receiving SetupConnection response: {e}")
            return
        
        # Step 2: Create and send CoinbaseOutputConstraints message
        constraints_message = create_coinbase_output_constraints_message()
        if not constraints_message:
            print("✗ Failed to create CoinbaseOutputConstraints message")
            return
        
        print("\n--- Encoding and Sending CoinbaseOutputConstraints ---")
        try:
            # Debug: Check codec state before encoding
            print(f"📊 Codec state before encoding:")
            print(f"  - Handshake complete: {initiator.handshake_complete()}")
            
            constraints_encoded_frame = encoder.encode(constraints_message, initiator)  # type: ignore
            print(f"✓ CoinbaseOutputConstraints encoded successfully: {len(constraints_encoded_frame)} bytes")
            print(f"  Encoded frame (first 64 chars): {constraints_encoded_frame.hex()[:64]}...")
            
            # Send with explicit flush
            client_socket.send(constraints_encoded_frame)
            print("✓ CoinbaseOutputConstraints message sent to server")
            
        except Exception as e:
            print(f"✗ Failed to encode/send CoinbaseOutputConstraints message: {e}")
            import traceback
            traceback.print_exc()
            return
        
    except Exception as e:
        print(f"✗ Error in message exchange: {e}")

def listen_for_messages(client_socket: socket.socket, initiator: Sv2CodecState, decoder: Sv2Decoder):
    """
    Continuously listen for incoming messages and print them to terminal.
    """
    print("\n--- Listening for Incoming Messages ---")
    print("Blocking and waiting for messages from server... (Press Ctrl+C to stop)")
    
    # Ensure no timeout is set - we want to block indefinitely
    client_socket.settimeout(None)
    
    # Add debug info about socket state
    print(f"📊 Socket state:")
    print(f"  - Timeout: {client_socket.gettimeout()} (None = blocking)")
    print(f"  - Socket connected: {client_socket.fileno() != -1}")
    
    try:
        message_count = 0
        
        print("\n🔄 Entering message listening loop...")
        while True:
            try:
                # Get the size of buffer that needs to be filled
                buffer_size = decoder.buffer_size()
                
                if buffer_size > 0:
                    
                    # Read exactly the number of bytes the decoder needs
                    data = client_socket.recv(buffer_size)
                    
                    if not data:
                        print("✗ Server closed the connection (received empty data)")
                        print("  This might be normal behavior after sending CoinbaseOutputConstraints")
                        break
                    
                    if len(data) != buffer_size:
                        print(f"⚠ Expected {buffer_size} bytes, got {len(data)} bytes")
                        # For TCP, we might get partial data, so we need to keep reading
                        while len(data) < buffer_size:
                            more_data = client_socket.recv(buffer_size - len(data))
                            if not more_data:
                                print("✗ Server closed connection while reading")
                                return
                            data += more_data
                    
                    # Try to decode with the exact amount of data
                    try:
                        decoded_message = decoder.try_decode(data, initiator)
                        
                        # Successfully decoded a message!
                        message_count += 1
                        print(f"\n--- Message #{message_count} Decoded ---")
                        print(f"Frame length: {len(data)} bytes")
                        print(f"Message type: {type(decoded_message).__name__}")
                        
                        # Print message details
                        if decoded_message.is_NEW_TEMPLATE():
                            print("📄 NEW_TEMPLATE message received")
                            # Access message data properly from the enum variant
                            template_data = decoded_message[0]  # type: ignore
                            print(f"  - Template ID: {template_data.template_id}")
                            print(f"  - Future template: {template_data.future_template}")
                            print(f"  - Version: {template_data.version}")
                            print(f"  - Coinbase value remaining: {template_data.coinbase_tx_value_remaining}")
                            print(f"  - Merkle path nodes: {len(template_data.merkle_path)}")
                            for i, path_node in enumerate(template_data.merkle_path):
                                print(f"    [{i}]: {path_node[::-1].hex()}")
                            
                        elif decoded_message.is_SET_NEW_PREV_HASH_TEMPLATE_DISTRIBUTION():
                            print("🔗 SET_NEW_PREV_HASH_TEMPLATE_DISTRIBUTION message received")
                            # Access message data properly from the enum variant
                            prev_hash_data = decoded_message[0]  # type: ignore
                            print(f"  - Template ID: {prev_hash_data.template_id}")
                            print(f"  - PrevHash: {prev_hash_data.prev_hash[::-1].hex()}")
                            print(f"  - Header timestamp: {prev_hash_data.header_timestamp}")
                        
                        else:
                            print(f"📨 Other message type: {type(decoded_message).__name__}")
                            # For other message types, we just print the type
                        
                        # Continue to next message
                        continue
                        
                    except Exception as e:
                        # Check if it's a MissingBytes error
                        error_type = type(e).__name__
                        
                        # Handle MissingBytes error
                        if "MissingBytes" in error_type:
                            # Decoder updated buffer size, will check buffer_size again
                            continue
                        else:
                            print(f"✗ Unexpected decoding error: {e}")
                            break
                            
                else:
                    # If buffer_size is 0, try calling try_decode with empty data to trigger initial calculation
                    try:
                        decoded_message = decoder.try_decode(bytes(), initiator)
                        # If this succeeds, we have a message (shouldn't happen on first call)
                        message_count += 1
                        print(f"\n--- Message #{message_count} Decoded (unexpected) ---")
                        print(f"Message type: {type(decoded_message).__name__}")
                        continue
                    except Exception as e:
                        # Check if it's a MissingBytes error
                        error_type = type(e).__name__
                        
                        # Handle MissingBytes error
                        if "MissingBytes" in error_type:
                            # Decoder updated buffer size, will check buffer_size again
                            continue
                        else:
                            print(f"✗ Unexpected error on initial decode: {e}")
                            break
                        
            except Exception as e:
                print(f"⚠ Error in message loop: {e}")
                break
                
    except KeyboardInterrupt:
        print("\n🛑 Stopping message listener (Ctrl+C pressed)")
        
    except Exception as e:
        print(f"✗ Error in message listener: {e}")
        
    finally:
        print(f"📊 Total messages received: {message_count}")

def connect_to_server(host: str = "127.0.0.1", port: int = 8442) -> bool:
    """
    Connect to the Stratum v2 server and perform complete communication flow.
    """
    print(f"🔗 Connecting to Stratum v2 server at {host}:{port}")
    print("This example sends a CoinbaseOutputConstraints message")
    
    try:
        # Create socket and connect
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)  # 10 second timeout for connection
        
        # Enable socket keepalive to prevent connection from closing
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        print(f"Attempting to connect to {host}:{port}...")
        client_socket.connect((host, port))
        print(f"✓ Connected to server at {host}:{port}")
        
        # Remove connection timeout after successful connection
        client_socket.settimeout(None)
        
        # Get authority public key
        authority_pub_key = get_authority_public_key()
        print(f"✓ Using authority public key: {authority_pub_key.hex()[:16]}...")
        
        # Create initiator
        initiator = Sv2CodecState.new_initiator(authority_pub_key)
        print("✓ Initiator created successfully")
        
        # Create single encoder/decoder pair for the entire session
        encoder = Sv2Encoder()
        decoder = Sv2Decoder()
        print("✓ Encoder and decoder created successfully")
        
        # Perform handshake
        if perform_handshake(client_socket, initiator):
            # Send SetupConnection and CoinbaseOutputConstraints messages after successful handshake
            send_setup_connection_and_coinbase_output_constraints_messages(client_socket, initiator, encoder, decoder)
            
            # Start listening for messages from server using the same decoder
            listen_for_messages(client_socket, initiator, decoder)
        else:
            print("✗ Handshake failed, closing connection")
            return False
        
        # Connection cleanup
        print("\n--- Connection Complete ---")
        client_socket.close()
        print("✓ Connection closed gracefully")
        return True
        
    except socket.timeout:
        print("✗ Connection timeout")
        return False
    except socket.error as e:
        if hasattr(e, 'errno') and e.errno == 61:  # Connection refused
            print(f"✗ Connection refused. Is the server running on {host}:{port}?")
            print("  Try running: python server_example.py")
        else:
            print(f"✗ Socket error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

def main():
    
    try:
        # Get server connection details from user
        server_ip = get_server_ip()
        server_port = get_server_port()
        
        # Connect to server and send message
        success = connect_to_server(server_ip, server_port)
        
        if success:
            print("\n🎉 Template Distribution Example completed successfully!")
        else:
            print("\n✗ Template Distribution Example failed")
            print("Make sure the Template Distribution Server is running and the authority public key is correct.")
            
    except KeyboardInterrupt:
        print("\n\n🛑 Example interrupted by user")
        
    except Exception as e:
        print(f"\n\n✗ Unexpected error in example: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 