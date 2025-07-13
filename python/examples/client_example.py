#!/usr/bin/env python3
"""
Stratum v2 Client Example

This example demonstrates how to create a TCP client that:
1. Connects to a Stratum v2 server
2. Performs Noise_NX handshake as an initiator
3. Sends Stratum v2 messages (like SetupConnection)
4. Receives and handles responses

Run the server_example.py first, then run this client to see the complete flow.
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
    Sv2CodecError,
    Sv2MessageError,
    SetupConnectionSuccess
)

def get_authority_public_key() -> bytes:
    """Get authority public key for connecting to the server."""
    # Use the same authority public key as the server
    authority_pub_key_b58 = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
    
    # Decode from base58 to bytes and extract 32-byte key according to SV2 spec
    pub_key_full = base58.b58decode(authority_pub_key_b58)
    authority_pub_key = pub_key_full[2:34]   # Skip 2-byte version prefix
    
    return authority_pub_key

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
        
    except Sv2CodecError as e:
        print(f"✗ Handshake failed with codec error: {e}")
        return False
    except Exception as e:
        print(f"✗ Handshake failed with error: {e}")
        return False

def create_setup_connection_message() -> Optional[Sv2Message]:
    """Create a SetupConnection message to send to the server."""
    try:
        print("\n--- Creating SetupConnection Message ---")
        
        setup_connection = SetupConnection(
            protocol=1,           # Mining protocol
            min_version=2,        # Minimum protocol version  
            max_version=2,        # Maximum protocol version
            flags=0,              # Protocol flags
            endpoint_host="client.example.com",
            endpoint_port=0,      # Client doesn't listen
            vendor="Example Python Client",
            hardware_version="v1.0.0",
            firmware="py-client-1.0",
            device_id="python-client-001"
        )
        
        print("✓ Created SetupConnection message:")
        print(f"  - Protocol: {setup_connection.protocol}")
        print(f"  - Version range: {setup_connection.min_version}-{setup_connection.max_version}")
        print(f"  - Flags: {setup_connection.flags}")
        print(f"  - Endpoint: {setup_connection.endpoint_host}:{setup_connection.endpoint_port}")
        print(f"  - Vendor: {setup_connection.vendor}")
        print(f"  - Hardware Version: {setup_connection.hardware_version}")
        print(f"  - Firmware: {setup_connection.firmware}")
        print(f"  - Device ID: {setup_connection.device_id}")
        
        # Wrap in Sv2Message enum
        return Sv2Message.SETUP_CONNECTION(setup_connection)  # type: ignore
        
    except Sv2MessagesError as e:
        print(f"✗ Failed to create SetupConnection message: {e}")
        return None
    except Exception as e:
        print(f"✗ Unexpected error creating message: {e}")
        return None

def send_and_receive_messages(client_socket: socket.socket, initiator: Sv2CodecState):
    """
    Send messages to the server and handle responses.
    Uses incremental reading to handle frame boundaries properly.
    """
    encoder = Sv2Encoder()
    decoder = Sv2Decoder()
    print("\n--- Message Exchange Phase ---")
    
    # Buffer to accumulate incoming data
    data_buffer = bytearray()
    
    try:
        # Create and send SetupConnection message
        setup_message = create_setup_connection_message()
        if not setup_message:
            print("✗ Failed to create SetupConnection message")
            return
        
        print("\n--- Encoding and Sending Message ---")
        try:
            encoded_frame = encoder.encode(setup_message, initiator)  # type: ignore
            print(f"✓ Message encoded successfully: {len(encoded_frame)} bytes")
            print(f"  Encoded frame: {encoded_frame.hex()[:64]}...")
            
            client_socket.send(encoded_frame)
            print("✓ SetupConnection message sent to server")
            
        except Exception as e:
            print(f"✗ Failed to encode/send message: {e}")
            return
        
        # Listen for responses using buffered approach
        print("\n--- Listening for Server Responses ---")
        message_count = 0
        
        while True:
            try:
                print("⏳ Waiting for next data from server...")
                
                # Read new data from socket
                new_data = client_socket.recv(4096)
                
                if not new_data:
                    print("✗ Server closed the connection")
                    break
                
                # Add new data to buffer
                data_buffer.extend(new_data)
                print(f"📦 Received {len(new_data)} bytes, buffer now has {len(data_buffer)} bytes")
                
                # Try to decode messages from the buffer
                processed_any = True
                while processed_any and len(data_buffer) > 0:
                    processed_any = False
                    
                    # Try different buffer sizes to find a complete frame
                    for try_length in range(7, len(data_buffer) + 1):  # Start from minimum reasonable frame size
                        try:
                            # Try to decode with first 'try_length' bytes
                            test_decoder = Sv2Decoder()  # Use fresh decoder for each test
                            decoded_response = test_decoder.decode(bytes(data_buffer[:try_length]), initiator)
                            
                            # Successfully decoded a message!
                            message_count += 1
                            print(f"\n--- Response #{message_count} Decoded ---")
                            print(f"Frame length: {try_length} bytes")
                            print(f"Message type: {type(decoded_response).__name__}")
                            
                            # Handle different response types
                            if decoded_response.is_SETUP_CONNECTION_SUCCESS():
                                print("\n🎉 Received SetupConnectionSuccess!")
                                
                                # Extract the response data
                                success_response = decoded_response[0]  # type: ignore
                                
                                print("--- SetupConnectionSuccess Details ---")
                                print(f"Used Version: {success_response.used_version}")
                                print(f"Flags: {success_response.flags}")
                                
                                print("\n✅ Connection setup completed successfully!")
                                print("Client-server communication established")
                                
                                # After successful setup, we could send more messages or exit
                                # For this example, we'll exit after receiving the success response
                                print("🏁 Example completed - connection established")
                                return
                                
                            else:
                                print(f"📨 Received other message type: {type(decoded_response).__name__}")
                                # Could handle other message types here
                            
                            # Remove the processed frame from buffer
                            data_buffer = data_buffer[try_length:]
                            print(f"🔄 Consumed {try_length} bytes, {len(data_buffer)} bytes remaining in buffer")
                            
                            processed_any = True
                            break  # Exit the try_length loop and try to decode next frame
                            
                        except Exception as decode_error:
                            # This length doesn't work, try next length
                            continue
                    
                    # If we couldn't decode any frame, we need more data
                    if not processed_any:
                        print(f"⏳ Buffer contains partial frame, waiting for more data...")
                        print(f"   Buffer size: {len(data_buffer)} bytes")
                        break  # Exit the processing loop and read more data
                        
            except socket.timeout:
                print("⚠ Timeout waiting for server response")
                break
            except Exception as e:
                print(f"⚠ Error receiving response: {e}")
                break
            
    except Exception as e:
        print(f"✗ Error in message exchange: {e}")
        
    finally:
        print(f"📊 Total responses received: {message_count}")

def connect_to_server(host: str = "127.0.0.1", port: int = 34254) -> bool:
    """
    Connect to the Stratum v2 server and perform complete communication flow.
    """
    print(f"🔗 Connecting to Stratum v2 server at {host}:{port}")
    
    try:
        # Create socket and connect
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(10)  # 10 second timeout
        
        print(f"Attempting to connect to {host}:{port}...")
        client_socket.connect((host, port))
        print(f"✓ Connected to server at {host}:{port}")
        
        # Get authority public key
        authority_pub_key = get_authority_public_key()
        print(f"✓ Using authority public key: {authority_pub_key.hex()[:16]}...")
        
        # Create initiator
        initiator = Sv2CodecState.new_initiator(authority_pub_key)
        print("✓ Initiator created successfully")
        
        # Perform handshake
        if perform_handshake(client_socket, initiator):
            # Send messages and handle responses after successful handshake
            send_and_receive_messages(client_socket, initiator)
        else:
            print("✗ Handshake failed, closing connection")
            return False
        
        # Keep connection alive for a moment
        print("\n--- Connection Complete ---")
        print("Keeping connection alive for 2 seconds...")
        time.sleep(2)
        
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
        print(f"✗ Connection failed: {e}")
        return False
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    """
    Main function to demonstrate client functionality.
    """
    print("=" * 60)
    print("        Stratum v2 Client Example")
    print("=" * 60)
    print()
    print("This example demonstrates a complete Stratum v2 client that:")
    print("1. Connects to a Stratum v2 server via TCP")
    print("2. Performs Noise_NX handshake as initiator")
    print("3. Sends SetupConnection message")
    print("4. Receives SetupConnectionSuccess response")
    print()
    print("Prerequisites:")
    print("- Run the server_example.py first")
    print("- Server should be listening on 127.0.0.1:34254")
    print()
    
    try:
        # Test the connection
        success = connect_to_server()
        
        if success:
            print("\n🎉 Client example completed successfully!")
            print("\nThe client successfully:")
            print("✓ Connected to the server")
            print("✓ Completed Noise_NX handshake")
            print("✓ Sent SetupConnection message")
            print("✓ Received SetupConnectionSuccess response")
            print("\nFull Stratum v2 communication flow demonstrated!")
        else:
            print("\n❌ Client example failed")
            print("\nTroubleshooting:")
            print("1. Make sure server_example.py is running")
            print("2. Check that port 34254 is available")
            print("3. Verify network connectivity")
            
    except KeyboardInterrupt:
        print("\n\n⚠ Client interrupted by user")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")

if __name__ == "__main__":
    main() 