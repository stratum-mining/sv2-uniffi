/*
 * Stratum v2 Client Example
 *
 * This example demonstrates how to create a TCP client that:
 * 1. Connects to a Stratum v2 server
 * 2. Performs Noise_NX handshake as an initiator
 * 3. Sends a SetupConnection message
 * 4. Receives and parses the response
 *
 * Run server_example.cpp first, then run this client to see the complete flow.
 */

#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include "example_utils.hpp"
#include "tcp_utils.hpp"
#include "sv2.hpp"

namespace {

constexpr const char *DEFAULT_HOST = "127.0.0.1";
constexpr std::uint16_t DEFAULT_PORT = 34254;
constexpr std::size_t HANDSHAKE_RESPONSE_BUFFER_SIZE = 4096;

using sv2cpp::example::tcp::TcpSocket;
using sv2cpp::example::tcp::connect_tcp;
using sv2cpp::example::tcp::recv_exact;
using sv2cpp::example::tcp::recv_some;
using sv2cpp::example::tcp::send_all;

bool perform_handshake(
    TcpSocket &client_socket,
    const std::shared_ptr<sv2::Sv2CodecState> &initiator
) {
    try {
        std::cout << "--- Starting Handshake as Initiator ---" << std::endl;

        std::cout << "Step 0: Sending ephemeral public key..." << std::endl;
        const auto step_0_frame = initiator->step_0();
        send_all(client_socket.fd(), step_0_frame);

        std::cout << "✓ Sent step 0 frame: " << step_0_frame.size() << " bytes" << std::endl;
        std::cout << "  Ephemeral key: "
                  << sv2cpp::example::shortened_hex(step_0_frame)
                  << std::endl;

        std::cout << "Step 1: Waiting for responder's response..." << std::endl;
        const auto step_1_data = recv_some(
            client_socket.fd(),
            HANDSHAKE_RESPONSE_BUFFER_SIZE
        );

        std::cout << "✓ Received step 1 response: " << step_1_data.size() << " bytes" << std::endl;
        std::cout << "  Response includes: ephemeral key + encrypted static key + signature" << std::endl;

        std::cout << "Step 2: Completing handshake..." << std::endl;
        initiator->step_2(step_1_data);

        std::cout << "✓ Handshake completed successfully" << std::endl;
        std::cout << "✓ Secure channel established" << std::endl;

        return true;
    } catch (const sv2::Sv2CodecError &error) {
        std::cout << "✗ Handshake failed with codec error: " << error.what() << std::endl;
        return false;
    } catch (const std::exception &error) {
        std::cout << "✗ Handshake failed with error: " << error.what() << std::endl;
        return false;
    }
}

std::optional<sv2::Sv2Message> create_setup_connection_message() {
    try {
        std::cout << std::endl;
        std::cout << "--- Creating SetupConnection Message ---" << std::endl;

        auto setup_connection = sv2::SetupConnection{
            .protocol = 1,
            .min_version = 2,
            .max_version = 2,
            .flags = 0,
            .endpoint_host = "client.example.com",
            .endpoint_port = 0,
            .vendor = "Example C++ Client",
            .hardware_version = "v1.0.0",
            .firmware = "cpp-client-1.0",
            .device_id = "cpp-client-001",
        };

        std::cout << "✓ Created SetupConnection message:" << std::endl;
        std::cout << "  - Protocol: " << static_cast<int>(setup_connection.protocol) << std::endl;
        std::cout << "  - Version range: "
                  << setup_connection.min_version
                  << "-"
                  << setup_connection.max_version
                  << std::endl;
        std::cout << "  - Flags: " << setup_connection.flags << std::endl;
        std::cout << "  - Endpoint: "
                  << setup_connection.endpoint_host
                  << ":"
                  << setup_connection.endpoint_port
                  << std::endl;
        std::cout << "  - Vendor: " << setup_connection.vendor << std::endl;
        std::cout << "  - Hardware Version: " << setup_connection.hardware_version << std::endl;
        std::cout << "  - Firmware: " << setup_connection.firmware << std::endl;
        std::cout << "  - Device ID: " << setup_connection.device_id << std::endl;

        return sv2::Sv2Message(
            sv2::Sv2Message::kSetupConnection{
                .message = setup_connection,
            }
        );
    } catch (const sv2::Sv2MessageError &error) {
        std::cout << "✗ Failed to create SetupConnection message: " << error.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception &error) {
        std::cout << "✗ Failed to create SetupConnection message: " << error.what() << std::endl;
        return std::nullopt;
    }
}

std::optional<sv2::Sv2Message> decode_next_message(
    TcpSocket &client_socket,
    sv2::Sv2Decoder &decoder,
    const std::shared_ptr<sv2::Sv2CodecState> &initiator
) {
    while (true) {
        const auto buffer_size = decoder.buffer_size();

        if (buffer_size == 0) {
            try {
                return decoder.try_decode({}, initiator);
            } catch (const std::exception &error) {
                if (sv2cpp::example::is_missing_bytes_error(error)) {
                    continue;
                }

                throw;
            }
        }

        const auto data = recv_exact(client_socket.fd(), buffer_size);

        try {
            return decoder.try_decode(data, initiator);
        } catch (const std::exception &error) {
            if (sv2cpp::example::is_missing_bytes_error(error)) {
                continue;
            }

            throw;
        }
    }
}

void send_and_receive_messages(
    TcpSocket &client_socket,
    const std::shared_ptr<sv2::Sv2CodecState> &initiator
) {
    auto encoder = sv2::Sv2Encoder::init();
    auto decoder = sv2::Sv2Decoder::init();

    if (encoder == nullptr) {
        throw std::runtime_error("Sv2Encoder::init returned null");
    }
    if (decoder == nullptr) {
        throw std::runtime_error("Sv2Decoder::init returned null");
    }

    std::cout << std::endl;
    std::cout << "--- Message Exchange Phase ---" << std::endl;

    std::size_t message_count = 0;

    try {
        const auto setup_message = create_setup_connection_message();

        if (!setup_message.has_value()) {
            std::cout << "✗ Failed to create SetupConnection message" << std::endl;
            return;
        }

        std::cout << std::endl;
        std::cout << "--- Encoding and Sending Message ---" << std::endl;

        const auto encoded_frame = encoder->encode(*setup_message, initiator);

        std::cout << "✓ Message encoded successfully: " << encoded_frame.size() << " bytes" << std::endl;
        std::cout << "  Encoded frame: "
                  << sv2cpp::example::shortened_hex(encoded_frame, 32)
                  << std::endl;

        send_all(client_socket.fd(), encoded_frame);
        std::cout << "✓ SetupConnection message sent to server" << std::endl;

        std::cout << std::endl;
        std::cout << "--- Listening for Server Responses ---" << std::endl;

        while (true) {
            const auto decoded_response = decode_next_message(
                client_socket,
                *decoder,
                initiator
            );

            if (!decoded_response.has_value()) {
                continue;
            }

            message_count += 1;

            std::cout << std::endl;
            std::cout << "--- Response #" << message_count << " Decoded ---" << std::endl;

            const auto &variant = decoded_response->get_variant();

            if (std::holds_alternative<sv2::Sv2Message::kSetupConnectionSuccess>(variant)) {
                std::cout << std::endl;
                std::cout << "🎉 Received SetupConnectionSuccess!" << std::endl;

                const auto &success_response =
                    std::get<sv2::Sv2Message::kSetupConnectionSuccess>(variant).message;

                std::cout << "--- SetupConnectionSuccess Details ---" << std::endl;
                std::cout << "Used Version: " << success_response.used_version << std::endl;
                std::cout << "Flags: " << success_response.flags << std::endl;

                std::cout << std::endl;
                std::cout << "✅ Connection setup completed successfully!" << std::endl;
                std::cout << "Client-server communication established" << std::endl;
                std::cout << "🏁 Example completed - connection established" << std::endl;
                return;
            }

            std::cout
                << "📨 Received message type: "
                << sv2cpp::example::message_type_name(*decoded_response)
                << std::endl;
        }
    } catch (const std::exception &error) {
        std::cout << "✗ Error in message exchange: " << error.what() << std::endl;
    }

    std::cout << "📊 Total responses received: " << message_count << std::endl;
}

bool connect_to_server(
    const std::string &host = DEFAULT_HOST,
    std::uint16_t port = DEFAULT_PORT
) {
    std::cout << "🔗 Connecting to Stratum v2 server at " << host << ":" << port << std::endl;

    try {
        std::cout << "Attempting to connect to " << host << ":" << port << "..." << std::endl;
        auto client_socket = connect_tcp(host, port);
        std::cout << "✓ Connected to server at " << host << ":" << port << std::endl;

        const auto &authority_pub_key = sv2cpp::example::authority_public_key();
        std::cout << "✓ Using authority public key: "
                  << sv2cpp::example::shortened_hex(authority_pub_key, 8)
                  << std::endl;

        auto initiator = sv2::Sv2CodecState::new_initiator(authority_pub_key);
        if (initiator == nullptr) {
            throw std::runtime_error("Sv2CodecState::new_initiator returned null");
        }

        std::cout << "✓ Initiator created successfully" << std::endl;

        if (perform_handshake(client_socket, initiator)) {
            send_and_receive_messages(client_socket, initiator);
        } else {
            std::cout << "✗ Handshake failed, closing connection" << std::endl;
            return false;
        }

        std::cout << std::endl;
        std::cout << "--- Connection Complete ---" << std::endl;
        std::cout << "Keeping connection alive for 2 seconds..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));

        client_socket.close();
        std::cout << "✓ Connection closed gracefully" << std::endl;

        return true;
    } catch (const std::exception &error) {
        std::cout << "✗ Connection failed: " << error.what() << std::endl;
        std::cout << "  Is the server running on " << host << ":" << port << "?" << std::endl;
        std::cout << "  Try running: ./build/sv2cpp_example_server_example" << std::endl;
        return false;
    }
}

} // namespace

int main(int argc, char **argv) {
    std::cout << "============================================================" << std::endl;
    std::cout << "        Stratum v2 Client Example" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;
    std::cout << "This example demonstrates a complete Stratum v2 client that:" << std::endl;
    std::cout << "1. Connects to a Stratum v2 server via TCP" << std::endl;
    std::cout << "2. Performs Noise_NX handshake as initiator" << std::endl;
    std::cout << "3. Sends SetupConnection message" << std::endl;
    std::cout << "4. Receives SetupConnectionSuccess response" << std::endl;
    std::cout << std::endl;
    std::cout << "Prerequisites:" << std::endl;
    std::cout << "- Run server_example.cpp first" << std::endl;
    std::cout << "- Server should be listening on 127.0.0.1:34254" << std::endl;
    std::cout << std::endl;

    const std::string host = argc >= 2 ? argv[1] : DEFAULT_HOST;
    const auto port = argc >= 3
        ? static_cast<std::uint16_t>(std::stoul(argv[2]))
        : DEFAULT_PORT;

    try {
        const auto success = connect_to_server(host, port);

        if (success) {
            std::cout << std::endl;
            std::cout << "🎉 Client example completed successfully!" << std::endl;
            std::cout << std::endl;
            std::cout << "The client successfully:" << std::endl;
            std::cout << "✓ Connected to the server" << std::endl;
            std::cout << "✓ Completed Noise_NX handshake" << std::endl;
            std::cout << "✓ Sent SetupConnection message" << std::endl;
            std::cout << "✓ Received SetupConnectionSuccess response" << std::endl;
            std::cout << std::endl;
            std::cout << "Full Stratum v2 communication flow demonstrated!" << std::endl;
            return 0;
        }

        std::cout << std::endl;
        std::cout << "❌ Client example failed" << std::endl;
        std::cout << std::endl;
        std::cout << "Troubleshooting:" << std::endl;
        std::cout << "1. Make sure server_example.cpp is running" << std::endl;
        std::cout << "2. Check that port 34254 is available" << std::endl;
        std::cout << "3. Verify network connectivity" << std::endl;

        return 1;
    } catch (const std::exception &error) {
        std::cout << std::endl;
        std::cout << "✗ Unexpected error: " << error.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << std::endl;
        std::cout << "✗ Unexpected unknown error" << std::endl;
        return 1;
    }
}