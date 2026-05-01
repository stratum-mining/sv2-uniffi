/*
 * Stratum v2 Server Example
 *
 * This example demonstrates how to create a TCP server that:
 * 1. Listens for incoming connections
 * 2. Performs Noise_NX handshake as a responder
 * 3. Receives and decodes Stratum v2 messages
 * 4. Responds with SetupConnectionSuccess to SetupConnection messages
 * 5. Prints other messages as they are received
 *
 * Run this server, then use client_example.cpp to connect and send messages.
 */

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <variant>
#include <vector>

#include "example_utils.hpp"
#include "tcp_utils.hpp"
#include "sv2.hpp"

namespace {

constexpr const char *DEFAULT_HOST = "0.0.0.0";
constexpr std::uint16_t DEFAULT_PORT = 34254;
constexpr std::size_t HANDSHAKE_INITIATOR_FRAME_SIZE = 64;
constexpr int LISTEN_BACKLOG = 5;

using sv2cpp::example::tcp::TcpSocket;
using sv2cpp::example::tcp::recv_exact;
using sv2cpp::example::tcp::send_all;
using sv2cpp::example::tcp::socket_error_message;

volatile std::sig_atomic_t shutdown_requested = 0;

void handle_signal(int) {
    shutdown_requested = 1;
}



TcpSocket create_server_socket(const std::string &host, std::uint16_t port) {
    TcpSocket server_socket(::socket(AF_INET, SOCK_STREAM, 0));

    if (!server_socket.valid()) {
        throw std::runtime_error(socket_error_message("Failed to create server socket"));
    }

    int reuse_address = 1;
    if (::setsockopt(
            server_socket.fd(),
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse_address,
            sizeof(reuse_address)
        ) < 0) {
        throw std::runtime_error(socket_error_message("Failed to set SO_REUSEADDR"));
    }

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    if (::inet_pton(AF_INET, host.c_str(), &server_address.sin_addr) != 1) {
        throw std::runtime_error("Server host must be an IPv4 address for this example");
    }

    if (::bind(
            server_socket.fd(),
            reinterpret_cast<sockaddr *>(&server_address),
            sizeof(server_address)
        ) < 0) {
        throw std::runtime_error(socket_error_message("Failed to bind server socket"));
    }

    if (::listen(server_socket.fd(), LISTEN_BACKLOG) < 0) {
        throw std::runtime_error(socket_error_message("Failed to listen on server socket"));
    }

    return server_socket;
}

bool perform_handshake(
    TcpSocket &client_socket,
    const std::shared_ptr<sv2::Sv2CodecState> &responder
) {
    try {
        std::cout << "--- Starting Handshake as Responder ---" << std::endl;

        std::cout << "Step 1: Waiting for initiator's ephemeral public key..." << std::endl;
        const auto step_0_data = recv_exact(
            client_socket.fd(),
            HANDSHAKE_INITIATOR_FRAME_SIZE
        );

        std::cout << "✓ Received step 0 frame: " << step_0_data.size() << " bytes" << std::endl;
        std::cout << "  Ephemeral key: "
                  << sv2cpp::example::shortened_hex(step_0_data)
                  << std::endl;

        std::cout << "Step 2: Processing initiator frame and sending response..." << std::endl;
        const auto step_1_frame = responder->step_1(step_0_data);
        send_all(client_socket.fd(), step_1_frame);

        std::cout << "✓ Sent step 1 response: " << step_1_frame.size() << " bytes" << std::endl;
        std::cout << "  Response includes: ephemeral key + encrypted static key + signature" << std::endl;

        std::cout << "Step 3: Handshake completed" << std::endl;
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

std::optional<sv2::Sv2Message> decode_next_message(
    TcpSocket &client_socket,
    sv2::Sv2Decoder &decoder,
    const std::shared_ptr<sv2::Sv2CodecState> &responder
) {
    while (true) {
        const auto buffer_size = decoder.buffer_size();

        if (buffer_size == 0) {
            try {
                return decoder.try_decode({}, responder);
            } catch (const std::exception &error) {
                if (sv2cpp::example::is_missing_bytes_error(error)) {
                    continue;
                }

                throw;
            }
        }

        const auto data = recv_exact(client_socket.fd(), buffer_size);

        try {
            return decoder.try_decode(data, responder);
        } catch (const std::exception &error) {
            if (sv2cpp::example::is_missing_bytes_error(error)) {
                continue;
            }

            throw;
        }
    }
}

void handle_decoded_message(
    const sv2::Sv2Message &decoded_message,
    sv2::Sv2Encoder &encoder,
    const std::shared_ptr<sv2::Sv2CodecState> &responder,
    TcpSocket &client_socket,
    std::size_t message_count
) {
    const auto &variant = decoded_message.get_variant();

    if (std::holds_alternative<sv2::Sv2Message::kSetupConnection>(variant)) {
        std::cout << std::endl;
        std::cout << "🎉 Received SetupConnection Message!" << std::endl;

        const auto &setup_connection =
            std::get<sv2::Sv2Message::kSetupConnection>(variant).message;

        sv2cpp::example::print_setup_connection(setup_connection);

        std::cout << std::endl;
        std::cout << "--- Creating SetupConnectionSuccess Response ---" << std::endl;

        const auto used_version = setup_connection.max_version;
        const auto flags = setup_connection.flags;

        auto success_message = sv2::Sv2Message(
            sv2::Sv2Message::kSetupConnectionSuccess{
                .message = sv2::SetupConnectionSuccess{
                    .used_version = used_version,
                    .flags = flags,
                },
            }
        );

        std::cout << "✓ Created SetupConnectionSuccess:" << std::endl;
        std::cout << "  - Used Version: " << used_version << std::endl;
        std::cout << "  - Flags: " << flags << std::endl;

        const auto encoded_response = encoder.encode(success_message, responder);
        send_all(client_socket.fd(), encoded_response);

        std::cout
            << "✓ Sent SetupConnectionSuccess response: "
            << encoded_response.size()
            << " bytes"
            << std::endl;
        std::cout
            << "  Response data: "
            << sv2cpp::example::shortened_hex(encoded_response, 32)
            << std::endl;

        return;
    }

    std::cout
        << "📨 Received message #"
        << message_count
        << " type: "
        << sv2cpp::example::message_type_name(decoded_message)
        << std::endl;
}

void handle_messages(
    TcpSocket &client_socket,
    const std::shared_ptr<sv2::Sv2CodecState> &responder
) {
    auto decoder = sv2::Sv2Decoder::init();
    auto encoder = sv2::Sv2Encoder::init();

    if (decoder == nullptr) {
        throw std::runtime_error("Sv2Decoder::init returned null");
    }
    if (encoder == nullptr) {
        throw std::runtime_error("Sv2Encoder::init returned null");
    }

    std::cout << std::endl;
    std::cout << "--- Message Handling Phase ---" << std::endl;
    std::cout << "Waiting for encrypted messages..." << std::endl;

    std::size_t message_count = 0;

    try {
        while (!shutdown_requested) {
            const auto decoded_message = decode_next_message(
                client_socket,
                *decoder,
                responder
            );

            if (!decoded_message.has_value()) {
                continue;
            }

            message_count += 1;

            std::cout << std::endl;
            std::cout << "--- Message #" << message_count << " Decoded ---" << std::endl;

            handle_decoded_message(
                *decoded_message,
                *encoder,
                responder,
                client_socket,
                message_count
            );
        }
    } catch (const std::exception &error) {
        std::cout << "⚠ Error in message loop: " << error.what() << std::endl;
    }

    std::cout << "📊 Total messages received: " << message_count << std::endl;
}

void handle_client(TcpSocket client_socket, sockaddr_in client_address) {
    const auto client_ip = std::string(::inet_ntoa(client_address.sin_addr));
    const auto client_port = ntohs(client_address.sin_port);

    std::cout << std::endl;
    std::cout
        << "🔗 New client connected from "
        << client_ip
        << ":"
        << client_port
        << std::endl;

    try {
        const auto &authority_pub_key = sv2cpp::example::authority_public_key();
        const auto &authority_priv_key = sv2cpp::example::authority_private_key();

        std::cout << "✓ Using authority keys:" << std::endl;
        std::cout
            << "  Public key: "
            << sv2cpp::example::shortened_hex(authority_pub_key, 8)
            << std::endl;
        std::cout
            << "  Private key: "
            << sv2cpp::example::shortened_hex(authority_priv_key, 8)
            << std::endl;

        constexpr std::uint64_t cert_validity_secs = 86400;

        auto responder = sv2::Sv2CodecState::new_responder(
            authority_pub_key,
            authority_priv_key,
            cert_validity_secs
        );

        if (responder == nullptr) {
            throw std::runtime_error("Sv2CodecState::new_responder returned null");
        }

        std::cout << "✓ Responder created successfully" << std::endl;

        if (perform_handshake(client_socket, responder)) {
            handle_messages(client_socket, responder);
        } else {
            std::cout << "✗ Handshake failed, closing connection" << std::endl;
        }
    } catch (const std::exception &error) {
        std::cout << "✗ Error handling client: " << error.what() << std::endl;
    }

    client_socket.close();

    std::cout
        << "🔌 Connection closed for "
        << client_ip
        << ":"
        << client_port
        << std::endl;
}

void start_server(
    const std::string &host = DEFAULT_HOST,
    std::uint16_t port = DEFAULT_PORT
) {
    std::cout << "🚀 Starting Stratum v2 Server" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "Listening on " << host << ":" << port << std::endl;
    std::cout << "Press Ctrl+C to stop the server" << std::endl;
    std::cout << "==================================================" << std::endl;

    auto server_socket = create_server_socket(host, port);

    std::cout << "✓ Server listening on " << host << ":" << port << std::endl;

    while (!shutdown_requested) {
        sockaddr_in client_address{};
        socklen_t client_address_len = sizeof(client_address);

        const int client_fd = ::accept(
            server_socket.fd(),
            reinterpret_cast<sockaddr *>(&client_address),
            &client_address_len
        );

        if (client_fd < 0) {
            if (errno == EINTR && shutdown_requested) {
                break;
            }

            if (errno == EINTR) {
                continue;
            }

            throw std::runtime_error(socket_error_message("Failed to accept client connection"));
        }

        std::thread client_thread(
            handle_client,
            TcpSocket(client_fd),
            client_address
        );
        client_thread.detach();
    }

    server_socket.close();
    std::cout << "✓ Server socket closed" << std::endl;
}

} // namespace

int main(int argc, char **argv) {
    struct sigaction action{};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (::sigaction(SIGINT, &action, nullptr) < 0) {
        std::cout << "✗ Failed to install SIGINT handler: " << std::strerror(errno) << std::endl;
        return 1;
    }

    if (::sigaction(SIGTERM, &action, nullptr) < 0) {
        std::cout << "✗ Failed to install SIGTERM handler: " << std::strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "Stratum v2 Server Example" << std::endl;
    std::cout << "This server will:" << std::endl;
    std::cout << "1. Listen for TCP connections" << std::endl;
    std::cout << "2. Perform Noise_NX handshake as responder" << std::endl;
    std::cout << "3. Receive and decode SetupConnection messages" << std::endl;
    std::cout << std::endl;

    const std::string host = argc >= 2 ? argv[1] : DEFAULT_HOST;
    const auto port = argc >= 3
        ? static_cast<std::uint16_t>(std::stoul(argv[2]))
        : DEFAULT_PORT;

    try {
        start_server(host, port);
        return 0;
    } catch (const std::exception &error) {
        std::cout << "✗ Server failed to start: " << error.what() << std::endl;
        return 1;
    } catch (...) {
        std::cout << "✗ Server failed to start with an unknown error" << std::endl;
        return 1;
    }
}