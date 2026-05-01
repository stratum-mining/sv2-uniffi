/*
 * Stratum v2 Template Distribution Example
 *
 * This example demonstrates how to create a TCP client that:
 * 1. Connects to a Stratum v2 Template Distribution Server
 * 2. Performs Noise_NX handshake as an initiator
 * 3. Sends a SetupConnection message
 * 4. Waits for SetupConnectionSuccess message
 * 5. Sends a CoinbaseOutputConstraints message
 * 6. Prints all messages it receives
 */

#include <cctype>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "example_utils.hpp"
#include "tcp_utils.hpp"
#include "sv2.hpp"

namespace {

constexpr const char *DEFAULT_HOST = "127.0.0.1";
constexpr std::uint16_t DEFAULT_TEMPLATE_DISTRIBUTION_PORT = 8442;
constexpr std::size_t HANDSHAKE_RESPONSE_BUFFER_SIZE = 4096;

using sv2cpp::example::tcp::TcpSocket;
using sv2cpp::example::tcp::connect_tcp;
using sv2cpp::example::tcp::recv_exact;
using sv2cpp::example::tcp::recv_some;
using sv2cpp::example::tcp::send_all;

std::string get_server_ip() {
    /*
     * Get template distribution server IP address from user input.
     */
    std::cout << std::endl;
    std::cout << "--- Template Distribution Server IP ---" << std::endl;
    std::cout << "Please enter the server IP address or hostname." << std::endl;
    std::cout << "Default is 127.0.0.1 (localhost)" << std::endl;
    std::cout << "Examples: 127.0.0.1, localhost, mining.example.com" << std::endl;

    while (true) {
        std::cout << "Server IP/hostname (default 127.0.0.1): ";

        std::string server_ip;
        std::getline(std::cin, server_ip);

        if (server_ip.empty()) {
            std::cout << "Using default IP: " << DEFAULT_HOST << std::endl;
            return DEFAULT_HOST;
        }

        if (server_ip.size() > 253) {
            std::cout << "Server IP/hostname too long. Please try again." << std::endl;
            continue;
        }

        std::cout << "Server IP/hostname accepted: " << server_ip << std::endl;
        return server_ip;
    }
}

std::uint16_t get_server_port() {
    /*
     * Get template distribution server port from user input.
     */
    std::cout << std::endl;
    std::cout << "--- Template Distribution Server Port ---" << std::endl;
    std::cout << "Please enter the server port number." << std::endl;
    std::cout << "Default Stratum v2 Template Distribution port is 8442" << std::endl;

    while (true) {
        std::cout << "Server port (default 8442): ";

        std::string port_input;
        std::getline(std::cin, port_input);

        if (port_input.empty()) {
            std::cout
                << "Using default port: "
                << DEFAULT_TEMPLATE_DISTRIBUTION_PORT
                << std::endl;
            return DEFAULT_TEMPLATE_DISTRIBUTION_PORT;
        }

        try {
            const auto port_long = std::stol(port_input);

            if (port_long < 1 || port_long > 65535) {
                std::cout << "Port must be between 1 and 65535. Please try again." << std::endl;
                continue;
            }

            const auto port = static_cast<std::uint16_t>(port_long);
            std::cout << "Server port accepted: " << port << std::endl;
            return port;
        } catch (const std::exception &) {
            std::cout << "Port must be a valid number. Please try again." << std::endl;
        }
    }
}

int base58_value(char c) {
    const std::string alphabet =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const auto position = alphabet.find(c);

    if (position == std::string::npos) {
        throw std::invalid_argument("invalid base58 character");
    }

    return static_cast<int>(position);
}

std::vector<std::uint8_t> decode_base58(const std::string &input) {
    /*
     * Minimal base58 decoder for this example. The Python example relies on the
     * base58 package. Here we keep the logic local so the C++ example remains a
     * standalone source file.
     */
    std::vector<std::uint8_t> bytes(1, 0);

    for (const auto c : input) {
        int carry = base58_value(c);

        for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
            const int value = (*it * 58) + carry;
            *it = static_cast<std::uint8_t>(value & 0xff);
            carry = value >> 8;
        }

        while (carry > 0) {
            bytes.insert(bytes.begin(), static_cast<std::uint8_t>(carry & 0xff));
            carry >>= 8;
        }
    }

    std::size_t leading_zeroes = 0;
    while (leading_zeroes < input.size() && input[leading_zeroes] == '1') {
        ++leading_zeroes;
    }

    auto first_non_zero = bytes.begin();
    while (first_non_zero != bytes.end() && *first_non_zero == 0) {
        ++first_non_zero;
    }

    std::vector<std::uint8_t> decoded(leading_zeroes, 0);
    decoded.insert(decoded.end(), first_non_zero, bytes.end());
    return decoded;
}

std::vector<std::uint8_t> get_authority_public_key() {
    /*
     * Get authority public key for connecting to the server.
     */
    std::cout << std::endl;
    std::cout << "--- Authority Public Key Required ---" << std::endl;
    std::cout << "Please enter the authority public key in base58 format." << std::endl;
    std::cout << "Example: 9af8kW9NvZLihSL8efV88GR6xrNwvHbef1ySBrzHP2WBHRoFo4m" << std::endl;

    while (true) {
        std::cout << "Authority public key (base58): ";

        std::string authority_pub_key_b58;
        std::getline(std::cin, authority_pub_key_b58);

        if (authority_pub_key_b58.empty()) {
            std::cout << "Authority public key cannot be empty. Please try again." << std::endl;
            continue;
        }

        try {
            // Decode from base58 to bytes and extract the 32-byte key according
            // to the SV2 spec.
            const auto pub_key_full = decode_base58(authority_pub_key_b58);

            if (pub_key_full.size() < 34) {
                std::cout
                    << "Invalid key length: "
                    << pub_key_full.size()
                    << " bytes (expected at least 34 bytes)"
                    << std::endl;
                std::cout
                    << "Please enter a valid base58 encoded authority public key."
                    << std::endl;
                continue;
            }

            const std::vector<std::uint8_t> authority_pub_key(
                pub_key_full.begin() + 2,
                pub_key_full.begin() + 34
            );

            std::cout
                << "Authority public key accepted: "
                << sv2cpp::example::shortened_hex(authority_pub_key, 8)
                << std::endl;
            return authority_pub_key;
        } catch (const std::exception &error) {
            std::cout << "Invalid base58 format: " << error.what() << std::endl;
            std::cout << "Please enter a valid base58 encoded authority public key." << std::endl;
        }
    }
}

bool perform_handshake(
    TcpSocket &client_socket,
    const std::shared_ptr<sv2::Sv2CodecState> &initiator
) {
    /*
     * Perform the 3-step Noise_NX handshake as initiator.
     *
     * Returns true if handshake is successful, false otherwise.
     */
    try {
        std::cout << "--- Starting Handshake as Initiator ---" << std::endl;

        // Step 0: Send initiator's ephemeral public key.
        std::cout << "Step 0: Sending ephemeral public key..." << std::endl;
        const auto step_0_frame = initiator->step_0();
        send_all(client_socket.fd(), step_0_frame);

        std::cout << "Sent step 0 frame: " << step_0_frame.size() << " bytes" << std::endl;
        std::cout << "  Ephemeral key: "
                  << sv2cpp::example::shortened_hex(step_0_frame)
                  << std::endl;

        // Step 1: Receive responder's response.
        std::cout << "Step 1: Waiting for responder's response..." << std::endl;
        const auto step_1_data = recv_some(
            client_socket.fd(),
            HANDSHAKE_RESPONSE_BUFFER_SIZE
        );

        std::cout << "Received step 1 response: " << step_1_data.size() << " bytes" << std::endl;
        std::cout << "  Response includes: ephemeral key + encrypted static key + signature" << std::endl;

        // Step 2: Complete handshake.
        std::cout << "Step 2: Completing handshake..." << std::endl;
        initiator->step_2(step_1_data);

        std::cout << "Handshake completed successfully" << std::endl;
        std::cout << "Secure channel established" << std::endl;
        return true;
    } catch (const sv2::Sv2CodecError &error) {
        std::cout << "Handshake failed with codec error: " << error.what() << std::endl;
        return false;
    } catch (const std::exception &error) {
        std::cout << "Handshake failed with error: " << error.what() << std::endl;
        return false;
    }
}

sv2::Sv2Message create_setup_connection_message() {
    /*
     * Create a SetupConnection message to send to the server.
     */
    std::cout << std::endl;
    std::cout << "--- Creating SetupConnection Message ---" << std::endl;

    const auto setup_connection = sv2::SetupConnection{
        .protocol = 2,
        .min_version = 2,
        .max_version = 2,
        .flags = 0,
        .endpoint_host = "template-client.example.com",
        .endpoint_port = 0,
        .vendor = "Template Distribution Client",
        .hardware_version = "v1.0.0",
        .firmware = "cpp-template-client-1.0",
        .device_id = "template-client-001",
    };

    // Create the message using the UniFFI-generated C++ enum wrapper.
    return sv2::Sv2Message(
        sv2::Sv2Message::kSetupConnection{
            .message = setup_connection,
        }
    );
}

sv2::Sv2Message create_coinbase_output_constraints_message() {
    /*
     * Create a CoinbaseOutputConstraints message to send to the server.
     */
    std::cout << std::endl;
    std::cout << "--- Creating CoinbaseOutputConstraints Message ---" << std::endl;

    // Create CoinbaseOutputConstraints with typical mining constraints.
    const auto coinbase_constraints = sv2::CoinbaseOutputConstraints{
        .coinbase_output_max_additional_size = 32,
        .coinbase_output_max_additional_sigops = 4,
    };

    std::cout << "Created CoinbaseOutputConstraints message:" << std::endl;
    std::cout
        << "  - Max Additional Size: "
        << coinbase_constraints.coinbase_output_max_additional_size
        << " bytes"
        << std::endl;
    std::cout
        << "  - Max Additional Sigops: "
        << coinbase_constraints.coinbase_output_max_additional_sigops
        << std::endl;

    // Create the message using the UniFFI-generated C++ enum wrapper.
    return sv2::Sv2Message(
        sv2::Sv2Message::kCoinbaseOutputConstraints{
            .message = coinbase_constraints,
        }
    );
}

std::optional<sv2::Sv2Message> decode_next_message(
    TcpSocket &client_socket,
    sv2::Sv2Decoder &decoder,
    const std::shared_ptr<sv2::Sv2CodecState> &initiator
) {
    while (true) {
        // Get the size of buffer that needs to be filled.
        const auto buffer_size = decoder.buffer_size();

        if (buffer_size == 0) {
            try {
                // If buffer_size is 0, call try_decode with empty data to
                // trigger the initial buffer size calculation.
                return decoder.try_decode({}, initiator);
            } catch (const std::exception &error) {
                if (sv2cpp::example::is_missing_bytes_error(error)) {
                    continue;
                }

                throw;
            }
        }

        // Read exactly the number of bytes the decoder needs.
        const auto data = recv_exact(client_socket.fd(), buffer_size);

        try {
            return decoder.try_decode(data, initiator);
        } catch (const std::exception &error) {
            if (sv2cpp::example::is_missing_bytes_error(error)) {
                // Decoder needs more data, so check buffer_size again.
                continue;
            }

            throw;
        }
    }
}

void send_setup_connection_and_coinbase_output_constraints_messages(
    TcpSocket &client_socket,
    const std::shared_ptr<sv2::Sv2CodecState> &initiator,
    sv2::Sv2Encoder &encoder,
    sv2::Sv2Decoder &decoder
) {
    /*
     * Send SetupConnection message first, then CoinbaseOutputConstraints.
     */
    std::cout << std::endl;
    std::cout << "--- Message Exchange Phase ---" << std::endl;

    // Step 1: Create and send SetupConnection message.
    const auto setup_message = create_setup_connection_message();

    std::cout << std::endl;
    std::cout << "--- Encoding and Sending SetupConnection ---" << std::endl;
    const auto setup_encoded_frame = encoder.encode(setup_message, initiator);
    std::cout
        << "SetupConnection encoded successfully: "
        << setup_encoded_frame.size()
        << " bytes"
        << std::endl;
    std::cout
        << "  Encoded frame: "
        << sv2cpp::example::shortened_hex(setup_encoded_frame, 32)
        << std::endl;

    send_all(client_socket.fd(), setup_encoded_frame);
    std::cout << "SetupConnection message sent to server" << std::endl;

    std::cout << std::endl;
    std::cout << "--- SetupConnection Message Details ---" << std::endl;
    std::cout << "Message Type: SetupConnection" << std::endl;
    std::cout << "Message Size: " << setup_encoded_frame.size() << " bytes" << std::endl;
    std::cout << "Encoded Data: " << sv2cpp::example::hex(setup_encoded_frame) << std::endl;

    // Wait for SetupConnectionSuccess response.
    std::cout << std::endl;
    std::cout << "--- Waiting for SetupConnectionSuccess Response ---" << std::endl;
    while (true) {
        const auto decoded_response = decode_next_message(
            client_socket,
            decoder,
            initiator
        );

        if (!decoded_response.has_value()) {
            continue;
        }

        const auto &variant = decoded_response->get_variant();
        if (std::holds_alternative<sv2::Sv2Message::kSetupConnectionSuccess>(variant)) {
            std::cout << "Received SetupConnectionSuccess!" << std::endl;
            break;
        }

        std::cout
            << "Received unexpected response: "
            << sv2cpp::example::message_type_name(*decoded_response)
            << std::endl;
        return;
    }

    // Step 2: Create and send CoinbaseOutputConstraints message.
    const auto constraints_message = create_coinbase_output_constraints_message();

    std::cout << std::endl;
    std::cout << "--- Encoding and Sending CoinbaseOutputConstraints ---" << std::endl;
    std::cout << "Codec state before encoding:" << std::endl;
    std::cout
        << "  - Handshake complete: "
        << (initiator->handshake_complete() ? "true" : "false")
        << std::endl;

    const auto constraints_encoded_frame = encoder.encode(
        constraints_message,
        initiator
    );
    std::cout
        << "CoinbaseOutputConstraints encoded successfully: "
        << constraints_encoded_frame.size()
        << " bytes"
        << std::endl;
    std::cout
        << "  Encoded frame: "
        << sv2cpp::example::shortened_hex(constraints_encoded_frame, 32)
        << std::endl;

    send_all(client_socket.fd(), constraints_encoded_frame);
    std::cout << "CoinbaseOutputConstraints message sent to server" << std::endl;
}

void listen_for_messages(
    TcpSocket &client_socket,
    const std::shared_ptr<sv2::Sv2CodecState> &initiator,
    sv2::Sv2Decoder &decoder
) {
    /*
     * Continuously listen for incoming messages and print them to terminal.
     */
    std::cout << std::endl;
    std::cout << "--- Listening for Incoming Messages ---" << std::endl;
    std::cout << "Blocking and waiting for messages from server... (Press Ctrl+C to stop)" << std::endl;

    std::size_t message_count = 0;

    while (true) {
        const auto decoded_message = decode_next_message(
            client_socket,
            decoder,
            initiator
        );

        if (!decoded_message.has_value()) {
            continue;
        }

        ++message_count;

        std::cout << std::endl;
        std::cout << "--- Message #" << message_count << " Decoded ---" << std::endl;
        std::cout
            << "Message type: "
            << sv2cpp::example::message_type_name(*decoded_message)
            << std::endl;

        const auto &variant = decoded_message->get_variant();

        if (std::holds_alternative<sv2::Sv2Message::kNewTemplate>(variant)) {
            std::cout << "NEW_TEMPLATE message received" << std::endl;

            // Access message data from the enum variant.
            const auto &template_data =
                std::get<sv2::Sv2Message::kNewTemplate>(variant).message;

            std::cout << "  - Template ID: " << template_data.template_id << std::endl;
            std::cout
                << "  - Future template: "
                << (template_data.future_template ? "true" : "false")
                << std::endl;
            std::cout << "  - Version: " << template_data.version << std::endl;
            std::cout
                << "  - Coinbase value remaining: "
                << template_data.coinbase_tx_value_remaining
                << std::endl;
            std::cout
                << "  - Merkle path nodes: "
                << template_data.merkle_path.size()
                << std::endl;

            for (std::size_t i = 0; i < template_data.merkle_path.size(); ++i) {
                const auto &path_node = template_data.merkle_path[i];
                std::vector<std::uint8_t> reversed(path_node.rbegin(), path_node.rend());
                std::cout
                    << "    ["
                    << i
                    << "]: "
                    << sv2cpp::example::hex(reversed)
                    << std::endl;
            }
        } else if (std::holds_alternative<sv2::Sv2Message::kSetNewPrevHashTemplateDistribution>(variant)) {
            std::cout << "SET_NEW_PREV_HASH_TEMPLATE_DISTRIBUTION message received" << std::endl;

            // Access message data from the enum variant.
            const auto &prev_hash_data =
                std::get<sv2::Sv2Message::kSetNewPrevHashTemplateDistribution>(variant).message;

            std::vector<std::uint8_t> reversed_prev_hash(
                prev_hash_data.prev_hash.rbegin(),
                prev_hash_data.prev_hash.rend()
            );

            std::cout << "  - Template ID: " << prev_hash_data.template_id << std::endl;
            std::cout
                << "  - PrevHash: "
                << sv2cpp::example::hex(reversed_prev_hash)
                << std::endl;
            std::cout
                << "  - Header timestamp: "
                << prev_hash_data.header_timestamp
                << std::endl;
        } else {
            // For other message types, print only the type.
            std::cout
                << "Other message type: "
                << sv2cpp::example::message_type_name(*decoded_message)
                << std::endl;
        }
    }
}

bool connect_to_server(
    const std::string &host,
    std::uint16_t port,
    const std::vector<std::uint8_t> &authority_pub_key
) {
    /*
     * Connect to the Stratum v2 server and perform the complete communication
     * flow.
     */
    std::cout
        << "Connecting to Stratum v2 server at "
        << host
        << ":"
        << port
        << std::endl;
    std::cout << "This example sends a CoinbaseOutputConstraints message" << std::endl;

    try {
        std::cout << "Attempting to connect to " << host << ":" << port << "..." << std::endl;
        auto client_socket = connect_tcp(host, port);
        std::cout << "Connected to server at " << host << ":" << port << std::endl;

        std::cout
            << "Using authority public key: "
            << sv2cpp::example::shortened_hex(authority_pub_key, 8)
            << std::endl;

        // Create initiator.
        auto initiator = sv2::Sv2CodecState::new_initiator(authority_pub_key);
        if (initiator == nullptr) {
            throw std::runtime_error("Sv2CodecState::new_initiator returned null");
        }
        std::cout << "Initiator created successfully" << std::endl;

        // Create a single encoder/decoder pair for the entire session.
        auto encoder = sv2::Sv2Encoder::init();
        auto decoder = sv2::Sv2Decoder::init();

        if (encoder == nullptr) {
            throw std::runtime_error("Sv2Encoder::init returned null");
        }
        if (decoder == nullptr) {
            throw std::runtime_error("Sv2Decoder::init returned null");
        }

        std::cout << "Encoder and decoder created successfully" << std::endl;

        // Perform handshake.
        if (perform_handshake(client_socket, initiator)) {
            // Send SetupConnection and CoinbaseOutputConstraints messages after
            // successful handshake.
            send_setup_connection_and_coinbase_output_constraints_messages(
                client_socket,
                initiator,
                *encoder,
                *decoder
            );

            // Start listening for messages from the server using the same
            // decoder.
            listen_for_messages(client_socket, initiator, *decoder);
        } else {
            std::cout << "Handshake failed, closing connection" << std::endl;
            return false;
        }

        // Connection cleanup. In practice this line is only reached if the
        // listening loop exits because the connection closes or an exception is
        // thrown.
        std::cout << std::endl;
        std::cout << "--- Connection Complete ---" << std::endl;
        client_socket.close();
        std::cout << "Connection closed gracefully" << std::endl;
        return true;
    } catch (const std::exception &error) {
        std::cout << "Connection failed: " << error.what() << std::endl;
        std::cout << "Make sure the Template Distribution Server is running and the authority public key is correct." << std::endl;
        return false;
    }
}

} // namespace

int main(int argc, char **argv) {
    try {
        std::string server_ip;
        std::uint16_t server_port = DEFAULT_TEMPLATE_DISTRIBUTION_PORT;
        std::vector<std::uint8_t> authority_pub_key;

        if (argc >= 4) {
            // Non-interactive form:
            // ./sv2cpp_example_template_distribution_example HOST PORT AUTHORITY_PUBKEY_BASE58
            server_ip = argv[1];
            const auto port_long = std::stol(argv[2]);
            if (port_long < 1 || port_long > 65535) {
                throw std::invalid_argument("port must be between 1 and 65535");
            }
            server_port = static_cast<std::uint16_t>(port_long);

            const auto pub_key_full = decode_base58(argv[3]);
            if (pub_key_full.size() < 34) {
                throw std::invalid_argument("authority public key must decode to at least 34 bytes");
            }
            authority_pub_key.assign(
                pub_key_full.begin() + 2,
                pub_key_full.begin() + 34
            );
        } else {
            // Interactive form, matching the Python example.
            server_ip = get_server_ip();
            server_port = get_server_port();
            authority_pub_key = get_authority_public_key();
        }

        const auto success = connect_to_server(
            server_ip,
            server_port,
            authority_pub_key
        );

        if (success) {
            std::cout << std::endl;
            std::cout << "Template Distribution Example completed successfully!" << std::endl;
        } else {
            std::cout << std::endl;
            std::cout << "Template Distribution Example failed" << std::endl;
        }

        return success ? 0 : 1;
    } catch (const std::exception &error) {
        std::cerr << "Unexpected error in example: " << error.what() << std::endl;
        return 1;
    }
}
