#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include "test_utils.hpp"

int main() {
    return sv2cpp::test::run_test("Encoding/decoding test", [] {
        using namespace sv2cpp::test;

        const auto handshake = complete_handshake();

        const auto setup_message = make_setup_connection_message(
            "test.example.com",
            4444
        );

        const auto decoded_setup_message = encode_then_decode(
            setup_message,
            handshake.initiator,
            handshake.responder
        );

        const auto &decoded_setup_connection = get_setup_connection(decoded_setup_message);

        require_eq(
            decoded_setup_connection.endpoint_host,
            std::string("test.example.com"),
            "decoded SetupConnection endpoint_host did not match encoded message"
        );
        require_eq(
            decoded_setup_connection.endpoint_port,
            static_cast<uint16_t>(4444),
            "decoded SetupConnection endpoint_port did not match encoded message"
        );
        require_eq(
            decoded_setup_connection.vendor,
            std::string("Test Miner"),
            "decoded SetupConnection vendor did not match encoded message"
        );
        require_eq(
            decoded_setup_connection.hardware_version,
            std::string("v1.0"),
            "decoded SetupConnection hardware_version did not match encoded message"
        );
        require_eq(
            decoded_setup_connection.firmware,
            std::string("test-1.0.0"),
            "decoded SetupConnection firmware did not match encoded message"
        );
        require_eq(
            decoded_setup_connection.device_id,
            std::string("test-device"),
            "decoded SetupConnection device_id did not match encoded message"
        );

        const auto success_message = make_setup_connection_success_message(
            decoded_setup_connection.max_version,
            decoded_setup_connection.flags
        );

        const auto decoded_success_message = encode_then_decode(
            success_message,
            handshake.responder,
            handshake.initiator
        );

        const auto &decoded_success = get_setup_connection_success(decoded_success_message);

        require_eq(
            decoded_success.used_version,
            static_cast<uint16_t>(2),
            "decoded SetupConnectionSuccess used_version did not match encoded message"
        );
        require_eq(
            decoded_success.flags,
            0U,
            "decoded SetupConnectionSuccess flags did not match encoded message"
        );

        auto encoder = sv2::Sv2Encoder::init();
        const auto encoded_frame = encoder->encode(setup_message, handshake.initiator);

        require(
            !encoded_frame.empty(),
            "encoding SetupConnection produced an empty frame"
        );

        const auto decoded_from_stream = decode_from_stream(
            encoded_frame,
            handshake.responder
        );

        const auto &stream_setup_connection = get_setup_connection(decoded_from_stream);

        require_eq(
            stream_setup_connection.endpoint_host,
            std::string("test.example.com"),
            "stream-style decode did not preserve SetupConnection endpoint_host"
        );
    });
}