#pragma once

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <utility>
#include <variant>
#include <vector>

#include "sv2.hpp"

namespace sv2cpp::test {

class TestFailure : public std::runtime_error {
public:
    explicit TestFailure(const std::string &message)
        : std::runtime_error(message) {}
};

inline void require(bool condition, const std::string &message) {
    if (!condition) {
        throw TestFailure(message);
    }
}

template <typename T, typename U>
inline void require_eq(const T &actual, const U &expected, const std::string &message) {
    if (!(actual == expected)) {
        std::ostringstream oss;
        oss << message << " (actual=" << actual << ", expected=" << expected << ")";
        throw TestFailure(oss.str());
    }
}

template <typename T, typename U>
inline void require_ne(const T &actual, const U &expected, const std::string &message) {
    if (!(actual != expected)) {
        throw TestFailure(message);
    }
}

inline std::string hex(const std::vector<uint8_t> &bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (const auto byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

inline std::string shortened_hex(const std::vector<uint8_t> &bytes, std::size_t max_bytes = 16) {
    const auto end = bytes.begin() + static_cast<std::ptrdiff_t>(std::min(bytes.size(), max_bytes));
    std::vector<uint8_t> shortened(bytes.begin(), end);

    auto out = hex(shortened);
    if (bytes.size() > max_bytes) {
        out += "...";
    }

    return out;
}

inline std::vector<uint8_t> repeated_byte(uint8_t value, std::size_t count) {
    return std::vector<uint8_t>(count, value);
}

inline const std::vector<uint8_t> &authority_public_key() {
    // Authority public key bytes used by the SV2 Noise_NX examples.
    static const std::vector<uint8_t> key = {
        36, 238, 60, 56, 4, 161, 170, 164,
        192, 59, 128, 234, 25, 247, 165, 134,
        60, 145, 110, 137, 148, 183, 219, 148,
        163, 186, 215, 238, 9, 43, 108, 231,
    };

    return key;
}

inline const std::vector<uint8_t> &authority_private_key() {
    // Authority private key bytes used by the SV2 Noise_NX examples.
    static const std::vector<uint8_t> key = {
        101, 153, 94, 177, 150, 49, 244, 120,
        164, 111, 250, 92, 241, 229, 69, 9,
        30, 254, 149, 14, 174, 172, 116, 130,
        255, 220, 6, 235, 106, 137, 246, 151,
    };

    return key;
}

struct CompletedHandshake {
    std::shared_ptr<sv2::Sv2CodecState> initiator;
    std::shared_ptr<sv2::Sv2CodecState> responder;
};

inline CompletedHandshake complete_handshake() {
    auto initiator = sv2::Sv2CodecState::new_initiator(authority_public_key());
    auto responder = sv2::Sv2CodecState::new_responder(
        authority_public_key(),
        authority_private_key(),
        86400
    );

    const auto step_0_frame = initiator->step_0();
    require(!step_0_frame.empty(), "handshake step_0 returned an empty frame");

    const auto step_1_frame = responder->step_1(step_0_frame);
    require(!step_1_frame.empty(), "handshake step_1 returned an empty frame");

    initiator->step_2(step_1_frame);

    require(initiator->handshake_complete(), "initiator handshake did not complete");
    require(responder->handshake_complete(), "responder handshake did not complete");

    return CompletedHandshake{
        .initiator = initiator,
        .responder = responder,
    };
}

inline sv2::SetupConnection make_setup_connection(
    const std::string &endpoint_host = "test.example.com",
    uint16_t endpoint_port = 4444
) {
    return sv2::SetupConnection{
        .protocol = 1,
        .min_version = 2,
        .max_version = 2,
        .flags = 0,
        .endpoint_host = endpoint_host,
        .endpoint_port = endpoint_port,
        .vendor = "Test Miner",
        .hardware_version = "v1.0",
        .firmware = "test-1.0.0",
        .device_id = "test-device",
    };
}

inline sv2::Sv2Message make_setup_connection_message(
    const std::string &endpoint_host = "test.example.com",
    uint16_t endpoint_port = 4444
) {
    return sv2::Sv2Message(
        sv2::Sv2Message::kSetupConnection{
            .message = make_setup_connection(endpoint_host, endpoint_port),
        }
    );
}

inline sv2::SetupConnectionSuccess make_setup_connection_success(
    uint16_t used_version = 2,
    uint32_t flags = 0
) {
    return sv2::SetupConnectionSuccess{
        .used_version = used_version,
        .flags = flags,
    };
}

inline sv2::Sv2Message make_setup_connection_success_message(
    uint16_t used_version = 2,
    uint32_t flags = 0
) {
    return sv2::Sv2Message(
        sv2::Sv2Message::kSetupConnectionSuccess{
            .message = make_setup_connection_success(used_version, flags),
        }
    );
}

inline bool is_missing_bytes_error(const std::exception &error) {
    const std::string type_name = typeid(error).name();
    const std::string what = error.what();

    return type_name.find("MissingBytes") != std::string::npos ||
           what.find("MissingBytes") != std::string::npos ||
           what.find("missing bytes") != std::string::npos ||
           what.find("missing_bytes") != std::string::npos;
}

inline sv2::Sv2Message decode_from_stream(
    const std::vector<uint8_t> &stream,
    const std::shared_ptr<sv2::Sv2CodecState> &state,
    std::size_t max_iterations = 16
) {
    auto decoder = sv2::Sv2Decoder::init();

    std::size_t offset = 0;

    for (std::size_t iteration = 0; iteration < max_iterations; ++iteration) {
        const auto buffer_size = decoder->buffer_size();

        if (buffer_size == 0) {
            try {
                return decoder->try_decode({}, state);
            } catch (const std::exception &error) {
                if (is_missing_bytes_error(error)) {
                    continue;
                }

                throw;
            }
        }

        require(
            offset + buffer_size <= stream.size(),
            "decoder requested more bytes than remain in the stream"
        );

        const std::vector<uint8_t> chunk(
            stream.begin() + static_cast<std::ptrdiff_t>(offset),
            stream.begin() + static_cast<std::ptrdiff_t>(offset + buffer_size)
        );
        offset += buffer_size;

        try {
            return decoder->try_decode(chunk, state);
        } catch (const std::exception &error) {
            if (is_missing_bytes_error(error)) {
                continue;
            }

            throw;
        }
    }

    throw TestFailure("decoder did not produce a message before max_iterations was reached");
}

inline sv2::Sv2Message encode_then_decode(
    const sv2::Sv2Message &message,
    const std::shared_ptr<sv2::Sv2CodecState> &encoder_state,
    const std::shared_ptr<sv2::Sv2CodecState> &decoder_state
) {
    auto encoder = sv2::Sv2Encoder::init();

    const auto encoded_frame = encoder->encode(message, encoder_state);
    require(!encoded_frame.empty(), "encoder produced an empty frame");

    return decode_from_stream(encoded_frame, decoder_state);
}

template <typename Variant>
inline bool is_variant(const sv2::Sv2Message &message) {
    return std::holds_alternative<Variant>(message.get_variant());
}

template <typename Variant>
inline const Variant &get_variant(const sv2::Sv2Message &message, const std::string &message_type_name) {
    require(
        std::holds_alternative<Variant>(message.get_variant()),
        "expected decoded message variant " + message_type_name
    );

    return std::get<Variant>(message.get_variant());
}

inline const sv2::SetupConnection &get_setup_connection(const sv2::Sv2Message &message) {
    return get_variant<sv2::Sv2Message::kSetupConnection>(
        message,
        "SetupConnection"
    ).message;
}

inline const sv2::SetupConnectionSuccess &get_setup_connection_success(const sv2::Sv2Message &message) {
    return get_variant<sv2::Sv2Message::kSetupConnectionSuccess>(
        message,
        "SetupConnectionSuccess"
    ).message;
}

inline void print_success(const std::string &test_name) {
    std::cout << "✓ " << test_name << " passed" << std::endl;
}

inline int run_test(const std::string &test_name, const std::function<void()> &test_body) {
    try {
        test_body();
        print_success(test_name);
        return 0;
    } catch (const TestFailure &error) {
        std::cerr << "✗ " << test_name << " failed: " << error.what() << std::endl;
        return 1;
    } catch (const std::exception &error) {
        std::cerr << "✗ " << test_name << " failed with exception: " << error.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "✗ " << test_name << " failed with an unknown exception" << std::endl;
        return 1;
    }
}

} // namespace sv2cpp::test