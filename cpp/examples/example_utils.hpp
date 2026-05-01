#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <variant>
#include <vector>

#include "sv2.hpp"

namespace sv2cpp::example {

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

inline std::vector<uint8_t> repeated_byte(uint8_t value, std::size_t count) {
    return std::vector<uint8_t>(count, value);
}

inline uint8_t hex_nibble(char c) {
    const auto value = static_cast<unsigned char>(c);

    if (value >= '0' && value <= '9') {
        return static_cast<uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<uint8_t>(10 + value - 'a');
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<uint8_t>(10 + value - 'A');
    }

    throw std::invalid_argument("invalid hex character");
}

inline std::vector<uint8_t> bytes_from_hex(const std::string &hex_string) {
    std::string compact;
    compact.reserve(hex_string.size());

    for (const auto c : hex_string) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            compact.push_back(c);
        }
    }

    if (compact.size() % 2 != 0) {
        throw std::invalid_argument("hex string must contain an even number of characters");
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(compact.size() / 2);

    for (std::size_t i = 0; i < compact.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(
            (hex_nibble(compact[i]) << 4) | hex_nibble(compact[i + 1])
        ));
    }

    return bytes;
}

inline std::string hex(const std::vector<uint8_t> &bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (const auto byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

inline std::string shortened_hex(
    const std::vector<uint8_t> &bytes,
    std::size_t max_bytes = 16
) {
    const auto copied_bytes = std::min(bytes.size(), max_bytes);
    const std::vector<uint8_t> shortened(
        bytes.begin(),
        bytes.begin() + static_cast<std::ptrdiff_t>(copied_bytes)
    );

    auto out = hex(shortened);
    if (bytes.size() > max_bytes) {
        out += "...";
    }

    return out;
}

inline void print_bytes(
    const std::string &label,
    const std::vector<uint8_t> &bytes,
    std::size_t max_bytes = 16
) {
    std::cout
        << label << ": "
        << shortened_hex(bytes, max_bytes)
        << " (" << bytes.size() << " bytes)"
        << std::endl;
}

inline bool is_missing_bytes_error(const std::exception &error) {
    const std::string type_name = typeid(error).name();
    const std::string what = error.what();

    return type_name.find("MissingBytes") != std::string::npos ||
           what.find("MissingBytes") != std::string::npos ||
           what.find("missing bytes") != std::string::npos ||
           what.find("missing_bytes") != std::string::npos;
}

inline std::string message_type_name(const sv2::Sv2Message &message) {
    const auto &variant = message.get_variant();

    if (std::holds_alternative<sv2::Sv2Message::kSetupConnection>(variant)) {
        return "SetupConnection";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetupConnectionSuccess>(variant)) {
        return "SetupConnectionSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetupConnectionError>(variant)) {
        return "SetupConnectionError";
    }
    if (std::holds_alternative<sv2::Sv2Message::kChannelEndpointChanged>(variant)) {
        return "ChannelEndpointChanged";
    }
    if (std::holds_alternative<sv2::Sv2Message::kReconnect>(variant)) {
        return "Reconnect";
    }
    if (std::holds_alternative<sv2::Sv2Message::kOpenStandardMiningChannel>(variant)) {
        return "OpenStandardMiningChannel";
    }
    if (std::holds_alternative<sv2::Sv2Message::kOpenStandardMiningChannelSuccess>(variant)) {
        return "OpenStandardMiningChannelSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kOpenExtendedMiningChannel>(variant)) {
        return "OpenExtendedMiningChannel";
    }
    if (std::holds_alternative<sv2::Sv2Message::kOpenExtendedMiningChannelSuccess>(variant)) {
        return "OpenExtendedMiningChannelSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kOpenMiningChannelError>(variant)) {
        return "OpenMiningChannelError";
    }
    if (std::holds_alternative<sv2::Sv2Message::kUpdateChannel>(variant)) {
        return "UpdateChannel";
    }
    if (std::holds_alternative<sv2::Sv2Message::kUpdateChannelError>(variant)) {
        return "UpdateChannelError";
    }
    if (std::holds_alternative<sv2::Sv2Message::kCloseChannel>(variant)) {
        return "CloseChannel";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetExtranoncePrefix>(variant)) {
        return "SetExtranoncePrefix";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSubmitSharesStandard>(variant)) {
        return "SubmitSharesStandard";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSubmitSharesExtended>(variant)) {
        return "SubmitSharesExtended";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSubmitSharesSuccess>(variant)) {
        return "SubmitSharesSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSubmitSharesError>(variant)) {
        return "SubmitSharesError";
    }
    if (std::holds_alternative<sv2::Sv2Message::kNewMiningJob>(variant)) {
        return "NewMiningJob";
    }
    if (std::holds_alternative<sv2::Sv2Message::kNewExtendedMiningJob>(variant)) {
        return "NewExtendedMiningJob";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetNewPrevHashMining>(variant)) {
        return "SetNewPrevHashMining";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetCustomMiningJob>(variant)) {
        return "SetCustomMiningJob";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetCustomMiningJobSuccess>(variant)) {
        return "SetCustomMiningJobSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetCustomMiningJobError>(variant)) {
        return "SetCustomMiningJobError";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetTarget>(variant)) {
        return "SetTarget";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetGroupChannel>(variant)) {
        return "SetGroupChannel";
    }
    if (std::holds_alternative<sv2::Sv2Message::kAllocateMiningJobToken>(variant)) {
        return "AllocateMiningJobToken";
    }
    if (std::holds_alternative<sv2::Sv2Message::kAllocateMiningJobTokenSuccess>(variant)) {
        return "AllocateMiningJobTokenSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kDeclareMiningJob>(variant)) {
        return "DeclareMiningJob";
    }
    if (std::holds_alternative<sv2::Sv2Message::kDeclareMiningJobSuccess>(variant)) {
        return "DeclareMiningJobSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kDeclareMiningJobError>(variant)) {
        return "DeclareMiningJobError";
    }
    if (std::holds_alternative<sv2::Sv2Message::kProvideMissingTransactions>(variant)) {
        return "ProvideMissingTransactions";
    }
    if (std::holds_alternative<sv2::Sv2Message::kProvideMissingTransactionsSuccess>(variant)) {
        return "ProvideMissingTransactionsSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kPushSolution>(variant)) {
        return "PushSolution";
    }
    if (std::holds_alternative<sv2::Sv2Message::kCoinbaseOutputConstraints>(variant)) {
        return "CoinbaseOutputConstraints";
    }
    if (std::holds_alternative<sv2::Sv2Message::kNewTemplate>(variant)) {
        return "NewTemplate";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetNewPrevHashTemplateDistribution>(variant)) {
        return "SetNewPrevHashTemplateDistribution";
    }
    if (std::holds_alternative<sv2::Sv2Message::kRequestTransactionData>(variant)) {
        return "RequestTransactionData";
    }
    if (std::holds_alternative<sv2::Sv2Message::kRequestTransactionDataSuccess>(variant)) {
        return "RequestTransactionDataSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kRequestTransactionDataError>(variant)) {
        return "RequestTransactionDataError";
    }
    if (std::holds_alternative<sv2::Sv2Message::kSubmitSolution>(variant)) {
        return "SubmitSolution";
    }
    if (std::holds_alternative<sv2::Sv2Message::kRequestExtensions>(variant)) {
        return "RequestExtensions";
    }
    if (std::holds_alternative<sv2::Sv2Message::kRequestExtensionsSuccess>(variant)) {
        return "RequestExtensionsSuccess";
    }
    if (std::holds_alternative<sv2::Sv2Message::kRequestExtensionsError>(variant)) {
        return "RequestExtensionsError";
    }

    return "Unknown";
}

inline sv2::Sv2Message decode_from_stream(
    sv2::Sv2Decoder &decoder,
    const std::vector<uint8_t> &stream,
    const std::shared_ptr<sv2::Sv2CodecState> &state,
    std::size_t max_iterations = 16
) {
    std::size_t offset = 0;

    for (std::size_t iteration = 0; iteration < max_iterations; ++iteration) {
        const auto buffer_size = decoder.buffer_size();

        if (buffer_size == 0) {
            try {
                return decoder.try_decode({}, state);
            } catch (const std::exception &error) {
                if (is_missing_bytes_error(error)) {
                    continue;
                }

                throw;
            }
        }

        if (offset + buffer_size > stream.size()) {
            std::ostringstream oss;
            oss
                << "decoder requested " << buffer_size
                << " bytes, but only " << (stream.size() - offset)
                << " bytes remain in the stream";

            throw std::runtime_error(oss.str());
        }

        const std::vector<uint8_t> chunk(
            stream.begin() + static_cast<std::ptrdiff_t>(offset),
            stream.begin() + static_cast<std::ptrdiff_t>(offset + buffer_size)
        );
        offset += buffer_size;

        try {
            return decoder.try_decode(chunk, state);
        } catch (const std::exception &error) {
            if (is_missing_bytes_error(error)) {
                continue;
            }

            throw;
        }
    }

    throw std::runtime_error("decoder did not produce a message before max_iterations was reached");
}

inline sv2::Sv2Message decode_from_stream(
    const std::vector<uint8_t> &stream,
    const std::shared_ptr<sv2::Sv2CodecState> &state,
    std::size_t max_iterations = 16
) {
    auto decoder = sv2::Sv2Decoder::init();

    if (decoder == nullptr) {
        throw std::runtime_error("Sv2Decoder::init returned null");
    }

    return decode_from_stream(*decoder, stream, state, max_iterations);
}

inline std::optional<sv2::Sv2Message> try_decode_chunk(
    sv2::Sv2Decoder &decoder,
    const std::vector<uint8_t> &chunk,
    const std::shared_ptr<sv2::Sv2CodecState> &state
) {
    try {
        return decoder.try_decode(chunk, state);
    } catch (const std::exception &error) {
        if (is_missing_bytes_error(error)) {
            return std::nullopt;
        }

        throw;
    }
}

inline void print_setup_connection(const sv2::SetupConnection &setup_connection) {
    std::cout << "--- SetupConnection Details ---" << std::endl;
    std::cout << "Protocol: " << static_cast<int>(setup_connection.protocol) << std::endl;
    std::cout << "Version Range: " << setup_connection.min_version
              << "-" << setup_connection.max_version << std::endl;
    std::cout << "Flags: " << setup_connection.flags << std::endl;
    std::cout << "Endpoint: " << setup_connection.endpoint_host
              << ":" << setup_connection.endpoint_port << std::endl;
    std::cout << "Vendor: " << setup_connection.vendor << std::endl;
    std::cout << "Hardware Version: " << setup_connection.hardware_version << std::endl;
    std::cout << "Firmware: " << setup_connection.firmware << std::endl;
    std::cout << "Device ID: " << setup_connection.device_id << std::endl;
}

inline void print_setup_connection_success(
    const sv2::SetupConnectionSuccess &setup_connection_success
) {
    std::cout << "--- SetupConnectionSuccess Details ---" << std::endl;
    std::cout << "Used Version: " << setup_connection_success.used_version << std::endl;
    std::cout << "Flags: " << setup_connection_success.flags << std::endl;
}

} // namespace sv2cpp::example
