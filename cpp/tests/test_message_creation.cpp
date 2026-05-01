#include <functional>
#include <iostream>
#include <string>
#include <variant>

#include "test_utils.hpp"

int main() {
    return sv2cpp::test::run_test("Message creation test", [] {
        using namespace sv2cpp::test;

        const auto setup_connection = sv2::SetupConnection{
            .protocol = 1,
            .min_version = 2,
            .max_version = 2,
            .flags = 0,
            .endpoint_host = "test.example.com",
            .endpoint_port = 4444,
            .vendor = "Test Miner",
            .hardware_version = "v1.0",
            .firmware = "test-1.0.0",
            .device_id = "test-device",
        };

        const auto sv2_message = sv2::Sv2Message(
            sv2::Sv2Message::kSetupConnection{
                .message = setup_connection,
            }
        );

        require(
            is_variant<sv2::Sv2Message::kSetupConnection>(sv2_message),
            "Sv2Message did not hold SetupConnection variant"
        );

        const auto &wrapped_setup_connection = get_setup_connection(sv2_message);

        require_eq(
            wrapped_setup_connection.protocol,
            static_cast<uint8_t>(1),
            "SetupConnection protocol was not preserved"
        );
        require_eq(
            wrapped_setup_connection.min_version,
            static_cast<uint16_t>(2),
            "SetupConnection min_version was not preserved"
        );
        require_eq(
            wrapped_setup_connection.max_version,
            static_cast<uint16_t>(2),
            "SetupConnection max_version was not preserved"
        );
        require_eq(
            wrapped_setup_connection.flags,
            0U,
            "SetupConnection flags were not preserved"
        );
        require_eq(
            wrapped_setup_connection.endpoint_host,
            std::string("test.example.com"),
            "SetupConnection endpoint_host was not preserved"
        );
        require_eq(
            wrapped_setup_connection.endpoint_port,
            static_cast<uint16_t>(4444),
            "SetupConnection endpoint_port was not preserved"
        );
        require_eq(
            wrapped_setup_connection.vendor,
            std::string("Test Miner"),
            "SetupConnection vendor was not preserved"
        );
        require_eq(
            wrapped_setup_connection.hardware_version,
            std::string("v1.0"),
            "SetupConnection hardware_version was not preserved"
        );
        require_eq(
            wrapped_setup_connection.firmware,
            std::string("test-1.0.0"),
            "SetupConnection firmware was not preserved"
        );
        require_eq(
            wrapped_setup_connection.device_id,
            std::string("test-device"),
            "SetupConnection device_id was not preserved"
        );

        const auto setup_connection_success = sv2::SetupConnectionSuccess{
            .used_version = 2,
            .flags = 0,
        };

        const auto success_message = sv2::Sv2Message(
            sv2::Sv2Message::kSetupConnectionSuccess{
                .message = setup_connection_success,
            }
        );

        require(
            is_variant<sv2::Sv2Message::kSetupConnectionSuccess>(success_message),
            "Sv2Message did not hold SetupConnectionSuccess variant"
        );

        const auto &wrapped_success = get_setup_connection_success(success_message);

        require_eq(
            wrapped_success.used_version,
            static_cast<uint16_t>(2),
            "SetupConnectionSuccess used_version was not preserved"
        );
        require_eq(
            wrapped_success.flags,
            0U,
            "SetupConnectionSuccess flags were not preserved"
        );
    });
}