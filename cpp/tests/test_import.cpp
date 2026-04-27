#include <functional>
#include <iostream>
#include <memory>
#include <variant>
#include <vector>

#include "test_utils.hpp"

int main() {
    return sv2cpp::test::run_test("Import smoke test", [] {
        using namespace sv2cpp::test;

        const auto initiator = sv2::Sv2CodecState::new_initiator(authority_public_key());
        require(initiator != nullptr, "Sv2CodecState::new_initiator returned null");

        const auto encoder = sv2::Sv2Encoder::init();
        require(encoder != nullptr, "Sv2Encoder::init returned null");

        const auto decoder = sv2::Sv2Decoder::init();
        require(decoder != nullptr, "Sv2Decoder::init returned null");

        const auto setup_message = make_setup_connection_message();
        require(
            is_variant<sv2::Sv2Message::kSetupConnection>(setup_message),
            "Sv2Message did not hold SetupConnection variant"
        );

        const auto setup_connection = get_setup_connection(setup_message);
        require_eq(
            setup_connection.endpoint_host,
            std::string("test.example.com"),
            "SetupConnection endpoint_host was not preserved"
        );

        const auto allocator = sv2::Sv2ExtranonceAllocator::init(
            std::vector<uint8_t>{0xff},
            10,
            256
        );
        require(allocator != nullptr, "Sv2ExtranonceAllocator::init returned null");

        const auto extended_prefix = allocator->allocate_extended(4);
        require(extended_prefix != nullptr, "allocate_extended returned null");
        require(!extended_prefix->is_empty(), "extended extranonce prefix was empty");

        const auto standard_prefix = allocator->allocate_standard();
        require(standard_prefix != nullptr, "allocate_standard returned null");
        require(!standard_prefix->is_empty(), "standard extranonce prefix was empty");

        require_eq(
            sv2::sv2_extranonce_bytes_needed(256),
            1U,
            "sv2_extranonce_bytes_needed returned unexpected value for 256 channels"
        );
    });
}