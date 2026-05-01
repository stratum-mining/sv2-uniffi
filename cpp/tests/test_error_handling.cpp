#include <functional>
#include <iostream>
#include <vector>

#include "test_utils.hpp"

int main() {
    return sv2cpp::test::run_test("Error handling test", [] {
        using namespace sv2cpp::test;

        bool invalid_key_failed = false;

        try {
            const std::vector<uint8_t> invalid_key = {
                't', 'o', 'o', '_', 's', 'h', 'o', 'r', 't',
            };

            (void)sv2::Sv2CodecState::new_initiator(invalid_key);
        } catch (const sv2::Sv2CodecError &) {
            invalid_key_failed = true;
        }

        require(
            invalid_key_failed,
            "Sv2CodecState::new_initiator accepted an invalid authority key length"
        );

        bool invalid_responder_public_key_failed = false;

        try {
            const std::vector<uint8_t> invalid_public_key = {
                'b', 'a', 'd', '_', 'p', 'u', 'b', 'l', 'i', 'c',
            };

            (void)sv2::Sv2CodecState::new_responder(
                invalid_public_key,
                authority_private_key(),
                86400
            );
        } catch (const sv2::Sv2CodecError &) {
            invalid_responder_public_key_failed = true;
        }

        require(
            invalid_responder_public_key_failed,
            "Sv2CodecState::new_responder accepted an invalid authority public key length"
        );

        bool invalid_responder_private_key_failed = false;

        try {
            const std::vector<uint8_t> invalid_private_key = {
                'b', 'a', 'd', '_', 'p', 'r', 'i', 'v', 'a', 't', 'e',
            };

            (void)sv2::Sv2CodecState::new_responder(
                authority_public_key(),
                invalid_private_key,
                86400
            );
        } catch (const sv2::Sv2CodecError &) {
            invalid_responder_private_key_failed = true;
        }

        require(
            invalid_responder_private_key_failed,
            "Sv2CodecState::new_responder accepted an invalid authority private key length"
        );

        bool invalid_handshake_frame_failed = false;

        try {
            auto responder = sv2::Sv2CodecState::new_responder(
                authority_public_key(),
                authority_private_key(),
                86400
            );

            responder->step_1(std::vector<uint8_t>{0x00, 0x01, 0x02});
        } catch (const sv2::Sv2CodecError &) {
            invalid_handshake_frame_failed = true;
        }

        require(
            invalid_handshake_frame_failed,
            "Sv2CodecState::step_1 accepted an invalid handshake frame"
        );

        bool invalid_extended_extranonce_size_failed = false;

        try {
            auto allocator = sv2::Sv2ExtranonceAllocator::init(
                std::vector<uint8_t>{0xff},
                10,
                256
            );

            (void)allocator->allocate_extended(10);
        } catch (const sv2::Sv2ExtranonceAllocatorError &) {
            invalid_extended_extranonce_size_failed = true;
        }

        require(
            invalid_extended_extranonce_size_failed,
            "Sv2ExtranonceAllocator::allocate_extended accepted an invalid rollable size"
        );
    });
}