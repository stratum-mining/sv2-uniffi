#include <functional>
#include <iostream>

#include "test_utils.hpp"

int main() {
    return sv2cpp::test::run_test("Handshake test", [] {
        using namespace sv2cpp::test;

        const auto handshake = complete_handshake();

        require(handshake.initiator != nullptr, "initiator codec state is null");
        require(handshake.responder != nullptr, "responder codec state is null");

        require(
            handshake.initiator->handshake_complete(),
            "initiator did not report a completed handshake"
        );
        require(
            handshake.responder->handshake_complete(),
            "responder did not report a completed handshake"
        );
    });
}