#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <vector>

#include "test_utils.hpp"

namespace {

void assert_initial_accounting(
    const std::shared_ptr<sv2::ShareAccounting> &accounting,
    uint64_t expected_batch_size
) {
    using namespace sv2cpp::test;

    require(accounting != nullptr, "share accounting snapshot is null");

    require_eq(
        accounting->get_last_share_sequence_number(),
        0U,
        "unexpected initial last_share_sequence_number"
    );
    require_eq(
        accounting->get_shares_accepted(),
        0U,
        "unexpected initial shares_accepted"
    );
    require_eq(
        accounting->get_share_work_sum(),
        0.0,
        "unexpected initial share_work_sum"
    );
    require_eq(
        accounting->get_last_batch_accepted(),
        0U,
        "unexpected initial last_batch_accepted"
    );
    require_eq(
        accounting->get_last_batch_work_sum(),
        0.0,
        "unexpected initial last_batch_work_sum"
    );
    require_eq(
        accounting->get_share_batch_size(),
        expected_batch_size,
        "unexpected initial share_batch_size"
    );
    require(
        !accounting->should_acknowledge(),
        "unexpected initial should_acknowledge"
    );
    require_eq(
        accounting->get_best_diff(),
        0.0,
        "unexpected initial best_diff"
    );
    require_eq(
        accounting->get_blocks_found(),
        0U,
        "unexpected initial blocks_found"
    );
}

} // namespace

int main() {
    return sv2cpp::test::run_test("Share accounting test", [] {
        using namespace sv2cpp::test;

        auto extended_extranonce_allocator = sv2::Sv2ExtranonceAllocator::init(
            std::vector<uint8_t>{0xff},
            22,
            256
        );
        require(
            extended_extranonce_allocator != nullptr,
            "extended extranonce allocator is null"
        );

        auto standard_extranonce_allocator = sv2::Sv2ExtranonceAllocator::init(
            std::vector<uint8_t>{0xff},
            32,
            256
        );
        require(
            standard_extranonce_allocator != nullptr,
            "standard extranonce allocator is null"
        );

        auto extended_extranonce_prefix =
            extended_extranonce_allocator->allocate_extended(20);
        require(
            extended_extranonce_prefix != nullptr,
            "extended extranonce prefix is null"
        );

        auto standard_extranonce_prefix =
            standard_extranonce_allocator->allocate_standard();
        require(
            standard_extranonce_prefix != nullptr,
            "standard extranonce prefix is null"
        );

        auto extended_channel = sv2::Sv2ExtendedChannelServer::init(
            1,
            "test",
            extended_extranonce_prefix,
            repeated_byte(0xff, 32),
            10'000.0F,
            true,
            20,
            2,
            1.0F,
            "test"
        );
        require(
            extended_channel != nullptr,
            "extended channel server is null"
        );

        auto standard_channel = sv2::Sv2StandardChannelServer::init(
            2,
            "test",
            standard_extranonce_prefix,
            repeated_byte(0xff, 32),
            10'000.0F,
            3,
            1.0F,
            "test"
        );
        require(
            standard_channel != nullptr,
            "standard channel server is null"
        );

        assert_initial_accounting(
            extended_channel->get_share_accounting(),
            2
        );
        assert_initial_accounting(
            standard_channel->get_share_accounting(),
            3
        );

        auto not_so_permissive_max_target = repeated_byte(0xff, 31);
        not_so_permissive_max_target.push_back(0x00);

        extended_channel->update_channel(
            0.1F,
            std::optional<std::vector<uint8_t>>(not_so_permissive_max_target)
        );

        require(
            extended_channel->get_target() == not_so_permissive_max_target,
            "extended channel target was not clamped to max target"
        );
        require(
            extended_channel->get_requested_max_target() == not_so_permissive_max_target,
            "extended channel requested max target was not updated"
        );

        standard_channel->update_channel(
            0.1F,
            std::optional<std::vector<uint8_t>>(not_so_permissive_max_target)
        );

        require(
            standard_channel->get_target() == not_so_permissive_max_target,
            "standard channel target was not clamped to max target"
        );
        require(
            standard_channel->get_requested_max_target() == not_so_permissive_max_target,
            "standard channel requested max target was not updated"
        );

        assert_initial_accounting(
            extended_channel->get_share_accounting(),
            2
        );
        assert_initial_accounting(
            standard_channel->get_share_accounting(),
            3
        );
    });
}