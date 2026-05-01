#include <functional>
#include <iostream>
#include <vector>

#include "test_utils.hpp"

int main() {
    return sv2cpp::test::run_test("Extranonce allocator test", [] {
        using namespace sv2cpp::test;

        constexpr uint32_t max_channels = 256;
        const std::vector<uint8_t> local_prefix_bytes = {0xff};
        constexpr uint32_t client_search_space_bytes = 8;

        const auto local_index_bytes = sv2::sv2_extranonce_bytes_needed(max_channels);
        const auto total_extranonce_len =
            static_cast<uint32_t>(local_prefix_bytes.size()) +
            local_index_bytes +
            client_search_space_bytes;

        require_eq(
            local_index_bytes,
            1U,
            "sv2_extranonce_bytes_needed returned unexpected local index length"
        );

        auto allocator = sv2::Sv2ExtranonceAllocator::init(
            local_prefix_bytes,
            total_extranonce_len,
            max_channels
        );

        require(allocator != nullptr, "Sv2ExtranonceAllocator::init returned null");

        const auto extended_prefix_a = allocator->allocate_extended(4);

        require(
            extended_prefix_a != nullptr,
            "allocate_extended returned null for first extended prefix"
        );
        require_eq(
            extended_prefix_a->len(),
            static_cast<uint32_t>(local_prefix_bytes.size()) + local_index_bytes,
            "extended prefix length was not local_prefix_len + local_index_len"
        );
        require_eq(
            allocator->rollable_extranonce_size(),
            client_search_space_bytes,
            "allocator rollable extranonce size was unexpected"
        );
        require_eq(
            allocator->local_prefix_len(),
            static_cast<uint32_t>(local_prefix_bytes.size()),
            "allocator local prefix length was unexpected"
        );
        require_eq(
            allocator->local_index_len(),
            local_index_bytes,
            "allocator local index length was unexpected"
        );
        require_eq(
            allocator->full_prefix_len(),
            static_cast<uint32_t>(local_prefix_bytes.size()) + local_index_bytes,
            "allocator full prefix length was unexpected"
        );
        require_eq(
            allocator->total_extranonce_len(),
            total_extranonce_len,
            "allocator total extranonce length was unexpected"
        );
        require_eq(
            allocator->max_channels(),
            max_channels,
            "allocator max channel count was unexpected"
        );
        require_eq(
            allocator->allocated_count(),
            1U,
            "allocator allocated count was not incremented after first allocation"
        );

        bool invalid_rollable_size_failed = false;

        try {
            (void)allocator->allocate_extended(client_search_space_bytes + 1);
        } catch (const sv2::Sv2ExtranonceAllocatorError &) {
            invalid_rollable_size_failed = true;
        }

        require(
            invalid_rollable_size_failed,
            "allocate_extended accepted a min_rollable_size larger than the available client search space"
        );

        const auto extended_prefix_b = allocator->allocate_extended(4);

        require(
            extended_prefix_b != nullptr,
            "allocate_extended returned null for second extended prefix"
        );
        require_ne(
            extended_prefix_a->as_bytes(),
            extended_prefix_b->as_bytes(),
            "two extended allocations produced the same prefix bytes"
        );

        const auto standard_prefix = allocator->allocate_standard();

        require(
            standard_prefix != nullptr,
            "allocate_standard returned null"
        );
        require_eq(
            standard_prefix->len(),
            total_extranonce_len,
            "standard prefix length did not match total extranonce length"
        );
        require_ne(
            standard_prefix->as_bytes(),
            extended_prefix_a->as_bytes(),
            "standard allocation produced the same bytes as the first extended allocation"
        );
        require_ne(
            standard_prefix->as_bytes(),
            extended_prefix_b->as_bytes(),
            "standard allocation produced the same bytes as the second extended allocation"
        );
        require_eq(
            allocator->allocated_count(),
            3U,
            "allocator allocated count did not match successful allocations"
        );
    });
}