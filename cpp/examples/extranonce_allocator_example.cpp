/*
 * Stratum v2 Extranonce Allocator Example
 *
 * This example demonstrates how to leverage Sv2ExtranonceAllocator.
 *
 * A Mining Server could have multiple clients, and each client could have multiple channels.
 * In Sv2, the extranonce prefix is what lets the Mining Server guarantee unique search space for
 * different channels.
 *
 * A Mining Server should use a single Sv2ExtranonceAllocator for both Standard and Extended
 * Channels. This keeps standard and extended channel prefixes in one allocation namespace.
 */

#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "example_utils.hpp"
#include "sv2.hpp"

namespace {

constexpr std::uint32_t POOL_SERVER_BYTES = 1;
constexpr std::uint32_t POOL_MAX_CHANNELS = 16'777'216;
constexpr std::uint32_t CLIENT_SEARCH_SPACE_BYTES = 16;

class MiningServer {
public:
    explicit MiningServer(std::uint8_t server_id)
        : extranonce_allocator(sv2::Sv2ExtranonceAllocator::init(
              std::vector<std::uint8_t>{server_id},
              POOL_SERVER_BYTES + sv2::sv2_extranonce_bytes_needed(POOL_MAX_CHANNELS) + CLIENT_SEARCH_SPACE_BYTES,
              POOL_MAX_CHANNELS
          )) {
        if (extranonce_allocator == nullptr) {
            throw std::runtime_error("Sv2ExtranonceAllocator::init returned null");
        }
    }

    std::shared_ptr<sv2::Sv2ExtranonceAllocator> extranonce_allocator;
};

void print_prefix(
    const std::string &label,
    const std::shared_ptr<sv2::Sv2ExtranoncePrefix> &prefix
) {
    if (prefix == nullptr) {
        throw std::runtime_error(label + " allocation returned null");
    }

    std::cout
        << label << ": "
        << sv2cpp::example::hex(prefix->as_bytes())
        << " (" << prefix->len() << " bytes)"
        << std::endl;
}

} // namespace

int main() {
    try {
        std::cout << "Stratum v2 Extranonce Allocator Example" << std::endl;
        std::cout << "==================================================" << std::endl;

        std::cout << "Pool server bytes: " << POOL_SERVER_BYTES << std::endl;
        std::cout << "Pool max channels: " << POOL_MAX_CHANNELS << std::endl;
        std::cout
            << "Pool local index bytes: "
            << sv2::sv2_extranonce_bytes_needed(POOL_MAX_CHANNELS)
            << std::endl;
        std::cout
            << "Full extranonce size: "
            << POOL_SERVER_BYTES + sv2::sv2_extranonce_bytes_needed(POOL_MAX_CHANNELS) + CLIENT_SEARCH_SPACE_BYTES
            << std::endl;
        std::cout
            << "Client search space bytes: "
            << CLIENT_SEARCH_SPACE_BYTES
            << std::endl;
        std::cout << std::endl;

        // different mining servers have unique server bytes
        // this guarantees no extranonce collisions between servers
        MiningServer mining_server_a(0);
        MiningServer mining_server_b(1);

        const auto standard_a_1 = mining_server_a.extranonce_allocator->allocate_standard();
        const auto standard_a_2 = mining_server_a.extranonce_allocator->allocate_standard();
        const auto standard_b_1 = mining_server_b.extranonce_allocator->allocate_standard();
        const auto standard_b_2 = mining_server_b.extranonce_allocator->allocate_standard();

        print_prefix("Standard Channel 1 on Mining Server A", standard_a_1);
        print_prefix("Standard Channel 2 on Mining Server A", standard_a_2);
        print_prefix("Standard Channel 1 on Mining Server B", standard_b_1);
        print_prefix("Standard Channel 2 on Mining Server B", standard_b_2);

        std::cout << std::endl;

        // clients can potentially ask for less than CLIENT_SEARCH_SPACE_BYTES
        const auto extended_a_1 = mining_server_a.extranonce_allocator->allocate_extended(CLIENT_SEARCH_SPACE_BYTES - 8);
        const auto extended_a_2 = mining_server_a.extranonce_allocator->allocate_extended(CLIENT_SEARCH_SPACE_BYTES - 4);
        const auto extended_b_1 = mining_server_b.extranonce_allocator->allocate_extended(CLIENT_SEARCH_SPACE_BYTES - 2);
        const auto extended_b_2 = mining_server_b.extranonce_allocator->allocate_extended(CLIENT_SEARCH_SPACE_BYTES);

        print_prefix("Extended Channel 1 on Mining Server A", extended_a_1);
        print_prefix("Extended Channel 2 on Mining Server A", extended_a_2);
        print_prefix("Extended Channel 1 on Mining Server B", extended_b_1);
        print_prefix("Extended Channel 2 on Mining Server B", extended_b_2);

        std::cout << std::endl;
        std::cout
            << "Mining Server A allocated "
            << mining_server_a.extranonce_allocator->allocated_count()
            << " prefixes"
            << std::endl;
        std::cout
            << "Mining Server B allocated "
            << mining_server_b.extranonce_allocator->allocated_count()
            << " prefixes"
            << std::endl;

        std::cout << std::endl;
        std::cout << "--- Invalid request demonstration ---" << std::endl;

        // clients can't ask for more than CLIENT_SEARCH_SPACE_BYTES
        try {
            (void)mining_server_a.extranonce_allocator->allocate_extended(CLIENT_SEARCH_SPACE_BYTES + 1);
            std::cout
                << "Unexpectedly accepted an oversized rollable extranonce request"
                << std::endl;
        } catch (const sv2::Sv2ExtranonceAllocatorError &error) {
            std::cout
                << "Client wants to roll more bytes than this allocator allows. "
                << "Return an OpenMiningChannel.Error."
                << std::endl;
            (void)error;
        }

        std::cout << std::endl;
        std::cout << "Example completed successfully" << std::endl;
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Example failed: " << error.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Example failed with an unknown error" << std::endl;
        return 1;
    }
}