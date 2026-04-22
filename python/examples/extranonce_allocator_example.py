"""
Stratum v2 Extranonce Allocator Example

This example demonstrates how to leverage Sv2ExtranonceAllocator.

A Mining Server could have multiple clients, and each client could have multiple channels.
In Sv2, the extranonce prefix is what lets the Mining Server guarantee unique search space for
different channels.

A Mining Server should use a single Sv2ExtranonceAllocator for both Standard and Extended
Channels. This keeps standard and extended channel prefixes in one allocation namespace.
"""

from sv2 import Sv2ExtranonceAllocator, sv2_extranonce_bytes_needed


# Size of the static identifier for this pool server, placed at the start of the pool's
# extranonce allocation. One byte covers up to 256 distinct pool servers.
POOL_SERVER_BYTES = 1
# Maximum number of concurrent channels the pool can allocate. Determines
# `POOL_LOCAL_PREFIX_BYTES` via `sv2_extranonce_bytes_needed`. The internal
# allocation bitmap uses `POOL_MAX_CHANNELS / 8` bytes of RAM.
POOL_MAX_CHANNELS = 16_777_216
# Bytes consumed by the per-channel `local_index`. Derived from
# `POOL_MAX_CHANNELS` so the two stay in sync.
POOL_LOCAL_PREFIX_BYTES = sv2_extranonce_bytes_needed(POOL_MAX_CHANNELS)
POOL_ALLOCATION_BYTES = POOL_SERVER_BYTES + POOL_LOCAL_PREFIX_BYTES
CLIENT_SEARCH_SPACE_BYTES = 16
FULL_EXTRANONCE_SIZE = POOL_ALLOCATION_BYTES + CLIENT_SEARCH_SPACE_BYTES


class MiningServer:
    extranonce_allocator: Sv2ExtranonceAllocator

    def __init__(self, server_id: int):
        local_prefix_bytes = server_id.to_bytes(POOL_SERVER_BYTES, "big")
        self.extranonce_allocator = Sv2ExtranonceAllocator(
            local_prefix_bytes=local_prefix_bytes,
            total_extranonce_len=FULL_EXTRANONCE_SIZE,
            max_channels=POOL_MAX_CHANNELS,
        )


def main():
    """Main demonstration function."""
    print("Stratum v2 Extranonce Allocator Example")
    print("=" * 50)

    mining_server_a = MiningServer(0)
    mining_server_b = MiningServer(1)

    standard_a_1 = mining_server_a.extranonce_allocator.allocate_standard()
    standard_a_2 = mining_server_a.extranonce_allocator.allocate_standard()
    print(f"Standard Channel 1 on Mining Server A: {standard_a_1.as_bytes().hex()}")
    print(f"Standard Channel 2 on Mining Server A: {standard_a_2.as_bytes().hex()}")

    standard_b_1 = mining_server_b.extranonce_allocator.allocate_standard()
    standard_b_2 = mining_server_b.extranonce_allocator.allocate_standard()
    print(f"Standard Channel 1 on Mining Server B: {standard_b_1.as_bytes().hex()}")
    print(f"Standard Channel 2 on Mining Server B: {standard_b_2.as_bytes().hex()}")

    extended_a_1 = mining_server_a.extranonce_allocator.allocate_extended(
        min_rollable_size=CLIENT_SEARCH_SPACE_BYTES
    )
    extended_a_2 = mining_server_a.extranonce_allocator.allocate_extended(
        min_rollable_size=CLIENT_SEARCH_SPACE_BYTES
    )
    extended_b_1 = mining_server_b.extranonce_allocator.allocate_extended(
        min_rollable_size=CLIENT_SEARCH_SPACE_BYTES
    )
    extended_b_2 = mining_server_b.extranonce_allocator.allocate_extended(
        min_rollable_size=CLIENT_SEARCH_SPACE_BYTES
    )
    print(f"Extended Channel 1 on Mining Server A: {extended_a_1.as_bytes().hex()}")
    print(f"Extended Channel 2 on Mining Server A: {extended_a_2.as_bytes().hex()}")
    print(f"Extended Channel 1 on Mining Server B: {extended_b_1.as_bytes().hex()}")
    print(f"Extended Channel 2 on Mining Server B: {extended_b_2.as_bytes().hex()}")

    try:
        mining_server_a.extranonce_allocator.allocate_extended(
            min_rollable_size=CLIENT_SEARCH_SPACE_BYTES + 1
        )
    except Exception:
        print(
            "Client wants to roll more bytes than this allocator allows. "
            "Return an OpenMiningChannel.Error."
        )


if __name__ == "__main__":
    main()
