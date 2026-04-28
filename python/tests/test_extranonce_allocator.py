"""
Extranonce allocator tests for sv2-uniffi.

Tests that verify allocator-backed extranonce prefix functionality.
"""

import traceback


def test_extranonce_allocator():
    """Test extranonce allocator functionality."""
    try:
        from sv2 import Sv2ExtranonceAllocator, sv2_extranonce_bytes_needed

        max_channels = 256
        local_prefix_bytes = b"\xff"
        client_search_space_bytes = 8
        total_extranonce_len = (
            len(local_prefix_bytes)
            + sv2_extranonce_bytes_needed(max_channels)
            + client_search_space_bytes
        )

        allocator = Sv2ExtranonceAllocator(
            local_prefix_bytes=local_prefix_bytes,
            total_extranonce_len=total_extranonce_len,
            max_channels=max_channels,
        )

        extended_prefix_a = allocator.allocate_extended(min_rollable_size=4)
        assert extended_prefix_a.len() == len(local_prefix_bytes) + 1
        assert allocator.rollable_extranonce_size() == client_search_space_bytes
        assert allocator.local_prefix_len() == len(local_prefix_bytes)
        assert allocator.local_index_len() == sv2_extranonce_bytes_needed(max_channels)
        assert allocator.full_prefix_len() == len(local_prefix_bytes) + 1

        failed = False
        try:
            allocator.allocate_extended(min_rollable_size=client_search_space_bytes + 1)
        except Exception:
            failed = True
        assert failed

        extended_prefix_b = allocator.allocate_extended(min_rollable_size=4)
        assert extended_prefix_a.as_bytes() != extended_prefix_b.as_bytes()

        standard_prefix = allocator.allocate_standard()
        assert standard_prefix.len() == total_extranonce_len
        assert standard_prefix.as_bytes() != extended_prefix_a.as_bytes()

        return True

    except Exception as e:
        print(f"Extranonce allocator test failed: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_extranonce_allocator()
    if success:
        print("Extranonce allocator test passed")
    else:
        print("Extranonce allocator test failed")
