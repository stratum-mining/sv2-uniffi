"""
Share accounting tests for sv2-uniffi.

Tests that server channel wrappers expose read-only share accounting snapshots.
"""

import traceback


def _assert_initial_accounting(accounting, expected_batch_size):
    if accounting.get_last_share_sequence_number() != 0:
        raise Exception("unexpected initial last_share_sequence_number")
    if accounting.get_shares_accepted() != 0:
        raise Exception("unexpected initial shares_accepted")
    if accounting.get_share_work_sum() != 0.0:
        raise Exception("unexpected initial share_work_sum")
    if accounting.get_last_batch_accepted() != 0:
        raise Exception("unexpected initial last_batch_accepted")
    if accounting.get_last_batch_work_sum() != 0.0:
        raise Exception("unexpected initial last_batch_work_sum")
    if accounting.get_share_batch_size() != expected_batch_size:
        raise Exception("unexpected initial share_batch_size")
    if accounting.should_acknowledge():
        raise Exception("unexpected initial should_acknowledge")
    if accounting.get_best_diff() != 0.0:
        raise Exception("unexpected initial best_diff")
    if accounting.get_blocks_found() != 0:
        raise Exception("unexpected initial blocks_found")


def test_share_accounting():
    """Test share accounting exposure on server channel wrappers."""
    try:
        from sv2 import Sv2ExtendedChannelServer, Sv2ExtranonceAllocator, Sv2StandardChannelServer

        extended_extranonce_allocator = Sv2ExtranonceAllocator(
            local_prefix_bytes=b"\xFF",
            total_extranonce_len=22,
            max_channels=256,
        )
        standard_extranonce_allocator = Sv2ExtranonceAllocator(
            local_prefix_bytes=b"\xFF",
            total_extranonce_len=32,
            max_channels=256,
        )

        extended_channel = Sv2ExtendedChannelServer(
            channel_id=1,
            user_identity="test",
            extranonce_prefix=extended_extranonce_allocator.allocate_extended(
                min_rollable_size=20
            ),
            max_target=b"\xFF" * 32,
            nominal_hashrate=10_000.0,
            version_rolling_allowed=True,
            rollable_extranonce_size=20,
            share_batch_size=2,
            expected_share_per_minute=1.0,
            pool_tag_string="test",
        )

        standard_channel = Sv2StandardChannelServer(
            channel_id=2,
            user_identity="test",
            extranonce_prefix=standard_extranonce_allocator.allocate_standard(),
            max_target=b"\xFF" * 32,
            nominal_hashrate=10_000.0,
            share_batch_size=3,
            expected_share_per_minute=1.0,
            pool_tag_string="test",
        )

        _assert_initial_accounting(extended_channel.get_share_accounting(), 2)
        _assert_initial_accounting(standard_channel.get_share_accounting(), 3)

        print("✓ Share accounting test passed")
        return True

    except Exception as e:
        print(f"✗ Share accounting test failed: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_share_accounting()
    exit(0 if success else 1)
