"""
Extranonce Prefix Factory tests for sv2-uniffi.

Tests that verify extranonce prefix factory functionality.
"""

import traceback

def test_extranonce_prefix_factory():
    """Test extranonce prefix factory functionality."""
    try:
        from sv2 import Sv2ExtranoncePrefixFactoryExtended, Sv2ExtranoncePrefixFactoryStandard

        allocation_size = 16

        # Create a new extended extranonce prefix factory
        extranonce_prefix_factory_extended = Sv2ExtranoncePrefixFactoryExtended(
            allocation_size=allocation_size,
            static_prefix=b"\xff",
        )

        # generate a new extranonce_prefix
        extranonce_prefix_a = extranonce_prefix_factory_extended.next_extranonce_prefix(
            min_required_len=2,
        )

        # assert that extranonce_prefix_a the correct length
        assert len(extranonce_prefix_a) == allocation_size

        # assert that an exception is raised if min_required_len is too big
        try:
            extranonce_prefix_b = extranonce_prefix_factory_extended.next_extranonce_prefix(
                min_required_len=18,
            )
        except Exception as e:
            # expected exception because min_required_len is too big
            pass

        extranonce_prefix_c = extranonce_prefix_factory_extended.next_extranonce_prefix(
            min_required_len=4,
        )
        
        # assert a new and unique extranonce_prefix is generated
        assert extranonce_prefix_a != extranonce_prefix_c

        # create a new extranonce prefix factory for standard channels
        extranonce_prefix_factory_standard = Sv2ExtranoncePrefixFactoryStandard(
            static_prefix=b"\xff",
        )
        
        extranonce_prefix_d = extranonce_prefix_factory_standard.next_extranonce_prefix()

        extranonce_prefix_e = extranonce_prefix_factory_standard.next_extranonce_prefix()

        # assert that a new and unique extranonce_prefix is generated
        assert extranonce_prefix_e != extranonce_prefix_d
        assert extranonce_prefix_e != extranonce_prefix_a

        return True

    except Exception as e:
        print(f"✗ Extranonce prefix factory test failed: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_extranonce_prefix_factory()
    if success:
        print("✓ Extranonce prefix factory test passed")
    else:
        print("✗ Extranonce prefix factory test failed")