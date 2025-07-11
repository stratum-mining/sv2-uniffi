"""
Stratum v2 Extranonce Prefix Factory Example

This example demonstrates how to leverage the APIs from Sv2ExtranoncePrefixFactoryStandard and Sv2ExtranoncePrefixFactoryExtended.

A Mining Server could have multiple clients, and each client could have multiple channels.

In Sv2, the Extranonce Prefix is what allows the Mining Server to guarantee unique search space for the different channels.

A Mining Server should use a single Sv2ExtranoncePrefixFactoryStandard for all Standard Channels (regardless of which client it belongs to),
and a single Sv2ExtranoncePrefixFactoryExtended for all Extended Channels (regardless of which client it belongs to).

It is common for Pools to have multiple Mining Servers (e.g.: in different geolocations). In order to guarantee unique search space allocation across all Mining Servers,
it is recommended to use a static prefix for each Mining Server.

We are going to represent that as a MiningServer class, which will contain the two Extranonce Prefix Factories.
Each instance of this class will represent a different Mining Server.

However, this does not mean you have to use the same MiningServer class on your code!!! This is for illustration purposes only.
"""

from sv2 import (
    Sv2ExtranoncePrefixFactoryExtended,
    Sv2ExtranoncePrefixFactoryStandard,
)

class MiningServer:
    extranonce_prefix_factory_extended: Sv2ExtranoncePrefixFactoryExtended
    extranonce_prefix_factory_standard: Sv2ExtranoncePrefixFactoryStandard
    
    # static_prefix is a bytes array that is used to guarantee unique search space allocation across different Mining Servers
    # it is recommended to use a different static_prefix for each Mining Server
    def __init__(self, static_prefix: bytes):
        # imagine we want to allow Extended Channels to roll 8 bytes out of the 32
        # so 24 bytes are used to generate unique Extranonce Prefixes
        self.extranonce_prefix_factory_extended = Sv2ExtranoncePrefixFactoryExtended(allocation_size=24, static_prefix=static_prefix)
        # Standard Channels use 32 bytes for Extranonce Prefix
        # there's no extranonce rolling, and the Merkle Root is fixed
        self.extranonce_prefix_factory_standard = Sv2ExtranoncePrefixFactoryStandard(static_prefix=static_prefix)


def main():
    """Main demonstration function."""
    print("Stratum v2 Extranonce Prefix Factory Example")
    print("=" * 50)
    
    # Imagine we have 3 Mining Servers in different geolocations
    # We need unique search space allocation across all of them!
    mining_server_a = MiningServer(b"\x00")
    mining_server_b = MiningServer(b"\x01")
    mining_server_c = MiningServer(b"\x02")
    
    # Imagine we have to create 3 Standard Channels on Mining Server A
    
    extranonce_prefix_standard_a_1 = mining_server_a.extranonce_prefix_factory_standard.next_extranonce_prefix()
    extranonce_prefix_standard_a_2 = mining_server_a.extranonce_prefix_factory_standard.next_extranonce_prefix()
    extranonce_prefix_standard_a_3 = mining_server_a.extranonce_prefix_factory_standard.next_extranonce_prefix()

    # 0000000000000000000000000000000000000000000000000000000000000001
    print(f"Extranonce Prefix for Standard Channel 1 on Mining Server A: {extranonce_prefix_standard_a_1.hex()}")
    # 0000000000000000000000000000000000000000000000000000000000000002
    print(f"Extranonce Prefix for Standard Channel 2 on Mining Server A: {extranonce_prefix_standard_a_2.hex()}")
    # 0000000000000000000000000000000000000000000000000000000000000003
    print(f"Extranonce Prefix for Standard Channel 3 on Mining Server A: {extranonce_prefix_standard_a_3.hex()}")

    # Imagine we have to create 3 Standard Channels on Mining Server B
    extranonce_prefix_standard_b_1 = mining_server_b.extranonce_prefix_factory_standard.next_extranonce_prefix()
    extranonce_prefix_standard_b_2 = mining_server_b.extranonce_prefix_factory_standard.next_extranonce_prefix()
    extranonce_prefix_standard_b_3 = mining_server_b.extranonce_prefix_factory_standard.next_extranonce_prefix()

    # 0100000000000000000000000000000000000000000000000000000000000001
    print(f"Extranonce Prefix for Standard Channel 1 on Mining Server B: {extranonce_prefix_standard_b_1.hex()}")
    # 0100000000000000000000000000000000000000000000000000000000000002
    print(f"Extranonce Prefix for Standard Channel 2 on Mining Server B: {extranonce_prefix_standard_b_2.hex()}")
    # 0100000000000000000000000000000000000000000000000000000000000003
    print(f"Extranonce Prefix for Standard Channel 3 on Mining Server B: {extranonce_prefix_standard_b_3.hex()}")

    # Imagine we have to create 3 Standard Channels on Mining Server C
    extranonce_prefix_standard_c_1 = mining_server_c.extranonce_prefix_factory_standard.next_extranonce_prefix()
    extranonce_prefix_standard_c_2 = mining_server_c.extranonce_prefix_factory_standard.next_extranonce_prefix()
    extranonce_prefix_standard_c_3 = mining_server_c.extranonce_prefix_factory_standard.next_extranonce_prefix()

    # 0200000000000000000000000000000000000000000000000000000000000001
    print(f"Extranonce Prefix for Standard Channel 1 on Mining Server C: {extranonce_prefix_standard_c_1.hex()}")
    # 0200000000000000000000000000000000000000000000000000000000000002
    print(f"Extranonce Prefix for Standard Channel 2 on Mining Server C: {extranonce_prefix_standard_c_2.hex()}")
    # 0200000000000000000000000000000000000000000000000000000000000003
    print(f"Extranonce Prefix for Standard Channel 3 on Mining Server C: {extranonce_prefix_standard_c_3.hex()}")

    # Imagine we have to create 3 Extended Channels on Mining Server A
    # Imagine the client requested 8 bytes for rolling
    extranonce_prefix_extended_a_1 = mining_server_a.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)
    extranonce_prefix_extended_a_2 = mining_server_a.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)
    extranonce_prefix_extended_a_3 = mining_server_a.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)

    # 000000000000000000000000000000000000000000000001
    print(f"Extranonce Prefix for Extended Channel 1 on Mining Server A: {extranonce_prefix_extended_a_1.hex()}")
    # 000000000000000000000000000000000000000000000002
    print(f"Extranonce Prefix for Extended Channel 2 on Mining Server A: {extranonce_prefix_extended_a_2.hex()}")
    # 000000000000000000000000000000000000000000000003
    print(f"Extranonce Prefix for Extended Channel 3 on Mining Server A: {extranonce_prefix_extended_a_3.hex()}")

    # Imagine we have to create 3 Extended Channels on Mining Server B
    # Imagine the client requested 8 bytes for rolling
    extranonce_prefix_extended_b_1 = mining_server_b.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)
    extranonce_prefix_extended_b_2 = mining_server_b.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)
    extranonce_prefix_extended_b_3 = mining_server_b.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)

    # 010000000000000000000000000000000000000000000001
    print(f"Extranonce Prefix for Extended Channel 1 on Mining Server B: {extranonce_prefix_extended_b_1.hex()}")
    # 010000000000000000000000000000000000000000000002
    print(f"Extranonce Prefix for Extended Channel 2 on Mining Server B: {extranonce_prefix_extended_b_2.hex()}")
    # 010000000000000000000000000000000000000000000003
    print(f"Extranonce Prefix for Extended Channel 3 on Mining Server B: {extranonce_prefix_extended_b_3.hex()}")
    

    # Imagine we have to create 3 Extended Channels on Mining Server C
    # Imagine the client requested 8 bytes for rolling
    extranonce_prefix_extended_c_1 = mining_server_c.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)
    extranonce_prefix_extended_c_2 = mining_server_c.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)
    extranonce_prefix_extended_c_3 = mining_server_c.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=8)

    # 020000000000000000000000000000000000000000000001
    print(f"Extranonce Prefix for Extended Channel 1 on Mining Server C: {extranonce_prefix_extended_c_1.hex()}")
    # 020000000000000000000000000000000000000000000002
    print(f"Extranonce Prefix for Extended Channel 2 on Mining Server C: {extranonce_prefix_extended_c_2.hex()}")
    # 020000000000000000000000000000000000000000000003
    print(f"Extranonce Prefix for Extended Channel 3 on Mining Server C: {extranonce_prefix_extended_c_3.hex()}")

    # Now, let's see what happens if the client request only 4 bytes for rolling
    extranonce_prefix_extended_a_4 = mining_server_a.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=4)
    
    # They still get a 24 bytes Extranonce Prefix!
    # 000000000000000000000000000000000000000000000004
    print(f"Extranonce Prefix for Extended Channel 4 on Mining Server A: {extranonce_prefix_extended_a_4.hex()}")

    # Now, let's see what happens if the client requests 10 bytes for rolling
    try:
        extranonce_prefix_extended_a_5 = mining_server_a.extranonce_prefix_factory_extended.next_extranonce_prefix(min_required_len=10)
    except Exception as e:
        # This should result in a OpenMiningChannel.Error
        print(f"Client wants to roll more bytes than this Sv2ExtranoncePrefixFactoryExtended allows. We should return a OpenMiningChannel.Error")

if __name__ == "__main__":
    main() 