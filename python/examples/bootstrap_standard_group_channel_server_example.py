"""
Example of how to bootstrap Stratum v2 Standard and Group Channels for Mining Servers.

Please note that the context is highly over-simplified, and reading this example should not replace a good understanding of the Sv2 protocol.

We recommend reading the comments and trying to interpret the code as merely a reference for API usage.
We also highly recommend reading the Sv2 protocol specification.

There are two distinct contexts that we need to consider:
- The context of the Mining Server
- The context of the Connection with the specific client

We are going to represent the Mining Server context as a MiningServerContext class, so each
instance of this class will represent a different Mining Server.

We are going to represent the Connection context as a ConnectionContext class.
Each instance of this class will represent a different Connection with a specific client.

⚠️ THIS DOES NOT MEAN YOU HAVE TO USE THESE SAME MiningServerContext and ConnectionContext CLASSES ON YOUR CODE!!! ⚠️

These are for illustration purposes only, so you can understand how to leverage the Sv2 APIs
under your own architecture.

"""

from sv2 import (
    Sv2StandardChannelServer,
    Sv2GroupChannelServer,
    Sv2ExtendedChannelServer,
    Sv2ExtranoncePrefixFactoryExtended,
    Sv2ExtranoncePrefixFactoryStandard,
    OpenStandardMiningChannel,
    OpenStandardMiningChannelSuccess,
    OpenMiningChannelError,
    NewTemplate,
    SetNewPrevHashTemplateDistribution,
    SetNewPrevHashMining,
    TxOutput,
)

from itertools import count


# Class that illustrates the context of a Mining Server
class MiningServerContext:
    # a factory to generate unique Extranonce Prefixes for Extended Channels
    extranonce_prefix_factory_extended: Sv2ExtranoncePrefixFactoryExtended
    # a factory to generate unique Extranonce Prefixes for Standard Channels
    # this is not really used on this example, but it's good to have it
    extranonce_prefix_factory_standard: Sv2ExtranoncePrefixFactoryStandard
    # a cached future template
    cached_future_template: NewTemplate
    # a cached set_new_prev_hash_tdp
    cached_set_new_prev_hash_tdp: SetNewPrevHashTemplateDistribution
    # a boolean to indicate if version rolling is allowed
    version_rolling_allowed: bool
    # a float to indicate the expected share per minute
    expected_shares_per_minute: float
    # an int to indicate the share batch size
    share_batch_size: int
    # pool tag to be written into scriptSig of the coinbase transaction
    # only used for non-custom jobs
    pool_tag_string: str
    # script pubkey to be used for coinbase reward output paying to the pool
    pool_payout_script_pubkey: bytes

    # static_prefix is a bytes array that is used to guarantee unique search space allocation across different Mining Servers
    # it is recommended to use a different static_prefix for each Mining Server
    def __init__(
        self,
        static_prefix: bytes,
        cached_future_template: NewTemplate,
        cached_set_new_prev_hash_tdp: SetNewPrevHashTemplateDistribution,
        version_rolling_allowed: bool,
        expected_share_per_minute: float,
        share_batch_size: int,
        pool_tag_string: str,
        pool_payout_script_pubkey: bytes,
    ):
        # imagine we want to allow Extended Channels to roll 8 bytes out of the 32
        # so 24 bytes are used to generate unique Extranonce Prefixes
        # (this is not really used on this example, but it's good to have it)
        self.extranonce_prefix_factory_extended = Sv2ExtranoncePrefixFactoryExtended(
            allocation_size=24, static_prefix=static_prefix
        )
        # Standard Channels use 32 bytes for Extranonce Prefix
        # there's no extranonce rolling, and the Merkle Root is fixed
        self.extranonce_prefix_factory_standard = Sv2ExtranoncePrefixFactoryStandard(
            static_prefix=static_prefix
        )
        # we're setting one on this constructor, but these are continuously cached as they are sent from the Template Provider
        self.cached_future_template = cached_future_template
        # we're setting one on this constructor, but these are continuously cached as they are sent from the Template Provider
        self.cached_set_new_prev_hash_tdp = cached_set_new_prev_hash_tdp
        # this should be defined as pool policy
        self.version_rolling_allowed = version_rolling_allowed
        # this should be defined as pool policy, which will determine the difficulty of valid shares based on the advertised nominal hashrate
        # ideally, it should also be enforced via vardiff, since nominal hashrate can be spoofed
        self.expected_share_per_minute = expected_share_per_minute
        # this should be defined as pool policy, which will determine how many successful shares are acknowledge in a SubmitShares.Success
        self.share_batch_size = share_batch_size
        # this should be defined as pool policy, which will determine the string to be written into scriptSig of the coinbase transaction
        # for jobs that are not declared by the client
        self.pool_tag_string = pool_tag_string
        # this should be defined as pool policy, which will determine the script pubkey to be used for coinbase reward output
        self.pool_payout_script_pubkey = pool_payout_script_pubkey


# Class that illustrates the context of a Connection with a specific client
class ConnectionContext:
    # allows us to guarantee unique channel_id for the different channels established with this specific client
    channel_id_factory: count
    # whether SetupConnection.REQUIRES_STANDARD_JOBS bit flag was set
    requires_standard_jobs: bool
    # whether SetupConnection.REQUIRES_WORK_SELECTION bit flag was set
    requires_work_selection: bool
    # whether SetupConnection.REQUIRES_VERSION_ROLLING bit flag was set
    # this is not really used on this example, but it's good to have it
    requires_version_rolling: bool
    # a dictionary to keep track of the extended channels established with this specific client
    # this is not really used on this example, but it's good to have it
    extended_channels: dict[int, Sv2ExtendedChannelServer]
    # a dictionary to keep track of the standard channels established with this specific client
    standard_channels: dict[int, Sv2StandardChannelServer]
    # a group channel established with this specific client
    group_channel: Sv2GroupChannelServer

    def __init__(
        self,
        requires_standard_jobs: bool,
        requires_work_selection: bool,
        requires_version_rolling: bool,
        mining_server_context: MiningServerContext,
    ):
        self.channel_id_factory = count(start=0)
        self.requires_standard_jobs = requires_standard_jobs
        self.requires_work_selection = requires_work_selection
        self.requires_version_rolling = requires_version_rolling
        self.extended_channels = {}
        self.standard_channels = {}
        # based on the SetupConnection.REQUIRES_STANDARD_JOBS and SetupConnection.REQUIRES_WORK_SELECTION bit flags,
        # we decide whether to create a Group Channel or not
        if self.requires_standard_jobs or self.requires_work_selection:
            self.group_channel = None
        else:
            # bootstrap a group channel for this connection
            self.group_channel = Sv2GroupChannelServer(
                channel_id=next(self.channel_id_factory),
                pool_tag_string=mining_server_context.pool_tag_string,
            )

            # it's up to us to set the coinbase reward output based on the template revenue
            # this is also where merged mining OP_RETURNs should be added
            coinbase_reward_outputs = [
                TxOutput(
                    value=mining_server_context.cached_future_template.coinbase_tx_value_remaining,
                    script_pubkey=mining_server_context.pool_payout_script_pubkey,
                )
            ]

            # bootstrap the channel state with the cached future template
            self.group_channel.on_new_template(
                template=mining_server_context.cached_future_template,
                coinbase_reward_outputs=coinbase_reward_outputs,
            )

            # activate the future job locally with the cached set_new_prev_hash_tdp
            self.group_channel.on_set_new_prev_hash(
                set_new_prev_hash=mining_server_context.cached_set_new_prev_hash_tdp,
            )


def bootstrap_standard_channel_server(
    mining_server_context: MiningServerContext,
    connection_context: ConnectionContext,
    open_standard_mining_channel_message: OpenStandardMiningChannel,
):
    """
    This function emulates the process of bootstrapping a Standard channel,
    after receiving an OpenStandardMiningChannel message from a client.

    It is expected to return:
    - the newly created channel, if the channel was successfully created
    - a list of messages to be sent to the client
    """

    # if the client requires work selection, we need to return an error
    # since Standard Channels cannot be used for custom work
    if connection_context.requires_work_selection:
        return [
            OpenMiningChannelError(
                request_id=open_standard_mining_channel_message.request_id,
                error_code="standard-channels-not-supported-for-custom-work",
            )
        ]

    extranonce_prefix = (
        mining_server_context.extranonce_prefix_factory_standard.next_extranonce_prefix()
    )

    try:
        new_standard_channel = Sv2StandardChannelServer(
            channel_id=next(connection_context.channel_id_factory),
            user_identity=open_standard_mining_channel_message.user_identity,
            extranonce_prefix=extranonce_prefix,
            max_target=open_standard_mining_channel_message.max_target,
            nominal_hashrate=open_standard_mining_channel_message.nominal_hash_rate,
            share_batch_size=mining_server_context.share_batch_size,
            expected_share_per_minute=mining_server_context.expected_share_per_minute,
            pool_tag_string=mining_server_context.pool_tag_string,
        )
    except Exception as e:
        error_type = type(e).__name__

        if "InvalidNominalHashrate" in error_type:
            error_code = "invalid-nominal-hashrate"
        if "RequestedMaxTargetOutOfRange" in error_type:
            error_code = "max-target-out-of-range"
        if "FailedToCreateStandardChannel" in error_type:
            error_code = "other-error"

        return [
            [],
            [
                OpenMiningChannelError(
                    request_id=open_standard_mining_channel_message.request_id,
                    error_code=error_code,
                )
            ],
        ]

    # we need to keep track of the new standard channel
    connection_context.standard_channels[new_standard_channel.get_channel_id()] = (
        new_standard_channel
    )

    # if we're using the Group Channel
    if not connection_context.requires_standard_jobs:
        group_channel_id = connection_context.group_channel.get_group_channel_id()

        # we also need to add the standard channel id to the group channel
        connection_context.group_channel.add_standard_channel_id(
            standard_channel_id=new_standard_channel.get_channel_id(),
        )
    else:
        # if we're not using the Group Channel, we use a dummy channel_id
        # which will be meaningless across the lifespan of the connection
        group_channel_id = 0

    # OpenStandardMiningChannelSuccess to be sent to the client
    open_standard_mining_channel_success = OpenStandardMiningChannelSuccess(
        request_id=open_standard_mining_channel_message.request_id,
        channel_id=new_standard_channel.get_channel_id(),
        target=new_standard_channel.get_target(),
        extranonce_prefix=new_standard_channel.get_extranonce_prefix(),
        group_channel_id=group_channel_id,
    )

    # initialize an array with messages to be sent to the client
    # in response to the OpenStandardMiningChannel message
    ret_messages = [open_standard_mining_channel_success]

    # it's up to us to set the coinbase reward output based on the template revenue
    # this is also where merged mining OP_RETURNs should be added
    coinbase_reward_outputs = [
        TxOutput(
            value=mining_server_context.cached_future_template.coinbase_tx_value_remaining,
            script_pubkey=mining_server_context.pool_payout_script_pubkey,
        )
    ]

    # bootstrap the channel state with the cached future template
    new_standard_channel.on_new_template(
        template=mining_server_context.cached_future_template,
        coinbase_reward_outputs=coinbase_reward_outputs,
    )

    # get the job id for the future job
    future_standard_job_id = new_standard_channel.get_future_template_to_job_id()[
        mining_server_context.cached_future_template.template_id
    ]

    # we're going to send the future job to the client
    # this one will be a standard job, regardless of whether we're using the Group Channel or not
    # this is only during the bootstrap process
    # next jobs will be extended for Group Channel, in case the connection allows for it
    future_standard_job_message = new_standard_channel.get_future_jobs()[
        future_standard_job_id
    ].get_job_message()

    # activate the future job locally with the cached set_new_prev_hash_tdp
    new_standard_channel.on_set_new_prev_hash(
        set_new_prev_hash=mining_server_context.cached_set_new_prev_hash_tdp,
    )

    # we're going to send the SetNewPrevHashMining message to the client
    # so that the future job we just sent is also activated on the client side
    set_new_prev_hash_mp = SetNewPrevHashMining(
        channel_id=new_standard_channel.get_channel_id(),  # it's important that the channel_id is the same as the one sent in the future job
        job_id=future_standard_job_id,  # it's important that the job_id is the same as the one sent in the future job
        prev_hash=mining_server_context.cached_set_new_prev_hash_tdp.prev_hash,
        min_ntime=mining_server_context.cached_set_new_prev_hash_tdp.header_timestamp,
        nbits=mining_server_context.cached_set_new_prev_hash_tdp.nbits,
    )

    ret_messages.append(future_standard_job_message)
    ret_messages.append(set_new_prev_hash_mp)
    return ret_messages


def pretty_format(obj):
    """
    Format objects for nice printing output.
    """
    if isinstance(obj, Sv2StandardChannelServer):
        return f"Sv2StandardChannelServer(channel_id={obj.get_channel_id()})"

    if isinstance(obj, Sv2GroupChannelServer):
        return f"Sv2GroupChannelServer(channel_id={obj.get_group_channel_id()}, standard_channel_ids={obj.get_standard_channel_ids()})"

    # Handle message objects with attributes
    if hasattr(obj, "__dict__"):
        class_name = obj.__class__.__name__
        attrs = []
        for key, value in obj.__dict__.items():
            if isinstance(value, bytes):
                # Show first few bytes for readability
                if len(value) <= 8:
                    hex_str = value.hex()
                else:
                    hex_str = value[:4].hex() + "..." + value[-4:].hex()
                attrs.append(f"{key}=0x{hex_str}")
            elif isinstance(value, list) and value and isinstance(value[0], bytes):
                # Handle list of bytes
                attrs.append(f"{key}=[{len(value)} items]")
            else:
                attrs.append(f"{key}={repr(value)}")

        return f"{class_name}({', '.join(attrs)})"

    # Fallback to string representation
    return str(obj)


def main():
    """Main demonstration function."""
    print("Stratum v2 Standard Channel Server Example")

    mining_server_context = MiningServerContext(
        static_prefix=b"\x01",
        # in practice, new messages will be continuously cached as they are sent from the Template Provider
        cached_future_template=NewTemplate(
            template_id=1,
            future_template=True,
            version=536870912,
            coinbase_tx_version=2,
            coinbase_prefix=bytes.fromhex("022c0700"),
            coinbase_tx_input_sequence=4294967294,
            coinbase_tx_value_remaining=5000000000,
            coinbase_tx_outputs_count=1,
            coinbase_tx_outputs=bytes.fromhex(
                "0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
            ),
            coinbase_tx_locktime=1835,
            merkle_path=[],
        ),
        # in practice, new messages will be continuously cached as they are sent from the Template Provider
        cached_set_new_prev_hash_tdp=SetNewPrevHashTemplateDistribution(
            template_id=1,
            prev_hash=bytes.fromhex(
                "809F529E2C93330426149012CB31AB5A83D5E59F7D089EE41DCD9F4174010000"
            ),
            header_timestamp=1754401525,
            nbits=503543726,
            target=bytes.fromhex(
                "000000000000000000000000000000000000000000000000000000AE77030000"
            ),
        ),
        version_rolling_allowed=True,
        expected_share_per_minute=10,
        share_batch_size=10,
        pool_tag_string="pool-tag-string",
        pool_payout_script_pubkey=bytes.fromhex(
            "0014ebe1b7dcc293ccaa0ee743a86f89df8258c208fc"
        ),
    )

    # imagine three connections are established

    # this client understands Group Channels
    connection_a = ConnectionContext(
        requires_standard_jobs=False,
        requires_work_selection=False,
        requires_version_rolling=False,
        mining_server_context=mining_server_context,
    )

    # this client does not understand Group Channels
    connection_b = ConnectionContext(
        requires_standard_jobs=True,
        requires_work_selection=False,
        requires_version_rolling=False,
        mining_server_context=mining_server_context,
    )

    # this client wants to work on custom jobs
    connection_c = ConnectionContext(
        requires_standard_jobs=False,
        requires_work_selection=True,
        requires_version_rolling=False,
        mining_server_context=mining_server_context,
    )

    # imagine client A sends a OpenStandardMiningChannel message
    open_standard_mining_channel_message_a_1 = OpenStandardMiningChannel(
        request_id=1,
        user_identity="A1",
        max_target=b"\xff" * 32,
        nominal_hash_rate=1000000,
    )

    ret_a_1 = bootstrap_standard_channel_server(
        mining_server_context=mining_server_context,
        connection_context=connection_a,
        open_standard_mining_channel_message=open_standard_mining_channel_message_a_1,
    )

    print("=" * 50)
    print("=" * 50)
    print(
        "messages to be sent to the client in response to OpenStandardMiningChannel message a_1:"
    )
    for _, obj in enumerate(ret_a_1):
        print("-" * 50)
        print(pretty_format(obj))

    # imagine client A sends another OpenStandardMiningChannel message
    open_standard_mining_channel_message_a_2 = OpenStandardMiningChannel(
        request_id=2,
        user_identity="A2",
        max_target=b"\xff" * 32,
        nominal_hash_rate=1000000,
    )

    ret_a_2 = bootstrap_standard_channel_server(
        mining_server_context=mining_server_context,
        connection_context=connection_a,
        open_standard_mining_channel_message=open_standard_mining_channel_message_a_2,
    )

    print("=" * 50)
    print("=" * 50)
    print(
        "messages to be sent to the client in response to OpenStandardMiningChannel message a_2:"
    )
    for _, obj in enumerate(ret_a_2):
        print("-" * 50)
        print(pretty_format(obj))

    # imagine client B sends a OpenStandardMiningChannel message
    open_standard_mining_channel_message_b_1 = OpenStandardMiningChannel(
        request_id=1,
        user_identity="B1",
        max_target=b"\xff" * 32,
        nominal_hash_rate=1000000,
    )

    ret_b_1 = bootstrap_standard_channel_server(
        mining_server_context=mining_server_context,
        connection_context=connection_b,
        open_standard_mining_channel_message=open_standard_mining_channel_message_b_1,
    )

    print("=" * 50)
    print("=" * 50)
    print(
        "messages to be sent to the client in response to OpenStandardMiningChannel message b_1:"
    )
    for _, obj in enumerate(ret_b_1):
        print("-" * 50)
        print(pretty_format(obj))

    # imagine client B sends another OpenStandardMiningChannel message
    open_standard_mining_channel_message_b_2 = OpenStandardMiningChannel(
        request_id=2,
        user_identity="B2",
        max_target=b"\xff" * 32,
        nominal_hash_rate=1000000,
    )

    ret_b_2 = bootstrap_standard_channel_server(
        mining_server_context=mining_server_context,
        connection_context=connection_b,
        open_standard_mining_channel_message=open_standard_mining_channel_message_b_2,
    )

    print("=" * 50)
    print("=" * 50)
    print(
        "messages to be sent to the client in response to OpenStandardMiningChannel message b_2:"
    )
    for _, obj in enumerate(ret_b_2):
        print("-" * 50)
        print(pretty_format(obj))

    # imagine client C sends a OpenStandardMiningChannel message
    open_standard_mining_channel_message_c_1 = OpenStandardMiningChannel(
        request_id=1,
        user_identity="C1",
        max_target=b"\xff" * 32,
        nominal_hash_rate=1000000,
    )

    # we expect this to fail and no channel is created, so we don't really try to store it in the dictionary

    ret_c_1 = bootstrap_standard_channel_server(
        mining_server_context=mining_server_context,
        connection_context=connection_c,
        open_standard_mining_channel_message=open_standard_mining_channel_message_c_1,
    )

    print("=" * 50)
    print("=" * 50)
    print(
        "messages to be sent to the client in response to OpenStandardMiningChannel message c_1:"
    )
    for _, obj in enumerate(ret_c_1):
        print("-" * 50)
        print(pretty_format(obj))

    # finally, let's print the state of the connections

    print("=" * 50)
    print("=" * 50)
    print("connection_a.standard_channels:")
    for _, channel in connection_a.standard_channels.items():
        print(pretty_format(channel))
    print("-" * 50)
    print("connection_a.group_channel:")
    print(pretty_format(connection_a.group_channel))

    print("=" * 50)
    print("=" * 50)
    print("connection_b.standard_channels:")
    for _, channel in connection_b.standard_channels.items():
        print(pretty_format(channel))
    print("-" * 50)
    print("connection_b.group_channel:")
    print(pretty_format(connection_b.group_channel))

    print("=" * 50)
    print("=" * 50)
    print("connection_c.standard_channels:")
    for _, channel in connection_c.standard_channels.items():
        print(pretty_format(channel))
    print("-" * 50)
    print("connection_c.group_channel:")
    print(pretty_format(connection_c.group_channel))


if __name__ == "__main__":
    main()
