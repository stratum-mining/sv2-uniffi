"""
Extended Channel Server tests for sv2-uniffi.

Tests that verify extended channel server functionality.
"""

SATS_AVAILABLE_IN_TEMPLATE = 5_000_000_000
CLIENT_SEARCH_SPACE_BYTES = 20

import traceback

def test_extended_channel_server():
    """Test extended channel server functionality."""
    try:
        from sv2 import Sv2ExtendedChannelServer, NewTemplate, TxOutput, SetNewPrevHashTemplateDistribution, SetCustomMiningJob

        # Create a new extended channel server using constructor directly
        extended_channel = Sv2ExtendedChannelServer(
            channel_id=1,
            user_identity="test",
            extranonce_prefix=b"\xFF" * 16,
            max_target=b"\xFF" * 32,
            nominal_hashrate=10_000.0,
            version_rolling_allowed=True,
            rollable_extranonce_size=CLIENT_SEARCH_SPACE_BYTES,
            share_batch_size=1,
            expected_share_per_minute=1.0,
            pool_tag_string="test",
        )

        # a future template to generate a future job on the channel
        template = NewTemplate(
            template_id=1,
            future_template=True,
            version=536870912,
            coinbase_tx_version=2,
            coinbase_prefix=b"\x00" * 32,
            coinbase_tx_input_sequence=4294967295,
            coinbase_tx_value_remaining=SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count=1,
            coinbase_tx_outputs=bytes([
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]),
            coinbase_tx_locktime=0,
            merkle_path=[]
        )

        # a tx output to be included in the coinbase transaction
        script = bytes([0, 20, 235, 225, 183, 220, 194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194, 8, 252])
        tx_output = TxOutput(value=SATS_AVAILABLE_IN_TEMPLATE, script_pubkey=script)

        # process the future template to generate a future job on the channel
        extended_channel.on_new_template(template, [tx_output])

        # get the job id for the future job using the template_id
        future_job_id = extended_channel.get_future_job_id_from_template_id(1)

        # check that the future job is set
        if future_job_id is None:
            raise Exception("no future job id found for template_id=1")

        job = extended_channel.get_future_job(future_job_id)
        if job is None:
            raise Exception("no future job found for job_id={}".format(future_job_id))

        # check that the job is future
        if not job.is_future():
            raise Exception("job is not future")
        
        # set the new prev hash for the future job
        ntime = 1746839905
        set_new_prev_hash = SetNewPrevHashTemplateDistribution(
            template_id=1,
            prev_hash=bytes([
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]),
            header_timestamp=ntime,
            nbits=503543726,
            target=bytes([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                174, 119, 3, 0, 0,
            ])
        )

        # set the new prev hash for the future job
        extended_channel.on_set_new_prev_hash(set_new_prev_hash)

        # check that the future job was activated
        active_job = extended_channel.get_active_job()
        if active_job.is_future():
            raise Exception("active job is not set")
        
        activated_job_id = active_job.get_job_id()

        # process a non-future template to create a new non-future job on the channel
        template = NewTemplate(
            template_id=1,
            future_template=False,
            version=536870912,
            coinbase_tx_version=2,
            coinbase_prefix=b"\x00" * 32,
            coinbase_tx_input_sequence=4294967295,
            coinbase_tx_value_remaining=SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count=1,
            coinbase_tx_outputs=bytes([
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]),
            coinbase_tx_locktime=0,
            merkle_path=[]
        )

        # process the non-future template to create a new non-future job on the channel
        extended_channel.on_new_template(template, [tx_output])

        # check that the active job is properly updated
        active_job = extended_channel.get_active_job()
        if active_job.get_job_id() == activated_job_id:
            raise Exception("active job is not updated with non-future template")

        cached_job_id = active_job.get_job_id()

        # get the current target
        current_target = extended_channel.get_target()

        # update the channel with a new hashrate
        new_hashrate = 1_000_000_000.0
        extended_channel.update_channel(new_hashrate, None)

        new_target = extended_channel.get_target()

        # check that the target is updated with the new hashrate
        if current_target == new_target:
            raise Exception("target is not updated")

        # set a custom mining job on the channel
        set_custom_mining_job = SetCustomMiningJob(
            channel_id=1,
            request_id=1,
            mining_job_token=bytes([]),
            version=536870912,
            prev_hash=bytes([
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]),
            min_ntime=ntime,
            nbits=503543726,
            coinbase_tx_version=2,
            coinbase_prefix=b"\x00" * 32,
            coinbase_tx_input_nsequence=4294967295,
            coinbase_tx_outputs=bytes([
                2, 0, 242, 5, 42, 1, 0, 0, 0, 22, 0, 20, 235, 225, 183, 220, 194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194, 8, 252, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249
            ]),
            coinbase_tx_locktime=0,
            merkle_path=[]
        )

        # set the custom mining job on the channel
        extended_channel.on_set_custom_mining_job(set_custom_mining_job)

        active_job = extended_channel.get_active_job()
        if active_job.get_job_id() == cached_job_id:
            raise Exception("active job is not updated with custom mining job")

        print("✓ Extended channel server test passed")
        return True
    
    except Exception as e:
        print(f"✗ Extended channel server test failed: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_extended_channel_server()
    exit(0 if success else 1)