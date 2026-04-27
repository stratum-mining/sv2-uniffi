#include <cstdint>
#include <functional>
#include <iostream>
#include <optional>
#include <vector>

#include "test_utils.hpp"

namespace {

constexpr uint64_t SATS_AVAILABLE_IN_TEMPLATE = 5'000'000'000ULL;
constexpr uint16_t CLIENT_SEARCH_SPACE_BYTES = 20;

std::vector<uint8_t> coinbase_tx_outputs_bytes() {
    return {
        0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170,
        33, 169, 237, 226, 246, 28, 63, 113, 209, 222,
        253, 63, 169, 153, 223, 163, 105, 83, 117, 92,
        105, 6, 137, 121, 153, 98, 180, 139, 235, 216,
        54, 151, 78, 140, 249,
    };
}

std::vector<uint8_t> prev_hash_bytes() {
    return {
        200, 53, 253, 129, 214, 31, 43, 84,
        179, 58, 58, 76, 128, 213, 24, 53,
        38, 144, 205, 88, 172, 20, 251, 22,
        217, 141, 21, 221, 21, 0, 0, 0,
    };
}

std::vector<uint8_t> target_bytes() {
    return {
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 174, 119, 3, 0, 0,
    };
}

std::vector<uint8_t> custom_mining_job_coinbase_outputs_bytes() {
    return {
        2, 0, 242, 5, 42, 1, 0, 0, 0, 22, 0, 20,
        235, 225, 183, 220, 194, 147, 204, 170, 14, 231,
        67, 168, 111, 137, 223, 130, 88, 194, 8, 252,
        0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170,
        33, 169, 237, 226, 246, 28, 63, 113, 209, 222,
        253, 63, 169, 153, 223, 163, 105, 83, 117, 92,
        105, 6, 137, 121, 153, 98, 180, 139, 235, 216,
        54, 151, 78, 140, 249,
    };
}

sv2::NewTemplate make_template(bool future_template) {
    return sv2::NewTemplate{
        .template_id = 1,
        .future_template = future_template,
        .version = 536870912,
        .coinbase_tx_version = 2,
        .coinbase_prefix = sv2cpp::test::repeated_byte(0x00, 32),
        .coinbase_tx_input_sequence = 4294967295,
        .coinbase_tx_value_remaining = SATS_AVAILABLE_IN_TEMPLATE,
        .coinbase_tx_outputs_count = 1,
        .coinbase_tx_outputs = coinbase_tx_outputs_bytes(),
        .coinbase_tx_locktime = 0,
        .merkle_path = {},
    };
}

sv2::TxOutput make_tx_output() {
    return sv2::TxOutput{
        .value = SATS_AVAILABLE_IN_TEMPLATE,
        .script_pubkey = {
            0, 20, 235, 225, 183, 220, 194, 147,
            204, 170, 14, 231, 67, 168, 111, 137,
            223, 130, 88, 194, 8, 252,
        },
    };
}

sv2::SetNewPrevHashTemplateDistribution make_set_new_prev_hash(uint32_t ntime) {
    return sv2::SetNewPrevHashTemplateDistribution{
        .template_id = 1,
        .prev_hash = prev_hash_bytes(),
        .header_timestamp = ntime,
        .nbits = 503543726,
        .target = target_bytes(),
    };
}

sv2::SetCustomMiningJob make_set_custom_mining_job(uint32_t ntime) {
    return sv2::SetCustomMiningJob{
        .channel_id = 1,
        .request_id = 1,
        .mining_job_token = {},
        .version = 536870912,
        .prev_hash = prev_hash_bytes(),
        .min_ntime = ntime,
        .nbits = 503543726,
        .coinbase_tx_version = 2,
        .coinbase_prefix = sv2cpp::test::repeated_byte(0x00, 32),
        .coinbase_tx_input_nsequence = 4294967295,
        .coinbase_tx_outputs = custom_mining_job_coinbase_outputs_bytes(),
        .coinbase_tx_locktime = 0,
        .merkle_path = {},
    };
}

} // namespace

int main() {
    return sv2cpp::test::run_test("Extended channel server lifecycle test", [] {
        using namespace sv2cpp::test;

        auto extranonce_allocator = sv2::Sv2ExtranonceAllocator::init(
            std::vector<uint8_t>{0xff},
            22,
            256
        );
        require(extranonce_allocator != nullptr, "extranonce allocator is null");

        auto extranonce_prefix = extranonce_allocator->allocate_extended(
            CLIENT_SEARCH_SPACE_BYTES
        );
        require(extranonce_prefix != nullptr, "extended extranonce prefix is null");

        auto extended_channel = sv2::Sv2ExtendedChannelServer::init(
            1,
            "test",
            extranonce_prefix,
            repeated_byte(0xff, 32),
            10'000.0F,
            true,
            CLIENT_SEARCH_SPACE_BYTES,
            1,
            1.0F,
            "test"
        );
        require(extended_channel != nullptr, "extended channel server is null");

        require_eq(
            extended_channel->get_channel_id(),
            1U,
            "extended channel id was not preserved"
        );
        require_eq(
            extended_channel->get_user_identity(),
            std::string("test"),
            "extended channel user identity was not preserved"
        );
        require_eq(
            extended_channel->get_rollable_extranonce_size(),
            CLIENT_SEARCH_SPACE_BYTES,
            "extended channel rollable extranonce size was not preserved"
        );
        require_eq(
            extended_channel->get_full_extranonce_size(),
            22ULL,
            "extended channel full extranonce size was unexpected"
        );

        const auto tx_output = make_tx_output();

        extended_channel->on_new_template(
            make_template(true),
            std::vector<sv2::TxOutput>{tx_output}
        );

        const auto future_job_id =
            extended_channel->get_future_job_id_from_template_id(1);

        require(
            future_job_id.has_value(),
            "no future job id found for template_id=1"
        );

        auto future_job = extended_channel->get_future_job(*future_job_id);
        require(future_job != nullptr, "no future job found for generated job id");
        require(future_job->is_future(), "future job was not marked as future");

        const auto ntime = 1746839905U;
        extended_channel->on_set_new_prev_hash(make_set_new_prev_hash(ntime));

        auto active_job = extended_channel->get_active_job();
        require(active_job != nullptr, "active job is null after SetNewPrevHash");
        require(!active_job->is_future(), "active job was still marked as future");

        const auto activated_job_id = active_job->get_job_id();

        extended_channel->on_new_template(
            make_template(false),
            std::vector<sv2::TxOutput>{tx_output}
        );

        active_job = extended_channel->get_active_job();
        require(active_job != nullptr, "active job is null after non-future template");
        require(
            active_job->get_job_id() != activated_job_id,
            "active job was not updated by non-future template"
        );

        const auto cached_job_id = active_job->get_job_id();
        const auto current_target = extended_channel->get_target();

        extended_channel->update_channel(
            1'000'000'000.0F,
            std::nullopt
        );

        const auto updated_target = extended_channel->get_target();
        require(
            current_target != updated_target,
            "target was not updated after hashrate change"
        );

        extended_channel->on_set_custom_mining_job(
            make_set_custom_mining_job(ntime)
        );

        active_job = extended_channel->get_active_job();
        require(active_job != nullptr, "active job is null after custom mining job");
        require(
            active_job->get_job_id() != cached_job_id,
            "active job was not updated by custom mining job"
        );
    });
}