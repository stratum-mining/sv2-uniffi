/*
 * Example of how to bootstrap Stratum v2 Standard and Group Channels for
 * Mining Servers.
 *
 * Please note that the context is highly over-simplified, and reading this
 * example should not replace a good understanding of the SV2 protocol.
 *
 * We recommend reading the comments and trying to interpret the code as merely
 * a reference for API usage. We also highly recommend reading the SV2 protocol
 * specification.
 *
 * There are two distinct contexts that we need to consider:
 * - The context of the Mining Server
 * - The context of the Connection with the specific client
 *
 * We represent the Mining Server context as a MiningServerContext class, so
 * each instance of this class represents a different Mining Server.
 *
 * We represent the Connection context as a ConnectionContext class. Each
 * instance of this class represents a different Connection with a specific
 * client.
 *
 * WARNING: This does not mean you have to use these same MiningServerContext
 * and ConnectionContext classes in your code.
 *
 * These are for illustration purposes only, so you can understand how to
 * leverage the SV2 APIs under your own architecture.
 */

#include <cstdint>
#include <exception>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "example_utils.hpp"
#include "sv2.hpp"

namespace {

// Size of the static identifier for this pool server, placed at the start of
// the pool's extranonce allocation. One byte covers up to 256 distinct pool
// servers.
constexpr std::uint32_t POOL_SERVER_BYTES = 1;
// Maximum number of concurrent channels the pool can allocate. Determines
// POOL_LOCAL_PREFIX_BYTES via sv2_extranonce_bytes_needed. The internal
// allocation bitmap uses POOL_MAX_CHANNELS / 8 bytes of RAM.
constexpr std::uint32_t POOL_MAX_CHANNELS = 16'777'216;
// Bytes consumed by the per-channel local_index. Derived from
// POOL_MAX_CHANNELS so the two stay in sync.
const std::uint32_t POOL_LOCAL_PREFIX_BYTES =
    sv2::sv2_extranonce_bytes_needed(POOL_MAX_CHANNELS);
const std::uint32_t POOL_ALLOCATION_BYTES =
    POOL_SERVER_BYTES + POOL_LOCAL_PREFIX_BYTES;
constexpr std::uint32_t CLIENT_SEARCH_SPACE_BYTES = 16;
const std::uint32_t FULL_EXTRANONCE_SIZE =
    POOL_ALLOCATION_BYTES + CLIENT_SEARCH_SPACE_BYTES;

// Class that illustrates the context of a Mining Server.
class MiningServerContext {
public:
    // static_prefix is the one-byte identifier for this specific pool server.
    // It must fit within POOL_SERVER_BYTES.
    MiningServerContext(
        std::vector<std::uint8_t> static_prefix,
        sv2::NewTemplate cached_future_template,
        sv2::SetNewPrevHashTemplateDistribution cached_set_new_prev_hash_tdp,
        bool version_rolling_allowed,
        float expected_share_per_minute,
        std::uint32_t share_batch_size,
        std::string pool_tag_string,
        std::vector<std::uint8_t> pool_payout_script_pubkey
    )
        : extranonce_allocator(sv2::Sv2ExtranonceAllocator::init(
              static_prefix,
              FULL_EXTRANONCE_SIZE,
              POOL_MAX_CHANNELS
          )),
          cached_future_template(std::move(cached_future_template)),
          cached_set_new_prev_hash_tdp(std::move(cached_set_new_prev_hash_tdp)),
          version_rolling_allowed(version_rolling_allowed),
          expected_share_per_minute(expected_share_per_minute),
          share_batch_size(share_batch_size),
          pool_tag_string(std::move(pool_tag_string)),
          pool_payout_script_pubkey(std::move(pool_payout_script_pubkey)) {
        if (extranonce_allocator == nullptr) {
            throw std::runtime_error("Sv2ExtranonceAllocator::init returned null");
        }
    }

    // A unified allocator to generate unique Extranonce Prefixes for downstream
    // channels.
    std::shared_ptr<sv2::Sv2ExtranonceAllocator> extranonce_allocator;
    // A cached future template.
    sv2::NewTemplate cached_future_template;
    // A cached SetNewPrevHash from Template Distribution.
    sv2::SetNewPrevHashTemplateDistribution cached_set_new_prev_hash_tdp;
    // Whether version rolling is allowed. This is not really used in this
    // example, but it is useful context to keep.
    bool version_rolling_allowed;
    // Expected shares per minute.
    float expected_share_per_minute;
    // Number of successful shares acknowledged in a SubmitShares.Success.
    std::uint32_t share_batch_size;
    // Pool tag to write into scriptSig of the coinbase transaction for jobs
    // that are not declared by the client.
    std::string pool_tag_string;
    // Script pubkey to use for the coinbase reward output paying to the pool.
    std::vector<std::uint8_t> pool_payout_script_pubkey;
};

// Class that illustrates the context of a Connection with a specific client.
class ConnectionContext {
public:
    ConnectionContext(
        bool requires_standard_jobs,
        bool requires_work_selection,
        bool requires_version_rolling,
        MiningServerContext &mining_server_context
    )
        : requires_standard_jobs(requires_standard_jobs),
          requires_work_selection(requires_work_selection),
          requires_version_rolling(requires_version_rolling) {
        // Based on the SetupConnection.REQUIRES_STANDARD_JOBS and
        // SetupConnection.REQUIRES_WORK_SELECTION bit flags, decide whether to
        // create a Group Channel.
        if (this->requires_standard_jobs || this->requires_work_selection) {
            group_channel = nullptr;
        } else {
            // Bootstrap a group channel for this connection.
            group_channel = sv2::Sv2GroupChannelServer::init(
                next_channel_id(),
                FULL_EXTRANONCE_SIZE,
                mining_server_context.pool_tag_string
            );
            if (group_channel == nullptr) {
                throw std::runtime_error("Sv2GroupChannelServer::init returned null");
            }

            // It is up to us to set the coinbase reward output based on the
            // template revenue. This is also where merged mining OP_RETURNs
            // should be added.
            const std::vector<sv2::TxOutput> coinbase_reward_outputs{
                sv2::TxOutput{
                    .value = mining_server_context.cached_future_template.coinbase_tx_value_remaining,
                    .script_pubkey = mining_server_context.pool_payout_script_pubkey,
                },
            };

            // Bootstrap the group channel state with the cached future template.
            group_channel->on_new_template(
                mining_server_context.cached_future_template,
                coinbase_reward_outputs
            );

            // Activate the future job locally with the cached SetNewPrevHash.
            group_channel->on_set_new_prev_hash(
                mining_server_context.cached_set_new_prev_hash_tdp
            );
        }
    }

    // Allows us to guarantee unique channel_id values for the different
    // channels established with this specific client.
    std::uint32_t next_channel_id() {
        return next_channel_id_++;
    }

    // Whether SetupConnection.REQUIRES_STANDARD_JOBS bit flag was set.
    bool requires_standard_jobs;
    // Whether SetupConnection.REQUIRES_WORK_SELECTION bit flag was set.
    bool requires_work_selection;
    // Whether SetupConnection.REQUIRES_VERSION_ROLLING bit flag was set. This
    // is not really used in this example, but it is useful context to keep.
    bool requires_version_rolling;
    // Extended channels established with this specific client. This is not
    // really used in this example, but it is useful context to keep.
    std::map<std::uint32_t, std::shared_ptr<sv2::Sv2ExtendedChannelServer>> extended_channels;
    // Standard channels established with this specific client.
    std::map<std::uint32_t, std::shared_ptr<sv2::Sv2StandardChannelServer>> standard_channels;
    // A group channel established with this specific client, when supported by
    // the connection.
    std::shared_ptr<sv2::Sv2GroupChannelServer> group_channel;

private:
    std::uint32_t next_channel_id_ = 0;
};

std::vector<sv2::Sv2Message> bootstrap_standard_channel_server(
    MiningServerContext &mining_server_context,
    ConnectionContext &connection_context,
    const sv2::OpenStandardMiningChannel &open_standard_mining_channel_message
) {
    /*
     * This function emulates the process of bootstrapping a Standard Channel
     * after receiving an OpenStandardMiningChannel message from a client.
     *
     * It returns the list of messages to be sent to the client.
     */

    // If the client requires work selection, return an error, since Standard
    // Channels cannot be used for custom work.
    if (connection_context.requires_work_selection) {
        return {
            sv2::Sv2Message(
                sv2::Sv2Message::kOpenMiningChannelError{
                    .message = sv2::OpenMiningChannelError{
                        .request_id = open_standard_mining_channel_message.request_id,
                        .error_code = "standard-channels-not-supported-for-custom-work",
                    },
                }
            ),
        };
    }

    const auto extranonce_prefix =
        mining_server_context.extranonce_allocator->allocate_standard();

    std::shared_ptr<sv2::Sv2StandardChannelServer> new_standard_channel;

    try {
        new_standard_channel = sv2::Sv2StandardChannelServer::init(
            connection_context.next_channel_id(),
            open_standard_mining_channel_message.user_identity,
            extranonce_prefix,
            open_standard_mining_channel_message.max_target,
            open_standard_mining_channel_message.nominal_hash_rate,
            mining_server_context.share_batch_size,
            mining_server_context.expected_share_per_minute,
            mining_server_context.pool_tag_string
        );
    } catch (const sv2::Sv2ServerStandardChannelError &) {
        return {
            sv2::Sv2Message(
                sv2::Sv2Message::kOpenMiningChannelError{
                    .message = sv2::OpenMiningChannelError{
                        .request_id = open_standard_mining_channel_message.request_id,
                        .error_code = "other-error",
                    },
                }
            ),
        };
    }

    if (new_standard_channel == nullptr) {
        return {
            sv2::Sv2Message(
                sv2::Sv2Message::kOpenMiningChannelError{
                    .message = sv2::OpenMiningChannelError{
                        .request_id = open_standard_mining_channel_message.request_id,
                        .error_code = "other-error",
                    },
                }
            ),
        };
    }

    // We need to keep track of the new standard channel.
    connection_context.standard_channels[new_standard_channel->get_channel_id()] =
        new_standard_channel;

    std::uint32_t group_channel_id = 0;

    // If we are using the Group Channel, also add the Standard Channel id to
    // the group channel.
    if (!connection_context.requires_standard_jobs && connection_context.group_channel != nullptr) {
        group_channel_id = connection_context.group_channel->get_group_channel_id();
        connection_context.group_channel->add_channel_id(
            new_standard_channel->get_channel_id(),
            new_standard_channel->get_extranonce_prefix().size()
        );
    } else {
        // If we are not using the Group Channel, use a dummy channel_id which
        // will be meaningless across the lifespan of the connection.
        group_channel_id = 0;
    }

    // OpenStandardMiningChannelSuccess to be sent to the client.
    const auto open_standard_mining_channel_success =
        sv2::OpenStandardMiningChannelSuccess{
            .request_id = open_standard_mining_channel_message.request_id,
            .channel_id = new_standard_channel->get_channel_id(),
            .target = new_standard_channel->get_target(),
            .extranonce_prefix = new_standard_channel->get_extranonce_prefix(),
            .group_channel_id = group_channel_id,
        };

    // Initialize an array with messages to be sent to the client in response to
    // the OpenStandardMiningChannel message.
    std::vector<sv2::Sv2Message> ret_messages{
        sv2::Sv2Message(
            sv2::Sv2Message::kOpenStandardMiningChannelSuccess{
                .message = open_standard_mining_channel_success,
            }
        ),
    };

    // It is up to us to set the coinbase reward output based on the template
    // revenue. This is also where merged mining OP_RETURNs should be added.
    const std::vector<sv2::TxOutput> coinbase_reward_outputs{
        sv2::TxOutput{
            .value = mining_server_context.cached_future_template.coinbase_tx_value_remaining,
            .script_pubkey = mining_server_context.pool_payout_script_pubkey,
        },
    };

    // Bootstrap the channel state with the cached future template.
    new_standard_channel->on_new_template(
        mining_server_context.cached_future_template,
        coinbase_reward_outputs
    );

    // Get the job id for the future job.
    const auto future_standard_job_id =
        new_standard_channel->get_future_job_id_from_template_id(
            mining_server_context.cached_future_template.template_id
        );

    if (!future_standard_job_id.has_value()) {
        throw std::runtime_error("future standard job id was not cached");
    }

    // We are going to send the future job to the client. This one will be a
    // Standard Job, regardless of whether we are using the Group Channel or not.
    // This is only during the bootstrap process. Future jobs can be extended for
    // Group Channel clients, when the connection allows for it.
    const auto future_standard_job_message =
        new_standard_channel->get_future_job(*future_standard_job_id)
            ->get_job_message();

    // Activate the future job locally with the cached SetNewPrevHash.
    new_standard_channel->on_set_new_prev_hash(
        mining_server_context.cached_set_new_prev_hash_tdp
    );

    // We are going to send the SetNewPrevHashMining message to the client so
    // that the future job we just sent is also activated on the client side.
    const auto set_new_prev_hash_mp = sv2::SetNewPrevHashMining{
        .channel_id = new_standard_channel->get_channel_id(),
        .job_id = *future_standard_job_id,
        .prev_hash = mining_server_context.cached_set_new_prev_hash_tdp.prev_hash,
        .min_ntime = mining_server_context.cached_set_new_prev_hash_tdp.header_timestamp,
        .nbits = mining_server_context.cached_set_new_prev_hash_tdp.nbits,
    };

    ret_messages.push_back(
        sv2::Sv2Message(
            sv2::Sv2Message::kNewMiningJob{
                .message = future_standard_job_message,
            }
        )
    );
    ret_messages.push_back(
        sv2::Sv2Message(
            sv2::Sv2Message::kSetNewPrevHashMining{
                .message = set_new_prev_hash_mp,
            }
        )
    );
    return ret_messages;
}

std::string pretty_bytes(const std::vector<std::uint8_t> &bytes) {
    if (bytes.size() <= 8) {
        return "0x" + sv2cpp::example::hex(bytes);
    }

    std::vector<std::uint8_t> first(bytes.begin(), bytes.begin() + 4);
    std::vector<std::uint8_t> last(bytes.end() - 4, bytes.end());
    return "0x" + sv2cpp::example::hex(first) + "..." + sv2cpp::example::hex(last);
}

std::string pretty_format(
    const std::shared_ptr<sv2::Sv2StandardChannelServer> &channel
) {
    std::ostringstream oss;
    oss << "Sv2StandardChannelServer(channel_id=" << channel->get_channel_id() << ")";
    return oss.str();
}

std::string pretty_format(const std::shared_ptr<sv2::Sv2GroupChannelServer> &channel) {
    if (channel == nullptr) {
        return "None";
    }

    std::ostringstream oss;
    oss
        << "Sv2GroupChannelServer(group_channel_id="
        << channel->get_group_channel_id()
        << ", channel_ids=[";

    const auto channel_ids = channel->get_channel_ids();
    for (std::size_t i = 0; i < channel_ids.size(); ++i) {
        if (i > 0) {
            oss << ", ";
        }
        oss << channel_ids[i];
    }
    oss << "])";
    return oss.str();
}

std::string pretty_format(const sv2::OpenStandardMiningChannelSuccess &message) {
    std::ostringstream oss;
    oss
        << "OpenStandardMiningChannelSuccess("
        << "request_id=" << message.request_id
        << ", channel_id=" << message.channel_id
        << ", target=" << pretty_bytes(message.target)
        << ", extranonce_prefix=" << pretty_bytes(message.extranonce_prefix)
        << ", group_channel_id=" << message.group_channel_id
        << ")";
    return oss.str();
}

std::string pretty_format(const sv2::OpenMiningChannelError &message) {
    std::ostringstream oss;
    oss
        << "OpenMiningChannelError("
        << "request_id=" << message.request_id
        << ", error_code='" << message.error_code
        << "')";
    return oss.str();
}

std::string pretty_format(const sv2::NewMiningJob &message) {
    std::ostringstream oss;
    oss
        << "NewMiningJob("
        << "channel_id=" << message.channel_id
        << ", job_id=" << message.job_id
        << ", min_ntime=";
    if (message.min_ntime.has_value()) {
        oss << *message.min_ntime;
    } else {
        oss << "None";
    }
    oss
        << ", version=" << message.version
        << ", merkle_root=" << pretty_bytes(message.merkle_root)
        << ")";
    return oss.str();
}

std::string pretty_format(const sv2::SetNewPrevHashMining &message) {
    std::ostringstream oss;
    oss
        << "SetNewPrevHashMining("
        << "channel_id=" << message.channel_id
        << ", job_id=" << message.job_id
        << ", prev_hash=" << pretty_bytes(message.prev_hash)
        << ", min_ntime=" << message.min_ntime
        << ", nbits=" << message.nbits
        << ")";
    return oss.str();
}

std::string pretty_format(const sv2::Sv2Message &message) {
    const auto &variant = message.get_variant();

    if (std::holds_alternative<sv2::Sv2Message::kOpenStandardMiningChannelSuccess>(variant)) {
        return pretty_format(
            std::get<sv2::Sv2Message::kOpenStandardMiningChannelSuccess>(variant).message
        );
    }
    if (std::holds_alternative<sv2::Sv2Message::kOpenMiningChannelError>(variant)) {
        return pretty_format(
            std::get<sv2::Sv2Message::kOpenMiningChannelError>(variant).message
        );
    }
    if (std::holds_alternative<sv2::Sv2Message::kNewMiningJob>(variant)) {
        return pretty_format(
            std::get<sv2::Sv2Message::kNewMiningJob>(variant).message
        );
    }
    if (std::holds_alternative<sv2::Sv2Message::kSetNewPrevHashMining>(variant)) {
        return pretty_format(
            std::get<sv2::Sv2Message::kSetNewPrevHashMining>(variant).message
        );
    }

    return sv2cpp::example::message_type_name(message);
}

void print_response_messages(
    const std::string &label,
    const std::vector<sv2::Sv2Message> &messages
) {
    std::cout << std::string(50, '=') << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    std::cout
        << "messages to be sent to the client in response to "
        << label
        << ":"
        << std::endl;

    for (const auto &message : messages) {
        std::cout << std::string(50, '-') << std::endl;
        std::cout << pretty_format(message) << std::endl;
    }
}

} // namespace

int main() {
    try {
        std::cout << "Stratum v2 Standard Channel Server Example" << std::endl;

        auto mining_server_context = MiningServerContext(
            std::vector<std::uint8_t>{0x01},
            // In practice, new messages will be continuously cached as they
            // are sent from the Template Provider.
            sv2::NewTemplate{
                .template_id = 1,
                .future_template = true,
                .version = 536870912,
                .coinbase_tx_version = 2,
                .coinbase_prefix = sv2cpp::example::bytes_from_hex("022c0700"),
                .coinbase_tx_input_sequence = 4294967294,
                .coinbase_tx_value_remaining = 5'000'000'000ULL,
                .coinbase_tx_outputs_count = 1,
                .coinbase_tx_outputs = sv2cpp::example::bytes_from_hex(
                    "0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
                ),
                .coinbase_tx_locktime = 1835,
                .merkle_path = {},
            },
            // In practice, new messages will be continuously cached as they
            // are sent from the Template Provider.
            sv2::SetNewPrevHashTemplateDistribution{
                .template_id = 1,
                .prev_hash = sv2cpp::example::bytes_from_hex(
                    "809F529E2C93330426149012CB31AB5A83D5E59F7D089EE41DCD9F4174010000"
                ),
                .header_timestamp = 1754401525,
                .nbits = 503543726,
                .target = sv2cpp::example::bytes_from_hex(
                    "000000000000000000000000000000000000000000000000000000AE77030000"
                ),
            },
            true,
            10.0F,
            10,
            "pool-tag-string",
            sv2cpp::example::bytes_from_hex("0014ebe1b7dcc293ccaa0ee743a86f89df8258c208fc")
        );

        // Imagine three connections are established.

        // This client understands Group Channels.
        auto connection_a = ConnectionContext(
            false,
            false,
            false,
            mining_server_context
        );

        // This client does not understand Group Channels.
        auto connection_b = ConnectionContext(
            true,
            false,
            false,
            mining_server_context
        );

        // This client wants to work on custom jobs.
        auto connection_c = ConnectionContext(
            false,
            true,
            false,
            mining_server_context
        );

        // Imagine client A sends an OpenStandardMiningChannel message.
        const auto open_standard_mining_channel_message_a_1 =
            sv2::OpenStandardMiningChannel{
                .request_id = 1,
                .user_identity = "A1",
                .nominal_hash_rate = 1'000'000.0F,
                .max_target = sv2cpp::example::repeated_byte(0xff, 32),
            };

        const auto ret_a_1 = bootstrap_standard_channel_server(
            mining_server_context,
            connection_a,
            open_standard_mining_channel_message_a_1
        );

        print_response_messages(
            "OpenStandardMiningChannel message a_1",
            ret_a_1
        );

        // Imagine client A sends another OpenStandardMiningChannel message.
        const auto open_standard_mining_channel_message_a_2 =
            sv2::OpenStandardMiningChannel{
                .request_id = 2,
                .user_identity = "A2",
                .nominal_hash_rate = 1'000'000.0F,
                .max_target = sv2cpp::example::repeated_byte(0xff, 32),
            };

        const auto ret_a_2 = bootstrap_standard_channel_server(
            mining_server_context,
            connection_a,
            open_standard_mining_channel_message_a_2
        );

        print_response_messages(
            "OpenStandardMiningChannel message a_2",
            ret_a_2
        );

        // Imagine client B sends an OpenStandardMiningChannel message.
        const auto open_standard_mining_channel_message_b_1 =
            sv2::OpenStandardMiningChannel{
                .request_id = 1,
                .user_identity = "B1",
                .nominal_hash_rate = 1'000'000.0F,
                .max_target = sv2cpp::example::repeated_byte(0xff, 32),
            };

        const auto ret_b_1 = bootstrap_standard_channel_server(
            mining_server_context,
            connection_b,
            open_standard_mining_channel_message_b_1
        );

        print_response_messages(
            "OpenStandardMiningChannel message b_1",
            ret_b_1
        );

        // Imagine client B sends another OpenStandardMiningChannel message.
        const auto open_standard_mining_channel_message_b_2 =
            sv2::OpenStandardMiningChannel{
                .request_id = 2,
                .user_identity = "B2",
                .nominal_hash_rate = 1'000'000.0F,
                .max_target = sv2cpp::example::repeated_byte(0xff, 32),
            };

        const auto ret_b_2 = bootstrap_standard_channel_server(
            mining_server_context,
            connection_b,
            open_standard_mining_channel_message_b_2
        );

        print_response_messages(
            "OpenStandardMiningChannel message b_2",
            ret_b_2
        );

        // Imagine client C sends an OpenStandardMiningChannel message.
        const auto open_standard_mining_channel_message_c_1 =
            sv2::OpenStandardMiningChannel{
                .request_id = 1,
                .user_identity = "C1",
                .nominal_hash_rate = 1'000'000.0F,
                .max_target = sv2cpp::example::repeated_byte(0xff, 32),
            };

        // We expect this to fail and no channel is created, so we do not try to
        // store it in the dictionary.
        const auto ret_c_1 = bootstrap_standard_channel_server(
            mining_server_context,
            connection_c,
            open_standard_mining_channel_message_c_1
        );

        print_response_messages(
            "OpenStandardMiningChannel message c_1",
            ret_c_1
        );

        // Finally, print the state of the connections.

        std::cout << std::string(50, '=') << std::endl;
        std::cout << std::string(50, '=') << std::endl;
        std::cout << "connection_a.standard_channels:" << std::endl;
        for (const auto &[_, channel] : connection_a.standard_channels) {
            (void)_;
            std::cout << pretty_format(channel) << std::endl;
        }
        std::cout << std::string(50, '-') << std::endl;
        std::cout << "connection_a.group_channel:" << std::endl;
        std::cout << pretty_format(connection_a.group_channel) << std::endl;

        std::cout << std::string(50, '=') << std::endl;
        std::cout << std::string(50, '=') << std::endl;
        std::cout << "connection_b.standard_channels:" << std::endl;
        for (const auto &[_, channel] : connection_b.standard_channels) {
            (void)_;
            std::cout << pretty_format(channel) << std::endl;
        }
        std::cout << std::string(50, '-') << std::endl;
        std::cout << "connection_b.group_channel:" << std::endl;
        std::cout << pretty_format(connection_b.group_channel) << std::endl;

        std::cout << std::string(50, '=') << std::endl;
        std::cout << std::string(50, '=') << std::endl;
        std::cout << "connection_c.standard_channels:" << std::endl;
        for (const auto &[_, channel] : connection_c.standard_channels) {
            (void)_;
            std::cout << pretty_format(channel) << std::endl;
        }
        std::cout << std::string(50, '-') << std::endl;
        std::cout << "connection_c.group_channel:" << std::endl;
        std::cout << pretty_format(connection_c.group_channel) << std::endl;

        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Example failed: " << error.what() << std::endl;
        return 1;
    }
}
