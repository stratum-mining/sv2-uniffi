pub mod common;
pub mod error;
pub mod job_declaration;
pub mod mining;
pub mod template_distribution;

use crate::messages::{common::*, error::Sv2MessageError, mining::*};
use codec_sv2::binary_sv2::Sv2Option;
use common_messages_sv2::{
    ChannelEndpointChanged as InnerChannelEndpointChanged, Protocol as InnerProtocol,
    Reconnect as InnerReconnect, SetupConnection as InnerSetupConnection,
    SetupConnectionError as InnerSetupConnectionError,
    SetupConnectionSuccess as InnerSetupConnectionSuccess,
};
use mining_sv2::{
    CloseChannel as InnerCloseChannel, NewExtendedMiningJob as InnerNewExtendedMiningJob,
    NewMiningJob as InnerNewMiningJob, OpenExtendedMiningChannel as InnerOpenExtendedMiningChannel,
    OpenExtendedMiningChannelSuccess as InnerOpenExtendedMiningChannelSuccess,
    OpenMiningChannelError as InnerOpenMiningChannelError,
    OpenStandardMiningChannel as InnerOpenStandardMiningChannel,
    OpenStandardMiningChannelSuccess as InnerOpenStandardMiningChannelSuccess,
    SetCustomMiningJob as InnerSetCustomMiningJob,
    SetCustomMiningJobError as InnerSetCustomMiningJobError,
    SetCustomMiningJobSuccess as InnerSetCustomMiningJobSuccess,
    SetExtranoncePrefix as InnerSetExtranoncePrefix, SetGroupChannel as InnerSetGroupChannel,
    SetNewPrevHash as InnerSetNewPrevHashMp, SetTarget as InnerSetTarget,
    SubmitSharesError as InnerSubmitSharesError, SubmitSharesExtended as InnerSubmitSharesExtended,
    SubmitSharesStandard as InnerSubmitSharesStandard,
    SubmitSharesSuccess as InnerSubmitSharesSuccess, UpdateChannel as InnerUpdateChannel,
    UpdateChannelError as InnerUpdateChannelError,
};
use parsers_sv2::{
    AnyMessage as InnerAnyMessage, CommonMessages as InnerCommonMessages,
    Mining as InnerMiningMessages,
};

use std::convert::{TryFrom, TryInto};

/// Provides UniFFI interfaces for every possible Sv2 message type.
///
/// This is used for encoding and decoding messages over the encrypted connection.
#[derive(uniffi::Enum)]
pub enum Sv2Message {
    // common messages
    SetupConnection(SetupConnection),
    SetupConnectionSuccess(SetupConnectionSuccess),
    SetupConnectionError(SetupConnectionError),
    ChannelEndpointChanged(ChannelEndpointChanged),
    Reconnect(Reconnect),
    // mining subprotocol messages
    OpenStandardMiningChannel(OpenStandardMiningChannel),
    OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess),
    OpenExtendedMiningChannel(OpenExtendedMiningChannel),
    OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess),
    OpenMiningChannelError(OpenMiningChannelError),
    UpdateChannel(UpdateChannel),
    UpdateChannelError(UpdateChannelError),
    CloseChannel(CloseChannel),
    SetExtranoncePrefix(SetExtranoncePrefix),
    SubmitSharesStandard(SubmitSharesStandard),
    SubmitSharesExtended(SubmitSharesExtended),
    SubmitSharesSuccess(SubmitSharesSuccess),
    SubmitSharesError(SubmitSharesError),
    NewMiningJob(NewMiningJob),
    NewExtendedMiningJob(NewExtendedMiningJob),
    SetNewPrevHashMining(SetNewPrevHashMining),
    SetCustomMiningJob(SetCustomMiningJob),
    SetCustomMiningJobSuccess(SetCustomMiningJobSuccess),
    SetCustomMiningJobError(SetCustomMiningJobError),
    SetTarget(SetTarget),
    SetGroupChannel(SetGroupChannel),
    // job declaration subprotocol messages
    // template distribution subprotocol messages
}

/// Convert from UniFFI Sv2Message to internal InnerAnyMessage
pub fn sv2_message_to_inner(
    sv2_message: Sv2Message,
) -> Result<InnerAnyMessage<'static>, Sv2MessageError> {
    match sv2_message {
        Sv2Message::SetupConnection(setup_connection) => {
            let protocol = InnerProtocol::try_from(setup_connection.protocol)
                .map_err(|_| Sv2MessageError::FailedToConvertProtocol)?;
            let inner_setup_connection = InnerSetupConnection {
                protocol,
                min_version: setup_connection.min_version,
                max_version: setup_connection.max_version,
                flags: setup_connection.flags,
                endpoint_host: setup_connection
                    .endpoint_host
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
                endpoint_port: setup_connection.endpoint_port,
                vendor: setup_connection
                    .vendor
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
                hardware_version: setup_connection
                    .hardware_version
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
                firmware: setup_connection
                    .firmware
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
                device_id: setup_connection
                    .device_id
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
            };
            let inner_message = InnerAnyMessage::Common(InnerCommonMessages::SetupConnection(
                inner_setup_connection,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SetupConnectionSuccess(setup_connection_success) => {
            let inner_setup_connection_success = InnerSetupConnectionSuccess {
                used_version: setup_connection_success.used_version,
                flags: setup_connection_success.flags,
            };
            let inner_message = InnerAnyMessage::Common(
                InnerCommonMessages::SetupConnectionSuccess(inner_setup_connection_success),
            );
            Ok(inner_message.into_static())
        }
        Sv2Message::SetupConnectionError(setup_connection_error) => {
            let inner_setup_connection_error = InnerSetupConnectionError {
                flags: setup_connection_error.flags,
                error_code: setup_connection_error
                    .error_code
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
            };
            let inner_message = InnerAnyMessage::Common(InnerCommonMessages::SetupConnectionError(
                inner_setup_connection_error,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::ChannelEndpointChanged(channel_endpoint_changed) => {
            let inner_channel_endpoint_changed = InnerChannelEndpointChanged {
                channel_id: channel_endpoint_changed.channel_id,
            };
            let inner_message = InnerAnyMessage::Common(
                InnerCommonMessages::ChannelEndpointChanged(inner_channel_endpoint_changed),
            );
            Ok(inner_message.into_static())
        }
        Sv2Message::Reconnect(reconnect) => {
            let inner_reconnect = InnerReconnect {
                new_host: reconnect
                    .new_host
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
                new_port: reconnect.new_port,
            };
            let inner_message =
                InnerAnyMessage::Common(InnerCommonMessages::Reconnect(inner_reconnect));
            Ok(inner_message.into_static())
        }
        Sv2Message::OpenStandardMiningChannel(open_standard_mining_channel) => {
            let max_target: [u8; 32] = open_standard_mining_channel
                .max_target
                .try_into()
                .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?;
            let inner_open_standard_mining_channel = InnerOpenStandardMiningChannel {
                request_id: open_standard_mining_channel.request_id.into(),
                user_identity: open_standard_mining_channel
                    .user_identity
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
                nominal_hash_rate: open_standard_mining_channel.nominal_hash_rate,
                max_target: max_target.into(),
            };
            let inner_message = InnerAnyMessage::Mining(
                InnerMiningMessages::OpenStandardMiningChannel(inner_open_standard_mining_channel),
            );
            Ok(inner_message.into_static())
        }
        Sv2Message::OpenStandardMiningChannelSuccess(open_standard_mining_channel_success) => {
            let target: [u8; 32] = open_standard_mining_channel_success
                .target
                .try_into()
                .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?;
            let inner_open_standard_mining_channel_success =
                InnerOpenStandardMiningChannelSuccess {
                    request_id: open_standard_mining_channel_success.request_id.into(),
                    channel_id: open_standard_mining_channel_success.channel_id.into(),
                    target: target.into(),
                    extranonce_prefix: open_standard_mining_channel_success
                        .extranonce_prefix
                        .try_into()
                        .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                    group_channel_id: open_standard_mining_channel_success.group_channel_id.into(),
                };
            let inner_message =
                InnerAnyMessage::Mining(InnerMiningMessages::OpenStandardMiningChannelSuccess(
                    inner_open_standard_mining_channel_success,
                ));
            Ok(inner_message.into_static())
        }
        Sv2Message::OpenExtendedMiningChannel(open_extended_mining_channel) => {
            let max_target: [u8; 32] = open_extended_mining_channel
                .max_target
                .try_into()
                .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?;
            let inner_open_extended_mining_channel = InnerOpenExtendedMiningChannel {
                request_id: open_extended_mining_channel.request_id.into(),
                user_identity: open_extended_mining_channel
                    .user_identity
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
                nominal_hash_rate: open_extended_mining_channel.nominal_hash_rate,
                max_target: max_target.into(),
                min_extranonce_size: open_extended_mining_channel.min_extranonce_size,
            };
            let inner_message = InnerAnyMessage::Mining(
                InnerMiningMessages::OpenExtendedMiningChannel(inner_open_extended_mining_channel),
            );
            Ok(inner_message.into_static())
        }
        Sv2Message::OpenExtendedMiningChannelSuccess(open_extended_mining_channel_success) => {
            let target: [u8; 32] = open_extended_mining_channel_success
                .target
                .try_into()
                .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?;
            let inner_open_extended_mining_channel_success =
                InnerOpenExtendedMiningChannelSuccess {
                    request_id: open_extended_mining_channel_success.request_id.into(),
                    channel_id: open_extended_mining_channel_success.channel_id.into(),
                    target: target.into(),
                    extranonce_prefix: open_extended_mining_channel_success
                        .extranonce_prefix
                        .try_into()
                        .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                    extranonce_size: open_extended_mining_channel_success.extranonce_size,
                };
            let inner_message =
                InnerAnyMessage::Mining(InnerMiningMessages::OpenExtendedMiningChannelSuccess(
                    inner_open_extended_mining_channel_success,
                ));
            Ok(inner_message.into_static())
        }
        Sv2Message::OpenMiningChannelError(open_mining_channel_error) => {
            let inner_open_mining_channel_error = InnerOpenMiningChannelError {
                request_id: open_mining_channel_error.request_id.into(),
                error_code: open_mining_channel_error
                    .error_code
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
            };
            let inner_message = InnerAnyMessage::Mining(
                InnerMiningMessages::OpenMiningChannelError(inner_open_mining_channel_error),
            );
            Ok(inner_message.into_static())
        }
        Sv2Message::UpdateChannel(update_channel) => {
            let maximum_target: [u8; 32] = update_channel
                .maximum_target
                .try_into()
                .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?;
            let inner_update_channel = InnerUpdateChannel {
                channel_id: update_channel.channel_id.into(),
                nominal_hash_rate: update_channel.nominal_hash_rate,
                maximum_target: maximum_target.into(),
            };
            let inner_message =
                InnerAnyMessage::Mining(InnerMiningMessages::UpdateChannel(inner_update_channel));
            Ok(inner_message.into_static())
        }
        Sv2Message::UpdateChannelError(update_channel_error) => {
            let inner_update_channel_error = InnerUpdateChannelError {
                channel_id: update_channel_error.channel_id.into(),
                error_code: update_channel_error
                    .error_code
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::UpdateChannelError(
                inner_update_channel_error,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::CloseChannel(close_channel) => {
            let inner_close_channel = InnerCloseChannel {
                channel_id: close_channel.channel_id.into(),
                reason_code: close_channel
                    .reason_code
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
            };
            let inner_message =
                InnerAnyMessage::Mining(InnerMiningMessages::CloseChannel(inner_close_channel));
            Ok(inner_message.into_static())
        }
        Sv2Message::SetExtranoncePrefix(set_extranonce_prefix) => {
            let inner_set_extranonce_prefix = InnerSetExtranoncePrefix {
                channel_id: set_extranonce_prefix.channel_id.into(),
                extranonce_prefix: set_extranonce_prefix
                    .extranonce_prefix
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SetExtranoncePrefix(
                inner_set_extranonce_prefix,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SubmitSharesStandard(submit_shares_standard) => {
            let inner_submit_shares_standard = InnerSubmitSharesStandard {
                channel_id: submit_shares_standard.channel_id.into(),
                sequence_number: submit_shares_standard.sequence_number,
                job_id: submit_shares_standard.job_id,
                nonce: submit_shares_standard.nonce,
                ntime: submit_shares_standard.ntime,
                version: submit_shares_standard.version,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesStandard(
                inner_submit_shares_standard,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SubmitSharesExtended(submit_shares_extended) => {
            let inner_submit_shares_extended = InnerSubmitSharesExtended {
                channel_id: submit_shares_extended.channel_id.into(),
                sequence_number: submit_shares_extended.sequence_number,
                job_id: submit_shares_extended.job_id,
                nonce: submit_shares_extended.nonce,
                ntime: submit_shares_extended.ntime,
                version: submit_shares_extended.version,
                extranonce: submit_shares_extended
                    .extranonce
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesExtended(
                inner_submit_shares_extended,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SubmitSharesSuccess(submit_shares_success) => {
            let inner_submit_shares_success = InnerSubmitSharesSuccess {
                channel_id: submit_shares_success.channel_id.into(),
                last_sequence_number: submit_shares_success.last_sequence_number,
                new_submits_accepted_count: submit_shares_success.new_submits_accepted_count,
                new_shares_sum: submit_shares_success.new_shares_sum,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesSuccess(
                inner_submit_shares_success,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SubmitSharesError(submit_shares_error) => {
            let inner_submit_shares_error = InnerSubmitSharesError {
                channel_id: submit_shares_error.channel_id.into(),
                sequence_number: submit_shares_error.sequence_number,
                error_code: submit_shares_error
                    .error_code
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesError(
                inner_submit_shares_error,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::NewMiningJob(new_mining_job) => {
            let min_ntime = Sv2Option::new(new_mining_job.min_ntime);
            let inner_new_mining_job = InnerNewMiningJob {
                channel_id: new_mining_job.channel_id.into(),
                job_id: new_mining_job.job_id,
                min_ntime: min_ntime,
                version: new_mining_job.version,
                merkle_root: new_mining_job
                    .merkle_root
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
            };
            let inner_message =
                InnerAnyMessage::Mining(InnerMiningMessages::NewMiningJob(inner_new_mining_job));
            Ok(inner_message.into_static())
        }
        Sv2Message::NewExtendedMiningJob(new_extended_mining_job) => {
            let merkle_path: Vec<_> = new_extended_mining_job
                .merkle_path
                .into_iter()
                .map(|path| {
                    path.try_into()
                        .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let merkle_path = merkle_path.into();

            let inner_new_extended_mining_job = InnerNewExtendedMiningJob {
                channel_id: new_extended_mining_job.channel_id.into(),
                job_id: new_extended_mining_job.job_id,
                min_ntime: Sv2Option::new(new_extended_mining_job.min_ntime),
                version: new_extended_mining_job.version,
                version_rolling_allowed: new_extended_mining_job.version_rolling_allowed,
                merkle_path,
                coinbase_tx_prefix: new_extended_mining_job
                    .coinbase_tx_prefix
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                coinbase_tx_suffix: new_extended_mining_job
                    .coinbase_tx_suffix
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::NewExtendedMiningJob(
                inner_new_extended_mining_job,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SetNewPrevHashMining(set_new_prev_hash) => {
            let inner_set_new_prev_hash = InnerSetNewPrevHashMp {
                channel_id: set_new_prev_hash.channel_id.into(),
                job_id: set_new_prev_hash.job_id,
                prev_hash: set_new_prev_hash
                    .prev_hash
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                min_ntime: set_new_prev_hash.min_ntime,
                nbits: set_new_prev_hash.nbits,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SetNewPrevHash(
                inner_set_new_prev_hash,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SetCustomMiningJob(set_custom_mining_job) => {
            let merkle_path: Vec<_> = set_custom_mining_job
                .merkle_path
                .into_iter()
                .map(|path| {
                    path.try_into()
                        .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let merkle_path = merkle_path.into();
            let inner_set_custom_mining_job = InnerSetCustomMiningJob {
                channel_id: set_custom_mining_job.channel_id.into(),
                request_id: set_custom_mining_job.request_id,
                token: set_custom_mining_job
                    .mining_job_token
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                version: set_custom_mining_job.version,
                prev_hash: set_custom_mining_job
                    .prev_hash
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                min_ntime: set_custom_mining_job.min_ntime,
                nbits: set_custom_mining_job.nbits,
                coinbase_tx_version: set_custom_mining_job.coinbase_tx_version,
                coinbase_prefix: set_custom_mining_job
                    .coinbase_prefix
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                coinbase_tx_input_n_sequence: set_custom_mining_job.coinbase_tx_input_nsequence,
                coinbase_tx_outputs: set_custom_mining_job
                    .coinbase_tx_outputs
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
                coinbase_tx_locktime: set_custom_mining_job.coinbase_tx_locktime,
                merkle_path,
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SetCustomMiningJob(
                inner_set_custom_mining_job,
            ));
            Ok(inner_message.into_static())
        }
        Sv2Message::SetCustomMiningJobSuccess(set_custom_mining_job_success) => {
            let inner_set_custom_mining_job_success = InnerSetCustomMiningJobSuccess {
                channel_id: set_custom_mining_job_success.channel_id.into(),
                request_id: set_custom_mining_job_success.request_id,
                job_id: set_custom_mining_job_success.job_id,
            };
            let inner_message = InnerAnyMessage::Mining(
                InnerMiningMessages::SetCustomMiningJobSuccess(inner_set_custom_mining_job_success),
            );
            Ok(inner_message.into_static())
        }
        Sv2Message::SetCustomMiningJobError(set_custom_mining_job_error) => {
            let inner_set_custom_mining_job_error = InnerSetCustomMiningJobError {
                channel_id: set_custom_mining_job_error.channel_id.into(),
                request_id: set_custom_mining_job_error.request_id,
                error_code: set_custom_mining_job_error
                    .error_code
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeString)?,
            };
            let inner_message = InnerAnyMessage::Mining(
                InnerMiningMessages::SetCustomMiningJobError(inner_set_custom_mining_job_error),
            );
            Ok(inner_message.into_static())
        }
        Sv2Message::SetTarget(set_target) => {
            let inner_set_target = InnerSetTarget {
                channel_id: set_target.channel_id.into(),
                maximum_target: set_target
                    .maximum_target
                    .try_into()
                    .map_err(|_| Sv2MessageError::FailedToSerializeByteArray)?,
            };
            let inner_message =
                InnerAnyMessage::Mining(InnerMiningMessages::SetTarget(inner_set_target));
            Ok(inner_message.into_static())
        }
        Sv2Message::SetGroupChannel(set_group_channel) => {
            let inner_set_group_channel = InnerSetGroupChannel {
                group_channel_id: set_group_channel.group_channel_id.into(),
                channel_ids: set_group_channel.channel_ids.into(),
            };
            let inner_message = InnerAnyMessage::Mining(InnerMiningMessages::SetGroupChannel(
                inner_set_group_channel,
            ));
            Ok(inner_message.into_static())
        }
        _ => todo!(),
    }
}

/// Convert from internal InnerAnyMessage to UniFFI Sv2Messages
pub fn inner_to_sv2_message(inner: &InnerAnyMessage<'static>) -> Sv2Message {
    match inner {
        InnerAnyMessage::Common(InnerCommonMessages::SetupConnection(inner_setup_connection)) => {
            Sv2Message::SetupConnection(SetupConnection {
                protocol: inner_setup_connection.protocol as u8,
                min_version: inner_setup_connection.min_version,
                max_version: inner_setup_connection.max_version,
                flags: inner_setup_connection.flags,
                endpoint_host: String::from_utf8_lossy(
                    inner_setup_connection.endpoint_host.inner_as_ref(),
                )
                .to_string(),
                endpoint_port: inner_setup_connection.endpoint_port,
                vendor: String::from_utf8_lossy(inner_setup_connection.vendor.inner_as_ref())
                    .to_string(),
                hardware_version: String::from_utf8_lossy(
                    inner_setup_connection.hardware_version.inner_as_ref(),
                )
                .to_string(),
                firmware: String::from_utf8_lossy(inner_setup_connection.firmware.inner_as_ref())
                    .to_string(),
                device_id: String::from_utf8_lossy(inner_setup_connection.device_id.inner_as_ref())
                    .to_string(),
            })
        }
        InnerAnyMessage::Common(InnerCommonMessages::SetupConnectionSuccess(
            inner_setup_connection_success,
        )) => Sv2Message::SetupConnectionSuccess(SetupConnectionSuccess {
            used_version: inner_setup_connection_success.used_version,
            flags: inner_setup_connection_success.flags,
        }),
        InnerAnyMessage::Common(InnerCommonMessages::SetupConnectionError(
            inner_setup_connection_error,
        )) => Sv2Message::SetupConnectionError(SetupConnectionError {
            flags: inner_setup_connection_error.flags,
            error_code: String::from_utf8_lossy(
                inner_setup_connection_error.error_code.inner_as_ref(),
            )
            .to_string(),
        }),
        InnerAnyMessage::Common(InnerCommonMessages::ChannelEndpointChanged(
            inner_channel_endpoint_changed,
        )) => Sv2Message::ChannelEndpointChanged(ChannelEndpointChanged {
            channel_id: inner_channel_endpoint_changed.channel_id,
        }),
        InnerAnyMessage::Common(InnerCommonMessages::Reconnect(inner_reconnect)) => {
            Sv2Message::Reconnect(Reconnect {
                new_host: String::from_utf8_lossy(inner_reconnect.new_host.inner_as_ref())
                    .to_string(),
                new_port: inner_reconnect.new_port,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::OpenStandardMiningChannel(
            inner_open_standard_mining_channel,
        )) => {
            // Convert request_id from Inner<4 bytes> to u32
            let request_id = u32::from_le_bytes(
                inner_open_standard_mining_channel
                    .request_id
                    .inner_as_ref()
                    .try_into()
                    .expect("request_id should be exactly 4 bytes"),
            );

            // Convert max_target from Inner<32 bytes> to Vec<u8>
            let max_target = inner_open_standard_mining_channel
                .max_target
                .inner_as_ref()
                .to_vec();

            Sv2Message::OpenStandardMiningChannel(OpenStandardMiningChannel {
                request_id,
                user_identity: String::from_utf8_lossy(
                    inner_open_standard_mining_channel
                        .user_identity
                        .inner_as_ref(),
                )
                .to_string(),
                nominal_hash_rate: inner_open_standard_mining_channel.nominal_hash_rate,
                max_target,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::OpenStandardMiningChannelSuccess(
            inner_open_standard_mining_channel_success,
        )) => {
            let target = inner_open_standard_mining_channel_success
                .target
                .inner_as_ref()
                .to_vec();
            let extranonce_prefix = inner_open_standard_mining_channel_success
                .extranonce_prefix
                .inner_as_ref()
                .to_vec();
            Sv2Message::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess {
                request_id: (&inner_open_standard_mining_channel_success.request_id).into(),
                channel_id: inner_open_standard_mining_channel_success.channel_id.into(),
                target,
                extranonce_prefix,
                group_channel_id: inner_open_standard_mining_channel_success
                    .group_channel_id
                    .into(),
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::OpenExtendedMiningChannel(
            inner_open_extended_mining_channel,
        )) => {
            let max_target = inner_open_extended_mining_channel
                .max_target
                .inner_as_ref()
                .to_vec();
            Sv2Message::OpenExtendedMiningChannel(OpenExtendedMiningChannel {
                request_id: inner_open_extended_mining_channel.request_id.into(),
                user_identity: String::from_utf8_lossy(
                    inner_open_extended_mining_channel
                        .user_identity
                        .inner_as_ref(),
                )
                .to_string(),
                nominal_hash_rate: inner_open_extended_mining_channel.nominal_hash_rate,
                max_target,
                min_extranonce_size: inner_open_extended_mining_channel.min_extranonce_size,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::OpenExtendedMiningChannelSuccess(
            inner_open_extended_mining_channel_success,
        )) => {
            let target = inner_open_extended_mining_channel_success
                .target
                .inner_as_ref()
                .to_vec();
            let extranonce_prefix = inner_open_extended_mining_channel_success
                .extranonce_prefix
                .inner_as_ref()
                .to_vec();
            Sv2Message::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
                request_id: inner_open_extended_mining_channel_success.request_id.into(),
                channel_id: inner_open_extended_mining_channel_success.channel_id.into(),
                target,
                extranonce_prefix,
                extranonce_size: inner_open_extended_mining_channel_success.extranonce_size,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::OpenMiningChannelError(
            inner_open_mining_channel_error,
        )) => Sv2Message::OpenMiningChannelError(OpenMiningChannelError {
            request_id: inner_open_mining_channel_error.request_id.into(),
            error_code: String::from_utf8_lossy(
                inner_open_mining_channel_error.error_code.inner_as_ref(),
            )
            .to_string(),
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::UpdateChannel(inner_update_channel)) => {
            let maximum_target = inner_update_channel.maximum_target.inner_as_ref().to_vec();
            Sv2Message::UpdateChannel(UpdateChannel {
                channel_id: inner_update_channel.channel_id.into(),
                nominal_hash_rate: inner_update_channel.nominal_hash_rate,
                maximum_target,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::UpdateChannelError(
            inner_update_channel_error,
        )) => Sv2Message::UpdateChannelError(UpdateChannelError {
            channel_id: inner_update_channel_error.channel_id.into(),
            error_code: String::from_utf8_lossy(
                inner_update_channel_error.error_code.inner_as_ref(),
            )
            .to_string(),
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::CloseChannel(inner_close_channel)) => {
            Sv2Message::CloseChannel(CloseChannel {
                channel_id: inner_close_channel.channel_id.into(),
                reason_code: String::from_utf8_lossy(
                    inner_close_channel.reason_code.inner_as_ref(),
                )
                .to_string(),
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::SetExtranoncePrefix(
            inner_set_extranonce_prefix,
        )) => Sv2Message::SetExtranoncePrefix(SetExtranoncePrefix {
            channel_id: inner_set_extranonce_prefix.channel_id.into(),
            extranonce_prefix: inner_set_extranonce_prefix
                .extranonce_prefix
                .inner_as_ref()
                .to_vec(),
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesStandard(
            inner_submit_shares_standard,
        )) => Sv2Message::SubmitSharesStandard(SubmitSharesStandard {
            channel_id: inner_submit_shares_standard.channel_id.into(),
            sequence_number: inner_submit_shares_standard.sequence_number,
            job_id: inner_submit_shares_standard.job_id,
            nonce: inner_submit_shares_standard.nonce,
            ntime: inner_submit_shares_standard.ntime,
            version: inner_submit_shares_standard.version,
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesExtended(
            inner_submit_shares_extended,
        )) => Sv2Message::SubmitSharesExtended(SubmitSharesExtended {
            channel_id: inner_submit_shares_extended.channel_id.into(),
            sequence_number: inner_submit_shares_extended.sequence_number,
            job_id: inner_submit_shares_extended.job_id,
            nonce: inner_submit_shares_extended.nonce,
            ntime: inner_submit_shares_extended.ntime,
            version: inner_submit_shares_extended.version,
            extranonce: inner_submit_shares_extended
                .extranonce
                .inner_as_ref()
                .to_vec(),
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesSuccess(
            inner_submit_shares_success,
        )) => Sv2Message::SubmitSharesSuccess(SubmitSharesSuccess {
            channel_id: inner_submit_shares_success.channel_id.into(),
            last_sequence_number: inner_submit_shares_success.last_sequence_number,
            new_submits_accepted_count: inner_submit_shares_success.new_submits_accepted_count,
            new_shares_sum: inner_submit_shares_success.new_shares_sum,
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::SubmitSharesError(
            inner_submit_shares_error,
        )) => Sv2Message::SubmitSharesError(SubmitSharesError {
            channel_id: inner_submit_shares_error.channel_id.into(),
            sequence_number: inner_submit_shares_error.sequence_number,
            error_code: String::from_utf8_lossy(
                inner_submit_shares_error.error_code.inner_as_ref(),
            )
            .to_string(),
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::NewMiningJob(inner_new_mining_job)) => {
            let merkle_root = inner_new_mining_job.merkle_root.inner_as_ref().to_vec();
            let min_ntime = match inner_new_mining_job.min_ntime.clone().into_inner() {
                Some(ntime) => Some(ntime),
                None => None,
            };
            Sv2Message::NewMiningJob(NewMiningJob {
                channel_id: inner_new_mining_job.channel_id.into(),
                job_id: inner_new_mining_job.job_id,
                min_ntime,
                version: inner_new_mining_job.version,
                merkle_root,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::NewExtendedMiningJob(
            inner_new_extended_mining_job,
        )) => {
            let merkle_path = inner_new_extended_mining_job
                .merkle_path
                .clone()
                .into_inner()
                .iter()
                .map(|path| path.inner_as_ref().to_vec())
                .collect();
            let min_ntime = match inner_new_extended_mining_job.min_ntime.clone().into_inner() {
                Some(ntime) => Some(ntime),
                None => None,
            };
            Sv2Message::NewExtendedMiningJob(NewExtendedMiningJob {
                channel_id: inner_new_extended_mining_job.channel_id.into(),
                job_id: inner_new_extended_mining_job.job_id,
                min_ntime,
                version: inner_new_extended_mining_job.version,
                version_rolling_allowed: inner_new_extended_mining_job.version_rolling_allowed,
                merkle_path,
                coinbase_tx_prefix: inner_new_extended_mining_job
                    .coinbase_tx_prefix
                    .inner_as_ref()
                    .to_vec(),
                coinbase_tx_suffix: inner_new_extended_mining_job
                    .coinbase_tx_suffix
                    .inner_as_ref()
                    .to_vec(),
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::SetNewPrevHash(inner_set_new_prev_hash)) => {
            Sv2Message::SetNewPrevHashMining(SetNewPrevHashMining {
                channel_id: inner_set_new_prev_hash.channel_id.into(),
                job_id: inner_set_new_prev_hash.job_id,
                prev_hash: inner_set_new_prev_hash.prev_hash.inner_as_ref().to_vec(),
                min_ntime: inner_set_new_prev_hash.min_ntime,
                nbits: inner_set_new_prev_hash.nbits,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::SetCustomMiningJob(
            inner_set_custom_mining_job,
        )) => {
            let merkle_path = inner_set_custom_mining_job
                .merkle_path
                .clone()
                .into_inner()
                .iter()
                .map(|path| path.inner_as_ref().to_vec())
                .collect();
            Sv2Message::SetCustomMiningJob(SetCustomMiningJob {
                channel_id: inner_set_custom_mining_job.channel_id.into(),
                request_id: inner_set_custom_mining_job.request_id,
                mining_job_token: inner_set_custom_mining_job.token.inner_as_ref().to_vec(),
                version: inner_set_custom_mining_job.version,
                prev_hash: inner_set_custom_mining_job
                    .prev_hash
                    .inner_as_ref()
                    .to_vec(),
                min_ntime: inner_set_custom_mining_job.min_ntime,
                nbits: inner_set_custom_mining_job.nbits,
                coinbase_tx_version: inner_set_custom_mining_job.coinbase_tx_version,
                coinbase_prefix: inner_set_custom_mining_job
                    .coinbase_prefix
                    .inner_as_ref()
                    .to_vec(),
                coinbase_tx_input_nsequence: inner_set_custom_mining_job
                    .coinbase_tx_input_n_sequence,
                coinbase_tx_outputs: inner_set_custom_mining_job
                    .coinbase_tx_outputs
                    .inner_as_ref()
                    .to_vec(),
                coinbase_tx_locktime: inner_set_custom_mining_job.coinbase_tx_locktime,
                merkle_path,
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::SetCustomMiningJobSuccess(
            inner_set_custom_mining_job_success,
        )) => Sv2Message::SetCustomMiningJobSuccess(SetCustomMiningJobSuccess {
            channel_id: inner_set_custom_mining_job_success.channel_id.into(),
            request_id: inner_set_custom_mining_job_success.request_id,
            job_id: inner_set_custom_mining_job_success.job_id,
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::SetCustomMiningJobError(
            inner_set_custom_mining_job_error,
        )) => Sv2Message::SetCustomMiningJobError(SetCustomMiningJobError {
            channel_id: inner_set_custom_mining_job_error.channel_id.into(),
            request_id: inner_set_custom_mining_job_error.request_id,
            error_code: String::from_utf8_lossy(
                inner_set_custom_mining_job_error.error_code.inner_as_ref(),
            )
            .to_string(),
        }),
        InnerAnyMessage::Mining(InnerMiningMessages::SetTarget(inner_set_target)) => {
            Sv2Message::SetTarget(SetTarget {
                channel_id: inner_set_target.channel_id.into(),
                maximum_target: inner_set_target.maximum_target.inner_as_ref().to_vec(),
            })
        }
        InnerAnyMessage::Mining(InnerMiningMessages::SetGroupChannel(inner_set_group_channel)) => {
            let channel_ids = inner_set_group_channel
                .channel_ids
                .clone()
                .into_inner()
                .iter()
                .map(|id| *id)
                .collect();
            Sv2Message::SetGroupChannel(SetGroupChannel {
                group_channel_id: inner_set_group_channel.group_channel_id.into(),
                channel_ids,
            })
        }
        _ => todo!(),
    }
}
