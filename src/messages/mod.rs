pub mod common;
pub mod mining;
pub mod job_declaration;
pub mod template_distribution;
pub mod error;

use crate::messages::{common::*, error::Sv2MessageError};
use common_messages_sv2::{
    ChannelEndpointChanged as InnerChannelEndpointChanged, Protocol as InnerProtocol,
    Reconnect as InnerReconnect, SetupConnection as InnerSetupConnection,
    SetupConnectionError as InnerSetupConnectionError,
    SetupConnectionSuccess as InnerSetupConnectionSuccess,
};
use parsers_sv2::{AnyMessage as InnerAnyMessage, CommonMessages as InnerCommonMessages};

use std::convert::{TryFrom, TryInto};

/// Provides UniFFI interfaces for every possible Sv2 message type.
///
/// This is used for encoding and decoding messages over the encrypted connection.
#[derive(uniffi::Enum)]
pub enum Sv2Message {
    SetupConnection(SetupConnection),
    SetupConnectionSuccess(SetupConnectionSuccess),
    SetupConnectionError(SetupConnectionError),
    ChannelEndpointChanged(ChannelEndpointChanged),
    Reconnect(Reconnect),
    // todo
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
        _ => todo!(),
    }
}
