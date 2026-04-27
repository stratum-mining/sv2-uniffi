use crate::channels::server::chain_tip::Sv2ChainTip;
use binary_sv2::U256;
use bitcoin::transaction::TxOut;
use bitcoin::Target;
use channels_sv2::server::share_accounting::{
    ShareValidationError as InnerShareValidationError,
    ShareValidationResult as InnerShareValidationResult,
};
use channels_sv2::server::{
    error::ExtendedChannelError,
    extended::ExtendedChannel,
    jobs::{extended::ExtendedJob, job_store::DefaultJobStore},
};
use std::{
    convert::TryInto,
    sync::{Arc, Mutex},
};

use crate::channels::extranonce::prefix::Sv2ExtranoncePrefix;
use crate::channels::server::error::Sv2ServerExtendedChannelError;
use crate::channels::server::jobs::extended::Sv2ExtendedJob;
use crate::channels::server::share_accounting::{
    ShareAccounting, ShareValidationError, ShareValidationResult,
};
use crate::channels::txout::TxOutput;
use crate::messages::{
    mining::{SetCustomMiningJob, SubmitSharesExtended},
    sv2_message_to_inner,
    template_distribution::{NewTemplate, SetNewPrevHashTemplateDistribution},
    Sv2Message,
};

#[derive(uniffi::Object)]
pub struct Sv2ExtendedChannelServer {
    pub inner: Mutex<ExtendedChannel<'static, DefaultJobStore<ExtendedJob<'static>>>>,
}

#[uniffi::export]
impl Sv2ExtendedChannelServer {
    #[uniffi::constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel_id: u32,
        user_identity: String,
        extranonce_prefix: Arc<Sv2ExtranoncePrefix>,
        max_target: Vec<u8>,
        nominal_hashrate: f32,
        version_rolling_allowed: bool,
        rollable_extranonce_size: u16,
        share_batch_size: u32,
        expected_share_per_minute: f32,
        pool_tag_string: String,
    ) -> Result<Self, Sv2ServerExtendedChannelError> {
        let max_target: [u8; 32] = max_target
            .try_into()
            .map_err(|_| Sv2ServerExtendedChannelError::BadMaxTarget)?;
        let max_target = Target::from_le_bytes(max_target);
        let job_store = DefaultJobStore::new();
        let extranonce_prefix = extranonce_prefix
            .take_inner()
            .map_err(|_| Sv2ServerExtendedChannelError::FailedToConsumeExtranoncePrefix)?;

        let channel = ExtendedChannel::new_for_pool(
            channel_id,
            user_identity,
            extranonce_prefix,
            max_target,
            nominal_hashrate,
            version_rolling_allowed,
            rollable_extranonce_size,
            share_batch_size as usize,
            expected_share_per_minute,
            job_store,
            pool_tag_string,
        )
        .map_err(|e| match e {
            ExtendedChannelError::InvalidNominalHashrate => {
                Sv2ServerExtendedChannelError::InvalidNominalHashrate
            }
            ExtendedChannelError::RequestedMinExtranonceSizeTooLarge => {
                Sv2ServerExtendedChannelError::RequestedMinExtranonceSizeTooLarge
            }
            _ => Sv2ServerExtendedChannelError::FailedToCreateExtendedChannel,
        })?;

        Ok(Self {
            inner: Mutex::new(channel),
        })
    }

    pub fn update_channel(
        &self,
        nominal_hashrate: f32,
        requested_max_target: Option<Vec<u8>>,
    ) -> Result<(), Sv2ServerExtendedChannelError> {
        let requested_max_target: Option<Target> = match requested_max_target {
            Some(target) => {
                let target_array: [u8; 32] = target
                    .try_into()
                    .map_err(|_| Sv2ServerExtendedChannelError::BadMaxTarget)?;
                Some(Target::from_le_bytes(target_array))
            }
            None => None,
        };
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        channel
            .update_channel(nominal_hashrate, requested_max_target)
            .map_err(|_| Sv2ServerExtendedChannelError::FailedToUpdateChannel)?;
        Ok(())
    }

    pub fn on_new_template(
        &self,
        new_template: NewTemplate,
        coinbase_reward_outputs: Vec<TxOutput>,
    ) -> Result<(), Sv2ServerExtendedChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let coinbase_reward_outputs: Vec<TxOut> = coinbase_reward_outputs
            .into_iter()
            .map(|output| output.to_txout())
            .collect();

        let any_message = sv2_message_to_inner(Sv2Message::NewTemplate(new_template))
            .map_err(Sv2ServerExtendedChannelError::FailedToConvertMessage)?;

        let inner_template = match any_message {
            parsers_sv2::AnyMessage::TemplateDistribution(
                parsers_sv2::TemplateDistribution::NewTemplate(template),
            ) => template,
            _ => return Err(Sv2ServerExtendedChannelError::MessageIsNotNewTemplate),
        };

        channel
            .on_new_template(inner_template, coinbase_reward_outputs)
            .map_err(|_| Sv2ServerExtendedChannelError::FailedToProcessNewTemplate)?;
        Ok(())
    }

    pub fn on_set_new_prev_hash(
        &self,
        set_new_prev_hash: SetNewPrevHashTemplateDistribution,
    ) -> Result<(), Sv2ServerExtendedChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let any_message = sv2_message_to_inner(Sv2Message::SetNewPrevHashTemplateDistribution(
            set_new_prev_hash,
        ))
        .map_err(Sv2ServerExtendedChannelError::FailedToConvertMessage)?;

        let inner_set_new_prev_hash = match any_message {
            parsers_sv2::AnyMessage::TemplateDistribution(
                parsers_sv2::TemplateDistribution::SetNewPrevHash(set_new_prev_hash),
            ) => set_new_prev_hash,
            _ => return Err(Sv2ServerExtendedChannelError::MessageIsNotSetNewPrevHash),
        };

        channel
            .on_set_new_prev_hash(inner_set_new_prev_hash)
            .map_err(|_| Sv2ServerExtendedChannelError::FailedToProcessNewPrevHash)?;
        Ok(())
    }

    pub fn on_set_custom_mining_job(
        &self,
        set_custom_mining_job: SetCustomMiningJob,
    ) -> Result<(), Sv2ServerExtendedChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;

        let any_message =
            sv2_message_to_inner(Sv2Message::SetCustomMiningJob(set_custom_mining_job))
                .map_err(Sv2ServerExtendedChannelError::FailedToConvertMessage)?;

        let inner_set_custom_mining_job = match any_message {
            parsers_sv2::AnyMessage::Mining(parsers_sv2::Mining::SetCustomMiningJob(
                set_custom_mining_job,
            )) => set_custom_mining_job,
            _ => return Err(Sv2ServerExtendedChannelError::MessageIsNotSetCustomMiningJob),
        };

        channel
            .on_set_custom_mining_job(inner_set_custom_mining_job)
            .map_err(|_| Sv2ServerExtendedChannelError::FailedToProcessSetCustomMiningJob)?;
        Ok(())
    }

    pub fn validate_share(
        &self,
        share: SubmitSharesExtended,
    ) -> Result<ShareValidationResult, Sv2ServerExtendedChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;

        let any_message = sv2_message_to_inner(Sv2Message::SubmitSharesExtended(share))
            .map_err(Sv2ServerExtendedChannelError::FailedToConvertMessage)?;

        let inner_share = match any_message {
            parsers_sv2::AnyMessage::Mining(parsers_sv2::Mining::SubmitSharesExtended(share)) => {
                share
            }
            _ => return Err(Sv2ServerExtendedChannelError::MessageIsNotSubmitSharesExtended),
        };

        let result = channel.validate_share(inner_share);

        match result {
            Ok(InnerShareValidationResult::Valid(hash)) => {
                Ok(ShareValidationResult::Valid(hash[..].to_vec()))
            }
            Ok(InnerShareValidationResult::BlockFound(share_hash, template_id, coinbase)) => Ok(
                ShareValidationResult::BlockFound(share_hash[..].to_vec(), template_id, coinbase),
            ),
            Err(InnerShareValidationError::Invalid) => Err(
                Sv2ServerExtendedChannelError::ShareValidationError(ShareValidationError::Invalid),
            ),
            Err(InnerShareValidationError::Stale) => Err(
                Sv2ServerExtendedChannelError::ShareValidationError(ShareValidationError::Stale),
            ),
            Err(InnerShareValidationError::InvalidJobId) => {
                Err(Sv2ServerExtendedChannelError::ShareValidationError(
                    ShareValidationError::InvalidJobId,
                ))
            }
            Err(InnerShareValidationError::DoesNotMeetTarget) => {
                Err(Sv2ServerExtendedChannelError::ShareValidationError(
                    ShareValidationError::DoesNotMeetTarget,
                ))
            }
            Err(InnerShareValidationError::VersionRollingNotAllowed) => {
                Err(Sv2ServerExtendedChannelError::ShareValidationError(
                    ShareValidationError::VersionRollingNotAllowed,
                ))
            }
            Err(InnerShareValidationError::DuplicateShare) => {
                Err(Sv2ServerExtendedChannelError::ShareValidationError(
                    ShareValidationError::DuplicateShare,
                ))
            }
            Err(InnerShareValidationError::InvalidCoinbase) => {
                Err(Sv2ServerExtendedChannelError::ShareValidationError(
                    ShareValidationError::InvalidCoinbase,
                ))
            }
            Err(InnerShareValidationError::NoChainTip) => {
                Err(Sv2ServerExtendedChannelError::ShareValidationError(
                    ShareValidationError::NoChainTip,
                ))
            }
            Err(InnerShareValidationError::BadExtranonceSize) => {
                Err(Sv2ServerExtendedChannelError::ShareValidationError(
                    ShareValidationError::BadExtranonceSize,
                ))
            }
        }
    }

    pub fn get_extranonce_prefix(&self) -> Result<Vec<u8>, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_extranonce_prefix().to_vec())
    }

    pub fn get_rollable_extranonce_size(&self) -> Result<u16, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_rollable_extranonce_size())
    }

    pub fn get_channel_id(&self) -> Result<u32, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_channel_id())
    }

    pub fn get_past_job(
        &self,
        job_id: u32,
    ) -> Result<Option<Arc<Sv2ExtendedJob>>, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let inner_jobs = channel.get_past_job(job_id);
        let job = inner_jobs.map(|job| Arc::new(Sv2ExtendedJob::from_inner(job.clone())));
        Ok(job)
    }

    pub fn get_active_job(&self) -> Result<Sv2ExtendedJob, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let inner_job = channel
            .get_active_job()
            .ok_or(Sv2ServerExtendedChannelError::FailedToGetActiveJob)?;
        Ok(Sv2ExtendedJob::from_inner(inner_job.clone()))
    }

    pub fn get_future_job(
        &self,
        job_id: u32,
    ) -> Result<Option<Arc<Sv2ExtendedJob>>, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let inner_jobs = channel.get_future_job(job_id);
        let job = inner_jobs.map(|job| Arc::new(Sv2ExtendedJob::from_inner(job.clone())));
        Ok(job)
    }

    pub fn get_future_job_id_from_template_id(
        &self,
        template_id: u64,
    ) -> Result<Option<u32>, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_future_job_id_from_template_id(template_id))
    }

    pub fn get_target(&self) -> Result<Vec<u8>, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let target_u256: U256 = (*channel.get_target()).to_le_bytes().into();
        Ok(target_u256.to_vec())
    }

    pub fn get_user_identity(&self) -> Result<String, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_user_identity().clone())
    }

    pub fn get_nominal_hashrate(&self) -> Result<f32, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_nominal_hashrate())
    }

    pub fn get_shares_per_minute(&self) -> Result<f32, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_shares_per_minute())
    }

    pub fn get_share_accounting(&self) -> Result<ShareAccounting, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(ShareAccounting::from_inner(
            channel.get_share_accounting().clone(),
        ))
    }

    pub fn get_requested_max_target(&self) -> Result<Vec<u8>, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let target_u256: U256 = (*channel.get_requested_max_target()).to_le_bytes().into();
        Ok(target_u256.to_vec())
    }

    pub fn get_full_extranonce_size(&self) -> Result<u64, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_full_extranonce_size() as u64)
    }

    pub fn set_target(&self, target: Vec<u8>) -> Result<(), Sv2ServerExtendedChannelError> {
        let target: [u8; 32] = target
            .try_into()
            .map_err(|_| Sv2ServerExtendedChannelError::BadMaxTarget)?;
        let target = Target::from_le_bytes(target);
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        channel.set_target(target);
        Ok(())
    }

    pub fn set_nominal_hashrate(
        &self,
        nominal_hashrate: f32,
    ) -> Result<(), Sv2ServerExtendedChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        channel.set_nominal_hashrate(nominal_hashrate);
        Ok(())
    }

    pub fn set_extranonce_prefix(
        &self,
        extranonce_prefix: Arc<Sv2ExtranoncePrefix>,
    ) -> Result<(), Sv2ServerExtendedChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let extranonce_prefix = extranonce_prefix
            .take_inner()
            .map_err(|_| Sv2ServerExtendedChannelError::FailedToConsumeExtranoncePrefix)?;
        channel
            .set_extranonce_prefix(extranonce_prefix)
            .map_err(|_| Sv2ServerExtendedChannelError::ExtranoncePrefixTooLarge)
    }

    pub fn get_chain_tip(&self) -> Result<Option<Sv2ChainTip>, Sv2ServerExtendedChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        Ok(channel.get_chain_tip().map(Sv2ChainTip::from))
    }

    pub fn on_group_channel_job(
        &self,
        extended_job: Arc<Sv2ExtendedJob>,
    ) -> Result<(), Sv2ServerExtendedChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        let extended_job_inner = extended_job
            .inner
            .lock()
            .map_err(|_| Sv2ServerExtendedChannelError::LockError)?;
        channel
            .on_group_channel_job(extended_job_inner.clone())
            .map_err(|_| Sv2ServerExtendedChannelError::FailedToProcessGroupChannelJob)
    }
}
