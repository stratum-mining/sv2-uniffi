use bitcoin::transaction::TxOut;
use channels_sv2::server::share_accounting::{
    ShareValidationError as InnerShareValidationError,
    ShareValidationResult as InnerShareValidationResult,
};
use channels_sv2::server::{jobs::job_store::DefaultJobStore, standard::StandardChannel};
use codec_sv2::binary_sv2::U256;
use mining_sv2::Target;
use std::collections::HashMap;
use std::{convert::TryInto, sync::Mutex};

use crate::channels::server::error::Sv2ServerStandardChannelError;
use crate::channels::server::jobs::extended::Sv2ExtendedJob;
use crate::channels::server::jobs::standard::Sv2StandardJob;
use crate::channels::server::share_validation::{ShareValidationError, ShareValidationResult};
use crate::channels::txout::TxOutput;
use crate::messages::{
    mining::SubmitSharesStandard,
    sv2_message_to_inner,
    template_distribution::{NewTemplate, SetNewPrevHashTemplateDistribution},
    Sv2Message,
};

use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct Sv2StandardChannelServer {
    pub inner: Mutex<StandardChannel<'static>>,
}

#[uniffi::export]
impl Sv2StandardChannelServer {
    #[uniffi::constructor]
    pub fn new(
        channel_id: u32,
        user_identity: String,
        extranonce_prefix: Vec<u8>,
        max_target: Vec<u8>,
        nominal_hashrate: f32,
        share_batch_size: u32,
        expected_share_per_minute: f32,
        pool_tag_string: String,
    ) -> Result<Self, Sv2ServerStandardChannelError> {
        let max_target: [u8; 32] = max_target
            .try_into()
            .map_err(|_| Sv2ServerStandardChannelError::BadMaxTarget)?;
        let max_target: Target = max_target.into();
        let job_store = Box::new(DefaultJobStore::new());

        let inner = StandardChannel::new_for_pool(
            channel_id,
            user_identity,
            extranonce_prefix,
            max_target,
            nominal_hashrate,
            share_batch_size as usize,
            expected_share_per_minute,
            job_store,
            pool_tag_string,
        )
        .map_err(|_| Sv2ServerStandardChannelError::FailedToCreateStandardChannel)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    pub fn update_channel(
        &self,
        nominal_hashrate: f32,
        requested_max_target: Option<Vec<u8>>,
    ) -> Result<(), Sv2ServerStandardChannelError> {
        let requested_max_target: Option<Target> = match requested_max_target {
            Some(target) => {
                let target_array: [u8; 32] = target
                    .try_into()
                    .map_err(|_| Sv2ServerStandardChannelError::BadMaxTarget)?;
                Some(target_array.into())
            }
            None => None,
        };
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        channel
            .update_channel(nominal_hashrate, requested_max_target)
            .map_err(|_| Sv2ServerStandardChannelError::FailedToUpdateChannel)?;
        Ok(())
    }

    pub fn on_new_template(
        &self,
        template: NewTemplate,
        coinbase_reward_outputs: Vec<TxOutput>,
    ) -> Result<(), Sv2ServerStandardChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let coinbase_reward_outputs: Vec<TxOut> = coinbase_reward_outputs
            .into_iter()
            .map(|output| output.to_txout())
            .collect();

        let any_message = sv2_message_to_inner(Sv2Message::NewTemplate(template))
            .map_err(|e| Sv2ServerStandardChannelError::FailedToConvertMessage(e))?;

        let inner_template = match any_message {
            parsers_sv2::AnyMessage::TemplateDistribution(
                parsers_sv2::TemplateDistribution::NewTemplate(template),
            ) => template,
            _ => return Err(Sv2ServerStandardChannelError::MessageIsNotNewTemplate),
        };

        channel
            .on_new_template(inner_template, coinbase_reward_outputs)
            .map_err(|_| Sv2ServerStandardChannelError::FailedToProcessNewTemplate)?;
        Ok(())
    }

    pub fn on_group_channel_job(
        &self,
        extended_job: Arc<Sv2ExtendedJob>,
    ) -> Result<(), Sv2ServerStandardChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let extended_job_inner = extended_job
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        channel
            .on_group_channel_job(extended_job_inner.clone())
            .map_err(|_| Sv2ServerStandardChannelError::FailedToProcessGroupChannelJob)?;
        Ok(())
    }

    pub fn on_set_new_prev_hash(
        &self,
        set_new_prev_hash: SetNewPrevHashTemplateDistribution,
    ) -> Result<(), Sv2ServerStandardChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let any_message = sv2_message_to_inner(Sv2Message::SetNewPrevHashTemplateDistribution(
            set_new_prev_hash,
        ))
        .map_err(|e| Sv2ServerStandardChannelError::FailedToConvertMessage(e))?;

        let inner_set_new_prev_hash = match any_message {
            parsers_sv2::AnyMessage::TemplateDistribution(
                parsers_sv2::TemplateDistribution::SetNewPrevHash(set_new_prev_hash),
            ) => set_new_prev_hash,
            _ => return Err(Sv2ServerStandardChannelError::MessageIsNotSetNewPrevHash),
        };

        channel
            .on_set_new_prev_hash(inner_set_new_prev_hash)
            .map_err(|_| Sv2ServerStandardChannelError::FailedToProcessNewPrevHash)?;
        Ok(())
    }

    pub fn validate_share(
        &self,
        share: SubmitSharesStandard,
    ) -> Result<ShareValidationResult, Sv2ServerStandardChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;

        let any_message = sv2_message_to_inner(Sv2Message::SubmitSharesStandard(share))
            .map_err(|e| Sv2ServerStandardChannelError::FailedToConvertMessage(e))?;

        let inner_share = match any_message {
            parsers_sv2::AnyMessage::Mining(parsers_sv2::Mining::SubmitSharesStandard(share)) => {
                share
            }
            _ => return Err(Sv2ServerStandardChannelError::MessageIsNotSubmitSharesStandard),
        };

        let result = channel.validate_share(inner_share);

        match result {
            Ok(InnerShareValidationResult::Valid) => Ok(ShareValidationResult::Valid),
            Ok(InnerShareValidationResult::ValidWithAcknowledgement(
                last_sequence_number,
                new_submits_accepted_count,
                new_shares_sum,
            )) => Ok(ShareValidationResult::ValidWithAcknowledgement(
                last_sequence_number,
                new_submits_accepted_count,
                new_shares_sum,
            )),
            Ok(InnerShareValidationResult::BlockFound(template_id, coinbase)) => {
                Ok(ShareValidationResult::BlockFound(template_id, coinbase))
            }
            Err(InnerShareValidationError::Invalid) => Err(
                Sv2ServerStandardChannelError::ShareValidationError(ShareValidationError::Invalid),
            ),
            Err(InnerShareValidationError::Stale) => Err(
                Sv2ServerStandardChannelError::ShareValidationError(ShareValidationError::Stale),
            ),
            Err(InnerShareValidationError::InvalidJobId) => {
                Err(Sv2ServerStandardChannelError::ShareValidationError(
                    ShareValidationError::InvalidJobId,
                ))
            }
            Err(InnerShareValidationError::DoesNotMeetTarget) => {
                Err(Sv2ServerStandardChannelError::ShareValidationError(
                    ShareValidationError::DoesNotMeetTarget,
                ))
            }
            Err(InnerShareValidationError::VersionRollingNotAllowed) => {
                Err(Sv2ServerStandardChannelError::ShareValidationError(
                    ShareValidationError::VersionRollingNotAllowed,
                ))
            }
            Err(InnerShareValidationError::DuplicateShare) => {
                Err(Sv2ServerStandardChannelError::ShareValidationError(
                    ShareValidationError::DuplicateShare,
                ))
            }
            Err(InnerShareValidationError::InvalidCoinbase) => {
                Err(Sv2ServerStandardChannelError::ShareValidationError(
                    ShareValidationError::InvalidCoinbase,
                ))
            }
            Err(InnerShareValidationError::NoChainTip) => {
                Err(Sv2ServerStandardChannelError::ShareValidationError(
                    ShareValidationError::NoChainTip,
                ))
            }
        }
    }

    pub fn get_channel_id(&self) -> Result<u32, Sv2ServerStandardChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        Ok(channel.get_channel_id())
    }

    pub fn get_past_jobs(
        &self,
    ) -> Result<HashMap<u32, Arc<Sv2StandardJob>>, Sv2ServerStandardChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let inner_jobs = channel.get_past_jobs();
        let jobs = inner_jobs
            .iter()
            .map(|(job_id, job)| Ok((*job_id, Arc::new(Sv2StandardJob::from_inner(job.clone())))))
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(jobs)
    }

    pub fn get_active_job(&self) -> Result<Arc<Sv2StandardJob>, Sv2ServerStandardChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let inner_job = channel
            .get_active_job()
            .ok_or(Sv2ServerStandardChannelError::FailedToGetActiveJob)?;
        Ok(Arc::new(Sv2StandardJob::from_inner(inner_job.clone())))
    }

    pub fn get_future_jobs(
        &self,
    ) -> Result<HashMap<u32, Arc<Sv2StandardJob>>, Sv2ServerStandardChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let inner_jobs = channel.get_future_jobs();
        let jobs = inner_jobs
            .iter()
            .map(|(job_id, job)| Ok((*job_id, Arc::new(Sv2StandardJob::from_inner(job.clone())))))
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(jobs)
    }

    pub fn get_future_template_to_job_id(
        &self,
    ) -> Result<HashMap<u64, u32>, Sv2ServerStandardChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let inner_template_to_job_id = channel.get_future_template_to_job_id();
        Ok(inner_template_to_job_id.clone())
    }

    pub fn get_target(&self) -> Result<Vec<u8>, Sv2ServerStandardChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        let target_u256: U256 = channel.get_target().clone().into();
        Ok(target_u256.to_vec())
    }

    pub fn get_extranonce_prefix(&self) -> Result<Vec<u8>, Sv2ServerStandardChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerStandardChannelError::LockError)?;
        Ok(channel.get_extranonce_prefix().to_vec())
    }
}
