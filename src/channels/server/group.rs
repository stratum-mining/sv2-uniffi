use crate::channels::server::chain_tip::Sv2ChainTip;
use bitcoin::transaction::TxOut;
use channels_sv2::server::{
    group::GroupChannel,
    jobs::{extended::ExtendedJob, job_store::DefaultJobStore},
};
use parsers_sv2::{AnyMessage, Mining};
use std::sync::Mutex;

use crate::channels::server::error::Sv2ServerGroupChannelError;
use crate::channels::txout::TxOutput;
use crate::messages::{
    inner_to_sv2_message,
    mining::NewExtendedMiningJob,
    sv2_message_to_inner,
    template_distribution::{NewTemplate, SetNewPrevHashTemplateDistribution},
    Sv2Message,
};

#[derive(uniffi::Object)]
pub struct Sv2GroupChannelServer {
    pub inner: Mutex<GroupChannel<'static, DefaultJobStore<ExtendedJob<'static>>>>,
}

#[uniffi::export]
impl Sv2GroupChannelServer {
    #[uniffi::constructor]
    pub fn new(
        group_channel_id: u32,
        full_extranonce_size: u64,
        pool_tag_string: String,
    ) -> Result<Self, Sv2ServerGroupChannelError> {
        let job_store = DefaultJobStore::new();
        let inner = GroupChannel::new_for_pool(
            group_channel_id,
            job_store,
            full_extranonce_size as usize,
            pool_tag_string,
        )
        .map_err(|_| Sv2ServerGroupChannelError::FailedToCreateGroupChannel)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    pub fn add_channel_id(
        &self,
        channel_id: u32,
        full_extranonce_size: u64,
    ) -> Result<(), Sv2ServerGroupChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        channel
            .add_channel_id(channel_id, full_extranonce_size as usize)
            .map_err(|_| Sv2ServerGroupChannelError::FailedToCreateGroupChannel)?;
        Ok(())
    }

    pub fn remove_channel_id(&self, channel_id: u32) -> Result<(), Sv2ServerGroupChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        channel.remove_channel_id(channel_id);
        Ok(())
    }

    pub fn on_new_template(
        &self,
        template: NewTemplate,
        coinbase_reward_outputs: Vec<TxOutput>,
    ) -> Result<(), Sv2ServerGroupChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        let coinbase_reward_outputs: Vec<TxOut> = coinbase_reward_outputs
            .into_iter()
            .map(|output| output.to_txout())
            .collect();

        let any_message = sv2_message_to_inner(Sv2Message::NewTemplate(template))
            .map_err(Sv2ServerGroupChannelError::FailedToConvertMessage)?;

        let inner_template = match any_message {
            parsers_sv2::AnyMessage::TemplateDistribution(
                parsers_sv2::TemplateDistribution::NewTemplate(template),
            ) => template,
            _ => return Err(Sv2ServerGroupChannelError::MessageIsNotNewTemplate),
        };

        channel
            .on_new_template(inner_template, coinbase_reward_outputs)
            .map_err(|_| Sv2ServerGroupChannelError::FailedToProcessNewTemplate)?;
        Ok(())
    }

    pub fn on_set_new_prev_hash(
        &self,
        set_new_prev_hash: SetNewPrevHashTemplateDistribution,
    ) -> Result<(), Sv2ServerGroupChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        let any_message = sv2_message_to_inner(Sv2Message::SetNewPrevHashTemplateDistribution(
            set_new_prev_hash,
        ))
        .map_err(Sv2ServerGroupChannelError::FailedToConvertMessage)?;

        let inner_set_new_prev_hash = match any_message {
            parsers_sv2::AnyMessage::TemplateDistribution(
                parsers_sv2::TemplateDistribution::SetNewPrevHash(set_new_prev_hash),
            ) => set_new_prev_hash,
            _ => return Err(Sv2ServerGroupChannelError::MessageIsNotSetNewPrevHash),
        };

        channel
            .on_set_new_prev_hash(inner_set_new_prev_hash)
            .map_err(|_| Sv2ServerGroupChannelError::FailedToProcessNewPrevHash)?;
        Ok(())
    }

    pub fn get_group_channel_id(&self) -> Result<u32, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        Ok(channel.get_group_channel_id())
    }

    pub fn get_channel_ids(&self) -> Result<Vec<u32>, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        Ok(channel.get_channel_ids().iter().copied().collect())
    }

    pub fn get_active_job(&self) -> Result<NewExtendedMiningJob, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        let inner_job = channel
            .get_active_job()
            .ok_or(Sv2ServerGroupChannelError::FailedToGetActiveJob)?;
        let inner_job_message = inner_job.get_job_message();
        let job_message = inner_to_sv2_message(&AnyMessage::Mining(Mining::NewExtendedMiningJob(
            inner_job_message.clone(),
        )));
        let job_message = match job_message {
            Sv2Message::NewExtendedMiningJob(job) => job,
            _ => return Err(Sv2ServerGroupChannelError::MessageIsNotNewExtendedMiningJob),
        };
        Ok(job_message)
    }

    pub fn get_future_job(
        &self,
        job_id: u32,
    ) -> Result<Option<NewExtendedMiningJob>, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        let inner_job = channel.get_future_job(job_id);
        let job = inner_job
            .map(|job| {
                let job_message = job.get_job_message();
                let job_message = inner_to_sv2_message(&AnyMessage::Mining(
                    Mining::NewExtendedMiningJob(job_message.clone()),
                ));
                let job_message = match job_message {
                    Sv2Message::NewExtendedMiningJob(job) => job,
                    _ => return Err(Sv2ServerGroupChannelError::MessageIsNotNewExtendedMiningJob),
                };
                Ok(job_message)
            })
            .transpose()?;
        Ok(job)
    }

    pub fn get_future_job_id_from_template_id(
        &self,
        template_id: u64,
    ) -> Result<Option<u32>, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        let job_id = channel.get_future_job_id_from_template_id(template_id);
        Ok(job_id)
    }

    pub fn get_full_extranonce_size(&self) -> Result<u64, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        Ok(channel.get_full_extranonce_size() as u64)
    }

    pub fn set_full_extranonce_size(
        &self,
        full_extranonce_size: u64,
    ) -> Result<(), Sv2ServerGroupChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        channel.set_full_extranonce_size(full_extranonce_size as usize);
        Ok(())
    }

    pub fn get_chain_tip(&self) -> Result<Option<Sv2ChainTip>, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        Ok(channel.get_chain_tip().map(Sv2ChainTip::from))
    }
}
