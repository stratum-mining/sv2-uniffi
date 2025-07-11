use bitcoin::transaction::TxOut;
use channels_sv2::server::{group::GroupChannel, jobs::job_store::DefaultJobStore};
use parsers_sv2::{AnyMessage, Mining};
use std::collections::HashMap;
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
    pub inner: Mutex<GroupChannel<'static>>,
}

#[uniffi::export]
impl Sv2GroupChannelServer {
    #[uniffi::constructor]
    pub fn new(
        channel_id: u32,
        pool_tag_string: String,
    ) -> Result<Self, Sv2ServerGroupChannelError> {
        let job_store = Box::new(DefaultJobStore::new());
        let inner = GroupChannel::new_for_pool(channel_id, job_store, pool_tag_string);
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    pub fn add_standard_channel_id(
        &self,
        standard_channel_id: u32,
    ) -> Result<(), Sv2ServerGroupChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        channel.add_standard_channel_id(standard_channel_id);
        Ok(())
    }

    pub fn remove_standard_channel_id(
        &self,
        standard_channel_id: u32,
    ) -> Result<(), Sv2ServerGroupChannelError> {
        let mut channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        channel.remove_standard_channel_id(standard_channel_id);
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
            .map_err(|e| Sv2ServerGroupChannelError::FailedToConvertMessage(e))?;

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
        .map_err(|e| Sv2ServerGroupChannelError::FailedToConvertMessage(e))?;

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

    pub fn get_standard_channel_ids(&self) -> Result<Vec<u32>, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        Ok(channel
            .get_standard_channel_ids()
            .into_iter()
            .copied()
            .collect())
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

    pub fn get_future_jobs(
        &self,
    ) -> Result<HashMap<u32, NewExtendedMiningJob>, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        let inner_jobs = channel.get_future_jobs();
        let jobs = inner_jobs
            .iter()
            .map(|(job_id, job)| {
                let job_message = job.get_job_message();
                let job_message = inner_to_sv2_message(&AnyMessage::Mining(
                    Mining::NewExtendedMiningJob(job_message.clone()),
                ));
                let job_message = match job_message {
                    Sv2Message::NewExtendedMiningJob(job) => job,
                    _ => return Err(Sv2ServerGroupChannelError::MessageIsNotNewExtendedMiningJob),
                };
                Ok((*job_id, job_message))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        Ok(jobs)
    }

    pub fn get_future_template_to_job_id(
        &self,
    ) -> Result<HashMap<u64, u32>, Sv2ServerGroupChannelError> {
        let channel = self
            .inner
            .lock()
            .map_err(|_| Sv2ServerGroupChannelError::LockError)?;
        let inner_template_to_job_id = channel.get_future_template_to_job_id();
        Ok(inner_template_to_job_id.clone())
    }
}
