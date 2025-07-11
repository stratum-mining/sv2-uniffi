use crate::channels::server::jobs::error::Sv2ExtendedJobError;
use crate::channels::txout::TxOutput;
use crate::messages::{
    inner_to_sv2_message,
    mining::{NewExtendedMiningJob, SetCustomMiningJob},
    template_distribution::NewTemplate,
    Sv2Message,
};
use channels_sv2::server::jobs::{extended::ExtendedJob, JobOrigin};
use parsers_sv2::{AnyMessage, Mining, TemplateDistribution};
use std::sync::Mutex;

#[derive(uniffi::Object)]
pub struct Sv2ExtendedJob {
    pub inner: Mutex<ExtendedJob<'static>>,
}

impl Sv2ExtendedJob {
    pub fn from_inner(inner: ExtendedJob<'static>) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

#[uniffi::export]
impl Sv2ExtendedJob {
    pub fn get_job_id(&self) -> Result<u32, Sv2ExtendedJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtendedJobError::LockError)?;
        Ok(inner.get_job_id())
    }

    pub fn get_job_message(&self) -> Result<NewExtendedMiningJob, Sv2ExtendedJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtendedJobError::LockError)?;

        let job_message = inner.get_job_message();
        let job_message = inner_to_sv2_message(&AnyMessage::Mining(Mining::NewExtendedMiningJob(
            job_message.clone(),
        )));
        let job_message = match job_message {
            Sv2Message::NewExtendedMiningJob(job) => job,
            _ => return Err(Sv2ExtendedJobError::MessageIsNotNewExtendedMiningJob),
        };
        Ok(job_message)
    }

    pub fn get_job_origin(&self) -> Result<Sv2ExtendedJobOrigin, Sv2ExtendedJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtendedJobError::LockError)?;
        let job_origin = inner.get_origin();
        let job_origin = match job_origin {
            JobOrigin::NewTemplate(template) => {
                let new_template_message = inner_to_sv2_message(&AnyMessage::TemplateDistribution(
                    TemplateDistribution::NewTemplate(template.clone()),
                ));
                let new_template_message = match new_template_message {
                    Sv2Message::NewTemplate(template) => template,
                    _ => return Err(Sv2ExtendedJobError::MessageIsNotNewTemplate),
                };
                Sv2ExtendedJobOrigin::NewTemplate(new_template_message)
            }
            JobOrigin::SetCustomMiningJob(job) => {
                let set_custom_mining_job_message = inner_to_sv2_message(&AnyMessage::Mining(
                    Mining::SetCustomMiningJob(job.clone()),
                ));
                let set_custom_mining_job_message = match set_custom_mining_job_message {
                    Sv2Message::SetCustomMiningJob(job) => job,
                    _ => return Err(Sv2ExtendedJobError::MessageIsNotSetCustomMiningJob),
                };
                Sv2ExtendedJobOrigin::SetCustomMiningJob(set_custom_mining_job_message)
            }
        };
        Ok(job_origin)
    }

    pub fn get_extranonce_prefix(&self) -> Result<Vec<u8>, Sv2ExtendedJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtendedJobError::LockError)?;
        Ok(inner.get_extranonce_prefix().clone())
    }

    pub fn get_coinbase_outputs(&self) -> Result<Vec<TxOutput>, Sv2ExtendedJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtendedJobError::LockError)?;
        let inner_outputs = inner.get_coinbase_outputs();
        let outputs = inner_outputs
            .iter()
            .map(|output| TxOutput::from_txout(output.clone()))
            .collect();
        Ok(outputs)
    }
}

#[derive(uniffi::Enum)]
pub enum Sv2ExtendedJobOrigin {
    NewTemplate(NewTemplate),
    SetCustomMiningJob(SetCustomMiningJob),
}
