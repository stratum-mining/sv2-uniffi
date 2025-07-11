use crate::channels::server::jobs::error::Sv2StandardJobError;
use crate::channels::txout::TxOutput;
use crate::messages::{
    inner_to_sv2_message, mining::NewMiningJob, template_distribution::NewTemplate, Sv2Message,
};
use parsers_sv2::{AnyMessage, Mining, TemplateDistribution};
use std::sync::Mutex;

use channels_sv2::server::jobs::standard::StandardJob;

#[derive(uniffi::Object)]
pub struct Sv2StandardJob {
    pub inner: Mutex<StandardJob<'static>>,
}

impl Sv2StandardJob {
    pub fn from_inner(inner: StandardJob<'static>) -> Self {
        Self {
            inner: Mutex::new(inner),
        }
    }
}

#[uniffi::export]
impl Sv2StandardJob {
    pub fn get_job_id(&self) -> Result<u32, Sv2StandardJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2StandardJobError::LockError)?;
        Ok(inner.get_job_id())
    }

    pub fn get_job_message(&self) -> Result<NewMiningJob, Sv2StandardJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2StandardJobError::LockError)?;

        let job_message = inner.get_job_message();
        let job_message = inner_to_sv2_message(&AnyMessage::Mining(Mining::NewMiningJob(
            job_message.clone(),
        )));
        let job_message = match job_message {
            Sv2Message::NewMiningJob(job) => job,
            _ => return Err(Sv2StandardJobError::MessageIsNotNewMiningJob),
        };
        Ok(job_message)
    }

    pub fn get_template(&self) -> Result<NewTemplate, Sv2StandardJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2StandardJobError::LockError)?;
        let template = inner.get_template();
        let template = inner_to_sv2_message(&AnyMessage::TemplateDistribution(
            TemplateDistribution::NewTemplate(template.clone()),
        ));
        let template = match template {
            Sv2Message::NewTemplate(template) => template,
            _ => return Err(Sv2StandardJobError::MessageIsNotNewTemplate),
        };
        Ok(template)
    }

    pub fn get_extranonce_prefix(&self) -> Result<Vec<u8>, Sv2StandardJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2StandardJobError::LockError)?;
        Ok(inner.get_extranonce_prefix().clone())
    }

    pub fn get_coinbase_outputs(&self) -> Result<Vec<TxOutput>, Sv2StandardJobError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2StandardJobError::LockError)?;
        let inner_outputs = inner.get_coinbase_outputs();
        let outputs = inner_outputs
            .iter()
            .map(|output| TxOutput::from_txout(output.clone()))
            .collect();
        Ok(outputs)
    }
}
