use channels_sv2::chain_tip::ChainTip;
use std::convert::TryInto;

#[derive(uniffi::Record, Clone, Debug)]
pub struct Sv2ChainTip {
    pub prev_hash: Vec<u8>,
    pub nbits: u32,
    pub min_ntime: u32,
}

impl From<&ChainTip> for Sv2ChainTip {
    fn from(tip: &ChainTip) -> Self {
        Self {
            prev_hash: tip.prev_hash().to_vec(),
            nbits: tip.nbits(),
            min_ntime: tip.min_ntime(),
        }
    }
}

impl From<Sv2ChainTip> for ChainTip {
    fn from(tip: Sv2ChainTip) -> Self {
        let prev_hash: [u8; 32] = tip
            .prev_hash
            .try_into()
            .expect("prev_hash must be 32 bytes");
        ChainTip::new(prev_hash.into(), tip.nbits, tip.min_ntime)
    }
}
