use bitcoin::{transaction::TxOut, Amount, ScriptBuf};

#[derive(uniffi::Record)]
pub struct TxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl TxOutput {
    pub fn to_txout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.value),
            script_pubkey: ScriptBuf::from_bytes(self.script_pubkey.clone()),
        }
    }

    pub fn from_txout(txout: TxOut) -> Self {
        Self {
            value: txout.value.to_sat(),
            script_pubkey: txout.script_pubkey.to_bytes().to_vec(),
        }
    }
}
