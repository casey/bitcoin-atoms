use {
  super::*,
  crate::wallet::Wallet,
  bitcoin::{
    blockdata::{locktime::absolute::LockTime, witness::Witness},
    psbt::Psbt,
    sighash::TapSighashType,
  },
};

#[derive(Debug, Parser, Clone)]
pub(crate) struct Sell {
  pub amount: Amount,
  pub outgoing: Outgoing,
}

#[derive(Serialize, Deserialize)]
pub struct Output {
  pub cardinal: u64,
}

impl Sell {
  pub(crate) fn run(self, options: Options) -> SubcommandResult {
    let index = Index::open(&options)?;
    index.update()?;

    let client = options.bitcoin_rpc_client_for_wallet_command(false)?;
    let unspent_outputs = index.get_unspent_outputs(Wallet::load(&options)?)?;
    let inscriptions = index.get_inscriptions(&unspent_outputs)?;
    let chain = options.chain();

    let satpoint = match self.outgoing {
      Outgoing::SatPoint(satpoint) => {
        // TODO : check if you actually own this satpoint
        satpoint
      }
      Outgoing::InscriptionId(id) => index
        .get_inscription_satpoint_by_id(id)?
        .ok_or_else(|| anyhow!("Inscription {id} not found"))?,
      Outgoing::Amount(_) => bail!("Only able to list satpoints and inscriptions for sale"),
    };

    let receive_address = get_change_address(&client, chain)?;

    let unsigned_tx = Transaction {
      version: 2,
      lock_time: LockTime::ZERO,
      input: vec![TxIn {
        previous_output: satpoint.outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
      }],
      output: vec![TxOut {
        script_pubkey: receive_address.script_pubkey(),
        value: self.amount.to_sat(),
      }],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    let non_witness_utxo = client.get_raw_transaction(&satpoint.outpoint.txid, None)?;
    let witness_utxo = non_witness_utxo.output[satpoint.outpoint.vout as usize].clone();

    psbt.inputs[0].sighash_type = Some(TapSighashType::SinglePlusAnyoneCanPay.into());
    psbt.inputs[0].non_witness_utxo = Some(non_witness_utxo.clone());
    psbt.inputs[0].witness_utxo = Some(witness_utxo);

    // TODO : should we use walletprocesspsbt rpc for signing?
    let signed_tx = client
      .sign_raw_transaction_with_wallet(&psbt.clone().extract_tx(), None, None)?
      .transaction()?;

    psbt.inputs[0].final_script_witness = Some(signed_tx.input[0].witness.clone());

    // TODO : optionally publish the psbt somewhere everyone can access. Giving the option of
    // keeping psbt private vs publishing it is desired. If you publish it publicly, in order to
    // delist the item, you will need to transfer the inscription/satpoint to yourself

    Ok(Box::new(psbt.serialize_hex()))
  }
}
