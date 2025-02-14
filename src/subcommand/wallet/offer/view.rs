use super::*;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Output {
  pub psbt: String,
  pub role: Role,
  pub seller_address: Address<NetworkUnchecked>,
  pub buyer_address: Address<NetworkUnchecked>,
  pub inscription: InscriptionId,
  pub balance_change: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Role {
  Buyer,
  Seller,
}

#[derive(Debug, Parser)]
pub(crate) struct View {
  #[arg(long, help = "<PSBT> that encodes the offer.")]
  psbt: String,
}

impl View {
  pub(crate) fn run(&self, wallet: Wallet) -> SubcommandResult {
    let psbt = base64_decode(&self.psbt).context("failed to base64 decode PSBT")?;

    let psbt = Psbt::deserialize(&psbt).context("failed to deserialize PSBT")?;

    let mut inputs = Vec::new();

    for (index, input) in psbt.unsigned_tx.input.iter().enumerate() {
      let mut mine = false;

      if wallet.utxos().contains_key(&input.previous_output) {
        mine = true;
      }

      let Some(output) = wallet.get_output(&input.previous_output)? else {
        return Err(anyhow!("input {} does not exist", input.previous_output));
      };

      inputs.push((index, output, mine));
    }

    let Some((_, output, mine)) = inputs.first() else {
      return Err(anyhow!("Wrong PSBT format"));
    };

    let Some(inscriptions) = output.inscriptions.clone() else {
      return Err(anyhow!("Wrong PSBT format"));
    };

    ensure!(
      inscriptions.len() <= 1,
      "input {} contains more than 1 inscription",
      output.outpoint
    );

    let Some(inscription) = inscriptions.first() else {
      return Err(anyhow!("PSBT contains no inscription"));
    };

    let role = if *mine { Role::Seller } else { Role::Buyer };

    let buyer_address = Address::from_script(
      &psbt.unsigned_tx.output[0].script_pubkey,
      wallet.chain().network(),
    )?
    .as_unchecked()
    .clone();

    let seller_address = Address::from_script(
      &psbt.unsigned_tx.output[1].script_pubkey,
      wallet.chain().network(),
    )?
    .as_unchecked()
    .clone();

    Ok(Some(Box::new(Output {
      psbt: self.psbt.clone(),
      role,
      buyer_address,
      seller_address,
      inscription: *inscription,
      balance_change: wallet.simulate_transaction(&psbt.unsigned_tx)?.to_sat(),
    })))
  }
}
