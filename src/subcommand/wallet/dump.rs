use super::*;

#[derive(Serialize, Deserialize)]
pub struct Output {
  pub descriptor: String,
  pub change_descriptor: String,
}

pub(crate) fn run(wallet: Wallet) -> SubcommandResult {
  eprintln!(
    "==========================================
= THIS STRING CONTAINS YOUR PRIVATE KEYS =
=        DO NOT SHARE WITH ANYONE        =
=========================================="
  );

  let descriptor = wallet
    .wallet
    .public_descriptor(KeychainKind::External)
    .to_string();

  let change_descriptor = wallet
    .wallet
    .public_descriptor(KeychainKind::Internal)
    .to_string();

  Ok(Some(Box::new(Output {
    descriptor,
    change_descriptor,
  })))
}
