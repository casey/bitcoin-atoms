use super::*;

pub(crate) fn run(options: Options) -> Result {
  for utxo in OrdWallet::load(&options)?.wallet.list_unspent()? {
    println!(
      "{}:{} {}",
      utxo.outpoint.txid, utxo.outpoint.vout, utxo.txout.value
    );
  }
  Ok(())
}
