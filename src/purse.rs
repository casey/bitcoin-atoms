use super::*;

#[derive(Debug)]
pub(crate) struct Purse {
  pub(crate) blockchain: RpcBlockchain,
  pub(crate) wallet: bdk::wallet::Wallet<SqliteDatabase>,
}

impl Purse {
  pub(crate) fn init(options: &Options) -> Result {
    let data_dir = options.data_dir()?;

    let entropy = data_dir.join("entropy");

    if entropy.exists() {
      return Err(anyhow!("Wallet already exists."));
    }

    let seed = Mnemonic::generate_in_with(&mut rand::thread_rng(), Language::English, 12)?;

    fs::write(entropy, seed.to_entropy())?;

    let wallet = bdk::wallet::Wallet::new(
      Bip84((seed.clone(), None), KeychainKind::External),
      None,
      options.network,
      SqliteDatabase::new(
        data_dir
          .join("wallet.sqlite")
          .to_str()
          .ok_or_else(|| anyhow!("Failed to convert path to str"))?,
      ),
    )?;

    wallet.sync(&Self::blockchain(options, seed)?, SyncOptions::default())?;

    eprintln!("Wallet initialized.");

    Ok(())
  }

  pub(crate) fn load(options: &Options) -> Result<Self> {
    let data_dir = options.data_dir()?;

    let entropy = data_dir.join("entropy");

    if !entropy.exists() {
      return Err(anyhow!("Wallet doesn't exist."));
    }

    let seed = Mnemonic::from_entropy(&fs::read(entropy)?)?;

    let wallet = bdk::wallet::Wallet::new(
      Bip84((seed.clone(), None), KeychainKind::External),
      None,
      options.network,
      SqliteDatabase::new(
        data_dir
          .join("wallet.sqlite")
          .to_str()
          .ok_or_else(|| anyhow!("Failed to convert path to str"))?,
      ),
    )?;

    let blockchain = Self::blockchain(options, seed)?;

    wallet.sync(&blockchain, SyncOptions::default())?;

    Ok(Self { blockchain, wallet })
  }

  pub(crate) fn find(&self, options: &Options, ordinal: Ordinal) -> Result<LocalUtxo> {
    let index = Index::index(options)?;

    for utxo in self.wallet.list_unspent()? {
      match index.list(utxo.outpoint)? {
        Some(List::Unspent(ranges)) => {
          for (start, end) in ranges {
            if ordinal.0 >= start && ordinal.0 < end {
              return Ok(utxo);
            }
          }
        }
        Some(List::Spent(txid)) => {
          return Err(anyhow!(
            "UTXO unspent in wallet but spent in index by transaction {txid}"
          ));
        }
        None => {
          return Err(anyhow!("UTXO unspent in wallet but not found in index"));
        }
      }
    }

    bail!("No utxo contains {}˚.", ordinal);
  }

  pub(crate) fn special_ordinals(
    &self,
    options: &Options,
    outpoint: OutPoint,
  ) -> Result<Vec<Ordinal>> {
    let index = Index::index(options)?;

    match index.list(outpoint)? {
      Some(List::Unspent(ranges)) => Ok(
        ranges
          .into_iter()
          .map(|(start, _end)| Ordinal(start))
          .filter(|ordinal| ordinal.rarity() > Rarity::Common)
          .collect(),
      ),
      Some(List::Spent(txid)) => Err(anyhow!(
        "UTXO {} unspent in wallet but spent in index by transaction {txid}",
        outpoint
      )),
      None => Ok(Vec::new()),
    }
  }

  fn blockchain(options: &Options, key: Mnemonic) -> Result<RpcBlockchain> {
    Ok(RpcBlockchain::from_config(&RpcConfig {
      url: options.rpc_url(),
      auth: Auth::Cookie {
        file: options.cookie_file()?,
      },
      network: options.network,
      wallet_name: wallet_name_from_descriptor(
        Bip84(key, KeychainKind::External),
        None,
        options.network,
        &Secp256k1::new(),
      )?,
      sync_params: None,
    })?)
  }
}
