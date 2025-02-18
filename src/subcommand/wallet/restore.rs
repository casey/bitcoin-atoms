use super::*;

#[derive(Debug, Clone)]
pub(crate) struct Timestamp(bitcoincore_rpc::json::Timestamp);

impl FromStr for Timestamp {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Ok(if s == "now" {
      Self(bitcoincore_rpc::json::Timestamp::Now)
    } else {
      Self(bitcoincore_rpc::json::Timestamp::Time(s.parse()?))
    })
  }
}

#[derive(Debug, Parser)]
pub(crate) struct Restore {
  #[clap(value_enum, long, help = "Restore wallet from <SOURCE> on stdin.")]
  from: Source,
  #[arg(long, help = "Use <PASSPHRASE> when deriving wallet.")]
  pub(crate) passphrase: Option<String>,
  #[arg(
    long,
    help = "Scan chain from <TIMESTAMP> onwards. Can be a unix timestamp in \
    seconds or the string `now`, to skip scanning"
  )]
  pub(crate) timestamp: Option<Timestamp>,
}

#[derive(clap::ValueEnum, Debug, Clone)]
enum Source {
  Descriptor,
  Mnemonic,
}

impl Restore {
  pub(crate) fn run(self, name: String, settings: &Settings) -> SubcommandResult {
    ensure!(
      !settings
        .bitcoin_rpc_client(None)?
        .list_wallet_dir()?
        .iter()
        .any(|wallet_name| wallet_name == &name),
      "wallet `{}` already exists",
      name
    );

    let mut buffer = String::new();

    match self.from {
      Source::Descriptor => {
        io::stdin().read_to_string(&mut buffer)?;

        ensure!(
          self.passphrase.is_none(),
          "descriptor does not take a passphrase"
        );

        ensure!(
          self.timestamp.is_none(),
          "descriptor does not take a timestamp"
        );

        let wallet_descriptors: ListDescriptorsResult = serde_json::from_str(&buffer)?;
        Wallet::initialize_from_descriptors(name, settings, wallet_descriptors.descriptors)?;
      }
      Source::Mnemonic => {
        io::stdin().read_line(&mut buffer)?;
        let mnemonic = Mnemonic::from_str(&buffer)?;
        Wallet::initialize_old(
          name,
          settings,
          mnemonic.to_seed(self.passphrase.unwrap_or_default()),
          self
            .timestamp
            .unwrap_or(Timestamp(bitcoincore_rpc::json::Timestamp::Time(0)))
            .0,
        )?;
      }
    }

    Ok(None)
  }
}
