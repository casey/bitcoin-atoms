#![allow(
  clippy::large_enum_variant,
  clippy::result_large_err,
  clippy::too_many_arguments,
  clippy::type_complexity
)]
#![deny(
  clippy::cast_lossless,
  clippy::cast_possible_truncation,
  clippy::cast_possible_wrap,
  clippy::cast_sign_loss
)]

use {
  self::{
    arguments::Arguments,
    blocktime::Blocktime,
    decimal::Decimal,
    deserialize_from_str::DeserializeFromStr,
    index::BitcoinCoreRpcResultExt,
    inscriptions::{
      inscription_id,
      media::{self, ImageRendering, Media},
      teleburn, ParsedEnvelope,
    },
    into_usize::IntoUsize,
    option_ext::OptionExt,
    outgoing::Outgoing,
    properties::Properties,
    representation::Representation,
    satscard::Satscard,
    settings::Settings,
    signer::Signer,
    subcommand::{OutputFormat, Subcommand, SubcommandResult},
    tally::Tally,
  },
  anyhow::{anyhow, bail, ensure, Context, Error},
  bdk_wallet::{self as bdk, KeychainKind, PersistedWallet},
  bip39::Mnemonic,
  bitcoin::{
    address::{Address, NetworkUnchecked},
    blockdata::{
      constants::{DIFFCHANGE_INTERVAL, MAX_SCRIPT_ELEMENT_SIZE, SUBSIDY_HALVING_INTERVAL},
      locktime::absolute::LockTime,
    },
    consensus::{self, Decodable, Encodable},
    hash_types::{BlockHash, TxMerkleNode},
    hashes::Hash,
    policy::MAX_STANDARD_TX_WEIGHT,
    script, secp256k1,
    transaction::Version,
    Amount, Block, KnownHrp, Network, OutPoint, Script, ScriptBuf, Sequence, SignedAmount,
    Transaction, TxIn, TxOut, Txid, Witness,
  },
  bitcoincore_rpc::{Client, RpcApi},
  chrono::{DateTime, TimeZone, Utc},
  ciborium::Value,
  clap::{ArgGroup, Parser},
  error::{ResultExt, SnafuError},
  html_escaper::{Escape, Trusted},
  lazy_static::lazy_static,
  ordinals::{
    varint, Artifact, Charm, Edict, Epoch, Etching, Height, Pile, Rarity, Rune, RuneId, Runestone,
    Sat, SatPoint, SpacedRune, Terms,
  },
  regex::Regex,
  reqwest::{header::HeaderMap, StatusCode, Url},
  serde::{Deserialize, Deserializer, Serialize},
  serde_with::{DeserializeFromStr, SerializeDisplay},
  snafu::{Backtrace, ErrorCompat, Snafu},
  std::{
    backtrace::BacktraceStatus,
    cmp,
    collections::{BTreeMap, BTreeSet, HashSet},
    env,
    ffi::OsString,
    fmt::{self, Display, Formatter},
    fs::{self, File},
    io::{self, BufReader, Cursor, Read},
    mem,
    net::ToSocketAddrs,
    path::{Path, PathBuf},
    process::{self, Command, Stdio},
    str::FromStr,
    sync::{
      atomic::{self, AtomicBool},
      Arc, LazyLock, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime},
  },
  sysinfo::System,
  tokio::{runtime::Runtime, task},
};

pub use self::{
  chain::Chain,
  fee_rate::FeeRate,
  index::{Index, RuneEntry},
  inscriptions::{Envelope, Inscription, InscriptionId},
  object::Object,
  options::Options,
  wallet::transaction_builder::{Target, TransactionBuilder},
};

#[cfg(test)]
#[macro_use]
mod test;

#[cfg(test)]
use self::test::*;

pub mod api;
pub mod arguments;
mod blocktime;
pub mod chain;
pub mod decimal;
mod deserialize_from_str;
mod error;
mod fee_rate;
pub mod index;
mod inscriptions;
mod into_usize;
mod macros;
mod object;
mod option_ext;
pub mod options;
pub mod outgoing;
mod properties;
mod re;
mod representation;
pub mod runes;
mod satscard;
pub mod settings;
mod signer;
pub mod subcommand;
mod tally;
pub mod templates;
pub mod wallet;

type Result<T = (), E = Error> = std::result::Result<T, E>;
type SnafuResult<T = (), E = SnafuError> = std::result::Result<T, E>;

const MAX_STANDARD_OP_RETURN_SIZE: usize = 83;
const TARGET_POSTAGE: Amount = Amount::from_sat(10_000);

static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
static LISTENERS: Mutex<Vec<axum_server::Handle>> = Mutex::new(Vec::new());
static INDEXER: Mutex<Option<thread::JoinHandle<()>>> = Mutex::new(None);

#[doc(hidden)]
#[derive(Deserialize, Serialize)]
pub struct SimulateRawTransactionResult {
  #[serde(with = "bitcoin::amount::serde::as_btc")]
  pub balance_change: SignedAmount,
}

#[doc(hidden)]
#[derive(Deserialize, Serialize)]
pub struct SimulateRawTransactionOptions {
  include_watchonly: bool,
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn fund_raw_transaction(
  client: &Client,
  fee_rate: FeeRate,
  unfunded_transaction: &Transaction,
) -> Result<Vec<u8>> {
  let mut buffer = Vec::new();

  {
    unfunded_transaction.version.consensus_encode(&mut buffer)?;
    unfunded_transaction.input.consensus_encode(&mut buffer)?;
    unfunded_transaction.output.consensus_encode(&mut buffer)?;
    unfunded_transaction
      .lock_time
      .consensus_encode(&mut buffer)?;
  }

  Ok(
    client
      .fund_raw_transaction(
        &buffer,
        Some(&bitcoincore_rpc::json::FundRawTransactionOptions {
          // NB. This is `fundrawtransaction`'s `feeRate`, which is fee per kvB
          // and *not* fee per vB. So, we multiply the fee rate given by the user
          // by 1000.
          fee_rate: Some(Amount::from_sat((fee_rate.n() * 1000.0).ceil() as u64)),
          change_position: Some(unfunded_transaction.output.len().try_into()?),
          ..default()
        }),
        Some(false),
      )
      .map_err(|err| {
        if matches!(
          err,
          bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::Error::Rpc(
            bitcoincore_rpc::jsonrpc::error::RpcError { code: -6, .. }
          ))
        ) {
          anyhow!("not enough cardinal utxos")
        } else {
          err.into()
        }
      })?
      .hex,
  )
}

pub fn timestamp(seconds: u64) -> DateTime<Utc> {
  Utc
    .timestamp_opt(seconds.try_into().unwrap_or(i64::MAX), 0)
    .unwrap()
}

fn target_as_block_hash(target: bitcoin::Target) -> BlockHash {
  BlockHash::from_raw_hash(Hash::from_byte_array(target.to_le_bytes()))
}

pub fn unbound_outpoint() -> OutPoint {
  OutPoint {
    txid: Hash::all_zeros(),
    vout: 0,
  }
}

fn uncheck(address: &Address) -> Address<NetworkUnchecked> {
  address.to_string().parse().unwrap()
}

pub fn base64_encode(data: &[u8]) -> String {
  use base64::Engine;
  base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
  use base64::Engine;
  Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

fn default<T: Default>() -> T {
  Default::default()
}

pub fn parse_ord_server_args(args: &str) -> (Settings, subcommand::server::Server) {
  match Arguments::try_parse_from(args.split_whitespace()) {
    Ok(arguments) => match arguments.subcommand {
      Subcommand::Server(server) => (
        Settings::merge(
          arguments.options,
          vec![("INTEGRATION_TEST".into(), "1".into())]
            .into_iter()
            .collect(),
        )
        .unwrap(),
        server,
      ),
      subcommand => panic!("unexpected subcommand: {subcommand:?}"),
    },
    Err(err) => panic!("error parsing arguments: {err}"),
  }
}

pub fn cancel_shutdown() {
  SHUTTING_DOWN.store(false, atomic::Ordering::Relaxed);
}

pub fn shut_down() {
  SHUTTING_DOWN.store(true, atomic::Ordering::Relaxed);
}

fn gracefully_shut_down_indexer() {
  if let Some(indexer) = INDEXER.lock().unwrap().take() {
    shut_down();
    log::info!("Waiting for index thread to finish...");
    if indexer.join().is_err() {
      log::warn!("Index thread panicked; join failed");
    }
  }
}

pub fn main() {
  env_logger::init();

  ctrlc::set_handler(move || {
    if SHUTTING_DOWN.fetch_or(true, atomic::Ordering::Relaxed) {
      process::exit(1);
    }

    eprintln!("Shutting down gracefully. Press <CTRL-C> again to shutdown immediately.");

    LISTENERS
      .lock()
      .unwrap()
      .iter()
      .for_each(|handle| handle.graceful_shutdown(Some(Duration::from_millis(100))));

    gracefully_shut_down_indexer();
  })
  .expect("Error setting <CTRL-C> handler");

  let args = Arguments::parse();

  let format = args.options.format;

  match args.run() {
    Err(err) => {
      eprintln!("error: {err}");

      if let SnafuError::Anyhow { err } = err {
        for (i, err) in err.chain().skip(1).enumerate() {
          if i == 0 {
            eprintln!();
            eprintln!("because:");
          }

          eprintln!("- {err}");
        }

        if env::var_os("RUST_BACKTRACE")
          .map(|val| val == "1")
          .unwrap_or_default()
        {
          eprintln!("{}", err.backtrace());
        }
      } else {
        for (i, err) in err.iter_chain().skip(1).enumerate() {
          if i == 0 {
            eprintln!();
            eprintln!("because:");
          }

          eprintln!("- {err}");
        }

        if let Some(backtrace) = err.backtrace() {
          if backtrace.status() == BacktraceStatus::Captured {
            eprintln!("backtrace:");
            eprintln!("{backtrace}");
          }
        }
      }

      gracefully_shut_down_indexer();

      process::exit(1);
    }
    Ok(output) => {
      if let Some(output) = output {
        output.print(format.unwrap_or_default());
      }
      gracefully_shut_down_indexer();
    }
  }
}
