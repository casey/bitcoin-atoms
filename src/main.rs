#![allow(clippy::too_many_arguments)]

use {
  crate::{
    arguments::Arguments, bytes::Bytes, epoch::Epoch, height::Height, index::Index, nft::Nft,
    options::Options, ordinal::Ordinal, sat_point::SatPoint, subcommand::Subcommand,
    wallet::Wallet as OrdWallet,
  },
  anyhow::{anyhow, bail, Context, Error},
  axum::{
    extract, http::StatusCode, response::Html, response::IntoResponse, routing::get, Json, Router,
  },
  axum_server::Handle,
  bdk::{
    blockchain::rpc::{Auth, RpcBlockchain, RpcConfig},
    blockchain::{Blockchain, ConfigurableBlockchain},
    database::SqliteDatabase,
    keys::bip39::Mnemonic,
    template::Bip84,
    wallet::{signer::SignOptions, AddressIndex::LastUnused},
    wallet::{wallet_name_from_descriptor, SyncOptions},
    KeychainKind, LocalUtxo,
  },
  bitcoin::{
    blockdata::constants::COIN_VALUE,
    consensus::{Decodable, Encodable},
    hash_types::BlockHash,
    hashes::{sha256, sha256d, Hash, HashEngine},
    secp256k1::{self, rand::thread_rng, schnorr::Signature, KeyPair, Secp256k1, XOnlyPublicKey},
    util::key::PrivateKey,
    Address, Block, Network, OutPoint, Transaction, Txid,
  },
  chrono::{DateTime, NaiveDateTime, Utc},
  clap::Parser,
  derive_more::{Display, FromStr},
  dirs::data_dir,
  lazy_static::lazy_static,
  redb::{Database, ReadableTable, Table, TableDefinition, WriteTransaction},
  serde::{Deserialize, Serialize},
  std::{
    cmp::Ordering,
    collections::VecDeque,
    env,
    fmt::{self, Display, Formatter},
    fs,
    io::{self, Write},
    net::ToSocketAddrs,
    ops::{Add, AddAssign, Deref, Sub},
    path::PathBuf,
    process,
    str::FromStr,
    sync::{
      atomic::{self, AtomicU64},
      Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
  },
  tokio::runtime::Runtime,
  tower_http::cors::{Any, CorsLayer},
};

const PERIOD_BLOCKS: u64 = 2016;
const CYCLE_EPOCHS: u64 = 6;

mod arguments;
mod bytes;
mod epoch;
mod height;
mod index;
mod nft;
mod options;
mod ordinal;
mod sat_point;
mod subcommand;
mod wallet;

type Result<T = (), E = Error> = std::result::Result<T, E>;

static INTERRUPTS: AtomicU64 = AtomicU64::new(0);

lazy_static! {
  static ref LISTENERS: Mutex<Vec<Handle>> = Mutex::new(Vec::new());
}

fn main() {
  env_logger::init();

  ctrlc::set_handler(move || {
    LISTENERS
      .lock()
      .unwrap()
      .iter()
      .for_each(|handle| handle.graceful_shutdown(Some(Duration::from_millis(100))));

    let interrupts = INTERRUPTS.fetch_add(1, atomic::Ordering::Relaxed);

    if interrupts > 5 {
      process::exit(1);
    }
  })
  .expect("Error setting ctrl-c handler");

  if let Err(err) = Arguments::parse().run() {
    eprintln!("error: {}", err);
    err
      .chain()
      .skip(1)
      .for_each(|cause| eprintln!("because: {}", cause));
    if env::var_os("RUST_BACKTRACE")
      .map(|val| val == "1")
      .unwrap_or_default()
    {
      eprintln!("{}", err.backtrace());
    }
    process::exit(1);
  }
}
