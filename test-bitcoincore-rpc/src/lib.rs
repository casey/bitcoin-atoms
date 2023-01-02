use {
  api::Api,
  bitcoin::{
    blockdata::constants::COIN_VALUE,
    blockdata::script,
    consensus::encode::{deserialize, serialize},
    hash_types::BlockHash,
    hashes::Hash,
    util::amount::SignedAmount,
    Amount, Block, BlockHeader, Network, OutPoint, PackedLockTime, Script, Sequence, Transaction,
    TxIn, TxMerkleNode, TxOut, Txid, Witness, Wtxid,
  },
  bitcoincore_rpc::json::{
    Bip125Replaceable, CreateRawTransactionInput, GetBalancesResult, GetBalancesResultEntry,
    GetBlockHeaderResult, GetBlockchainInfoResult, GetDescriptorInfoResult, GetNetworkInfoResult,
    GetRawTransactionResult, GetTransactionResult, GetTransactionResultDetail,
    GetTransactionResultDetailCategory, GetWalletInfoResult, ListTransactionResult,
    ListUnspentResultEntry, LoadWalletResult, SignRawTransactionResult, WalletTxInfo,
  },
  jsonrpc_core::{IoHandler, Value},
  jsonrpc_http_server::{CloseHandle, ServerBuilder},
  server::Server,
  state::State,
  std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex, MutexGuard},
    thread,
    time::Duration,
  },
};

mod api;
mod server;
mod state;

pub fn builder() -> Builder {
  Builder {
    network: Network::Bitcoin,
    version: 240000,
    wallet_name: "ord",
  }
}

pub struct Builder {
  network: Network,
  version: usize,
  wallet_name: &'static str,
}

impl Builder {
  pub fn network(self, network: Network) -> Self {
    Self { network, ..self }
  }

  pub fn version(self, version: usize) -> Self {
    Self { version, ..self }
  }

  pub fn wallet_name(self, wallet_name: &'static str) -> Self {
    Self {
      wallet_name,
      ..self
    }
  }

  pub fn build(self) -> Handle {
    let state = Arc::new(Mutex::new(State::new(
      self.network,
      self.version,
      self.wallet_name,
    )));
    let server = Server::new(state.clone());
    let mut io = IoHandler::default();
    io.extend_with(server.to_delegate());

    let rpc_server = ServerBuilder::new(io)
      .threads(1)
      .start_http(&"127.0.0.1:0".parse().unwrap())
      .unwrap();

    let close_handle = rpc_server.close_handle();
    let port = rpc_server.address().port();

    thread::spawn(|| rpc_server.wait());

    for i in 0.. {
      match reqwest::blocking::get(format!("http://127.0.0.1:{port}/")) {
        Ok(_) => break,
        Err(err) => {
          if i == 400 {
            panic!("Server failed to start: {err}");
          }
        }
      }

      thread::sleep(Duration::from_millis(25));
    }

    Handle {
      close_handle: Some(close_handle),
      port,
      state,
    }
  }
}

pub fn spawn() -> Handle {
  builder().build()
}

pub struct TransactionTemplate<'a> {
  pub fee: u64,
  pub inputs: &'a [(usize, usize, usize)],
  pub output_values: &'a [u64],
  pub outputs: usize,
  pub witness: Witness,
}

impl<'a> Default for TransactionTemplate<'a> {
  fn default() -> Self {
    Self {
      fee: 0,
      inputs: &[],
      output_values: &[],
      outputs: 1,
      witness: Witness::default(),
    }
  }
}

pub struct Handle {
  close_handle: Option<CloseHandle>,
  port: u16,
  state: Arc<Mutex<State>>,
}

impl Handle {
  pub fn url(&self) -> String {
    format!("http://127.0.0.1:{}", self.port)
  }

  fn state(&self) -> MutexGuard<State> {
    self.state.lock().unwrap()
  }

  pub fn wallets(&self) -> BTreeSet<String> {
    self.state().wallets.clone()
  }

  pub fn mine_blocks(&self, n: u64) -> Vec<Block> {
    self.mine_blocks_with_subsidy(n, 50 * COIN_VALUE)
  }

  pub fn mine_blocks_with_subsidy(&self, n: u64, subsidy: u64) -> Vec<Block> {
    let mut bitcoin_rpc_data = self.state.lock().unwrap();
    (0..n)
      .map(|_| bitcoin_rpc_data.push_block(subsidy))
      .collect()
  }

  pub fn broadcast_tx(&self, template: TransactionTemplate) -> Txid {
    self.state().broadcast_tx(template)
  }

  pub fn invalidate_tip(&self) -> BlockHash {
    self.state().pop_block()
  }

  pub fn tx(&self, bi: usize, ti: usize) -> Transaction {
    let state = self.state();
    state.blocks[&state.hashes[bi]].txdata[ti].clone()
  }

  pub fn mempool(&self) -> Vec<Transaction> {
    self.state.lock().unwrap().mempool().to_vec()
  }

  pub fn descriptors(&self) -> u64 {
    self.state.lock().unwrap().descriptors
  }
}

impl Drop for Handle {
  fn drop(&mut self) {
    self.close_handle.take().unwrap().close();
  }
}
