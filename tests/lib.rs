#![allow(clippy::type_complexity)]

use {
  bdk::{
    blockchain::{
      rpc::{RpcBlockchain, RpcConfig},
      ConfigurableBlockchain,
    },
    database::MemoryDatabase,
    keys::bip39::Mnemonic,
    template::Bip84,
    wallet::{signer::SignOptions, AddressIndex, SyncOptions, Wallet},
    KeychainKind,
  },
  bitcoin::hash_types::Txid,
  bitcoin::{network::constants::Network, Block, OutPoint},
  bitcoincore_rpc::{Client, RawTx, RpcApi},
  executable_path::executable_path,
  log::LevelFilter,
  nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
  },
  regex::Regex,
  std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    fs,
    net::TcpListener,
    process::{Child, Command, Stdio},
    str,
    sync::Once,
    thread::sleep,
    time::{Duration, Instant},
  },
  tempfile::TempDir,
  unindent::Unindent,
};

mod epochs;
mod find;
mod index;
mod info;
mod list;
mod name;
mod nft;
mod range;
mod server;
mod supply;
mod traits;
mod version;
mod wallet;

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

static ONCE: Once = Once::new();

fn free_port() -> Result<u16> {
  Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

#[derive(Debug)]
enum Expected {
  String(String),
  Regex(Regex),
  Ignore,
}

impl Expected {
  fn regex(pattern: &str) -> Self {
    Self::Regex(Regex::new(&format!("^(?s){}$", pattern)).unwrap())
  }

  fn assert_match(&self, output: &str) {
    match self {
      Self::String(string) => assert_eq!(output, string),
      Self::Regex(regex) => assert!(
        regex.is_match(output),
        "output did not match regex: {:?}",
        output
      ),
      Self::Ignore => {}
    }
  }
}

enum Event<'a> {
  Blocks(u64),
  Request(String, u16, String),
  Transaction(TransactionOptions<'a>),
}

struct Output {
  bitcoind: Bitcoind,
  client: Client,
  rpc_port: u16,
  stdout: String,
  tempdir: TempDir,
}

struct TransactionOptions<'a> {
  slots: &'a [(usize, usize, usize)],
  output_count: usize,
  fee: u64,
}

struct Test<'a> {
  args: Vec<String>,
  bitcoind: Bitcoind,
  blockchain: RpcBlockchain,
  client: Client,
  envs: Vec<(OsString, OsString)>,
  events: Vec<Event<'a>>,
  expected_status: i32,
  expected_stderr: Expected,
  expected_stdout: Expected,
  rpc_port: u16,
  tempdir: TempDir,
  wallet: Wallet<MemoryDatabase>,
}

struct Bitcoind(Child);

impl Drop for Bitcoind {
  fn drop(&mut self) {
    self.0.kill().unwrap();
  }
}

impl<'a> Test<'a> {
  fn new() -> Result<Self> {
    Self::with_tempdir(TempDir::new()?)
  }

  fn with_tempdir(tempdir: TempDir) -> Result<Self> {
    ONCE.call_once(|| {
      env_logger::init();
    });

    let datadir = tempdir.path().join("bitcoin");

    fs::create_dir(&datadir).unwrap();

    let rpc_port = free_port()?;

    let bitcoind = Command::new("bitcoind")
      .stdout(if log::max_level() >= LevelFilter::Info {
        Stdio::inherit()
      } else {
        Stdio::piped()
      })
      .args(&[
        "-minrelaytxfee=0",
        "-blockmintxfee=0",
        "-dustrelayfee=0",
        "-maxtxfee=21000000",
        "-datadir=bitcoin",
        "-regtest",
        &format!("-rpcport={rpc_port}"),
      ])
      .current_dir(&tempdir.path())
      .spawn()?;

    let cookiefile = datadir.join("regtest/.cookie");

    while !cookiefile.is_file() {}

    let client = Client::new(
      &format!("localhost:{rpc_port}"),
      bitcoincore_rpc::Auth::CookieFile(cookiefile.clone()),
    )?;

    loop {
      let mut attempts = 0;
      match client.get_blockchain_info() {
        Ok(_) => break,
        Err(error) => {
          attempts += 1;
          if attempts > 300 {
            panic!("Failed to connect to bitcoind: {error}");
          }
          sleep(Duration::from_millis(100));
        }
      }
    }

    let wallet = Wallet::new(
      Bip84(
        (
          Mnemonic::parse("book fit fly ketchup also elevator scout mind edit fatal where rookie")?,
          None,
        ),
        KeychainKind::External,
      ),
      None,
      Network::Regtest,
      MemoryDatabase::new(),
    )?;

    let blockchain = RpcBlockchain::from_config(&RpcConfig {
      url: format!("localhost:{rpc_port}"),
      auth: bdk::blockchain::rpc::Auth::Cookie { file: cookiefile },
      network: Network::Regtest,
      wallet_name: "test".to_string(),
      skip_blocks: None,
    })?;

    let test = Self {
      args: Vec::new(),
      client,
      blockchain,
      bitcoind: Bitcoind(bitcoind),
      envs: Vec::new(),
      events: Vec::new(),
      expected_status: 0,
      expected_stderr: Expected::Ignore,
      expected_stdout: Expected::String(String::new()),
      rpc_port,
      tempdir,
      wallet,
    };

    test.sync()?;

    Ok(test)
  }

  fn connect(output: Output) -> Result<Self> {
    ONCE.call_once(|| {
      env_logger::init();
    });

    let cookiefile = output.tempdir.path().join("bitcoin/regtest/.cookie");

    let client = Client::new(
      &format!("127.0.0.1:{}", output.rpc_port),
      bitcoincore_rpc::Auth::CookieFile(cookiefile.clone()),
    )?;

    log::info!("Connecting to client...");

    loop {
      let mut attempts = 0;
      match client.get_blockchain_info() {
        Ok(_) => break,
        Err(error) => {
          attempts += 1;
          if attempts > 300 {
            panic!("Failed to connect to bitcoind: {error}");
          }
          sleep(Duration::from_millis(100));
        }
      }
    }

    let wallet = Wallet::new(
      Bip84(
        (
          Mnemonic::parse("book fit fly ketchup also elevator scout mind edit fatal where rookie")?,
          None,
        ),
        KeychainKind::External,
      ),
      None,
      Network::Regtest,
      MemoryDatabase::new(),
    )?;

    let blockchain = RpcBlockchain::from_config(&RpcConfig {
      url: format!("127.0.0.1:{}", output.rpc_port),
      auth: bdk::blockchain::rpc::Auth::Cookie { file: cookiefile },
      network: Network::Regtest,
      wallet_name: "test".to_string(),
      skip_blocks: None,
    })?;

    let test = Self {
      args: Vec::new(),
      client,
      blockchain,
      bitcoind: output.bitcoind,
      envs: Vec::new(),
      events: Vec::new(),
      expected_status: 0,
      expected_stderr: Expected::Ignore,
      expected_stdout: Expected::String(String::new()),
      rpc_port: output.rpc_port,
      tempdir: output.tempdir,
      wallet,
    };

    test.sync()?;

    Ok(test)
  }

  fn command(self, args: &str) -> Self {
    Self {
      args: args.split_whitespace().map(str::to_owned).collect(),
      ..self
    }
  }

  fn args(self, args: &[&str]) -> Self {
    Self {
      args: self
        .args
        .into_iter()
        .chain(args.iter().cloned().map(str::to_owned))
        .collect(),
      ..self
    }
  }

  fn expected_stdout(self, expected_stdout: impl AsRef<str>) -> Self {
    Self {
      expected_stdout: Expected::String(expected_stdout.as_ref().to_owned()),
      ..self
    }
  }

  fn stdout_regex(self, expected_stdout: impl AsRef<str>) -> Self {
    Self {
      expected_stdout: Expected::regex(expected_stdout.as_ref()),
      ..self
    }
  }

  fn set_home_to_tempdir(mut self) -> Self {
    self
      .envs
      .push((OsString::from("HOME"), OsString::from(self.tempdir.path())));

    self
  }

  fn expected_stderr(self, expected_stderr: &str) -> Self {
    Self {
      expected_stderr: Expected::String(expected_stderr.to_owned()),
      ..self
    }
  }

  fn stderr_regex(self, expected_stderr: impl AsRef<str>) -> Self {
    Self {
      expected_stderr: Expected::regex(expected_stderr.as_ref()),
      ..self
    }
  }

  fn expected_status(self, expected_status: i32) -> Self {
    Self {
      expected_status,
      ..self
    }
  }

  fn ignore_stdout(self) -> Self {
    Self {
      expected_stdout: Expected::Ignore,
      ..self
    }
  }

  fn request(mut self, path: &str, status: u16, response: &str) -> Self {
    self.events.push(Event::Request(
      path.to_string(),
      status,
      response.to_string(),
    ));
    self
  }

  fn run(self) -> Result {
    self.test(None).map(|_| ())
  }

  fn output(self) -> Result<Output> {
    self.test(None)
  }

  fn run_server(self, port: u16) -> Result {
    self.test(Some(port)).map(|_| ())
  }

  fn get_block(&self, height: u64) -> Result<Block> {
    Ok(
      self
        .client
        .get_block(&self.client.get_block_hash(height)?)?,
    )
  }

  fn run_server_output(self, port: u16) -> Output {
    self.test(Some(port)).unwrap()
  }

  fn sync(&self) -> Result {
    self.wallet.sync(&self.blockchain, SyncOptions::default())?;
    Ok(())
  }

  fn test(self, port: Option<u16>) -> Result<Output> {
    let client = reqwest::blocking::Client::new();

    let (healthy, child) = if let Some(port) = port {
      log::info!("Spawning ord server child process...");

      let child = Command::new(executable_path("ord"))
        .envs(self.envs.clone())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if !matches!(self.expected_stderr, Expected::Ignore) {
          Stdio::piped()
        } else {
          Stdio::inherit()
        })
        .current_dir(&self.tempdir)
        .arg(format!("--rpc-url=127.0.0.1:{}", self.rpc_port))
        .arg("--cookie-file=bitcoin/regtest/.cookie")
        .args(self.args.clone())
        .spawn()?;

      let start = Instant::now();
      let mut healthy = false;

      loop {
        if let Ok(response) = client
          .get(&format!("http://127.0.0.1:{port}/status"))
          .send()
        {
          if response.status().is_success() {
            healthy = true;
            break;
          }
        }

        if Instant::now() - start > Duration::from_secs(1) {
          break;
        }

        sleep(Duration::from_millis(100));
      }

      (healthy, Some(child))
    } else {
      (false, None)
    };

    log::info!(
      "Server status: {}",
      if healthy { "healthy" } else { "unhealthy" }
    );

    let mut successful_requests = 0;

    for event in &self.events {
      match event {
        Event::Blocks(n) => {
          self
            .client
            .generate_to_address(*n, &self.wallet.get_address(AddressIndex::Peek(0))?.address)?;
        }
        Event::Request(request, status, expected_response) => {
          if healthy {
            let response = client
              .get(&format!("http://127.0.0.1:{}/{request}", port.unwrap()))
              .send()?;
            log::info!("{:?}", response);
            assert_eq!(response.status().as_u16(), *status);
            assert_eq!(response.text()?, *expected_response);
            successful_requests += 1;
          } else {
            panic!("Tried to make a request when unhealthy");
          }
        }
        Event::Transaction(options) => {
          self.sync()?;

          let input_value = options
            .slots
            .iter()
            .map(|slot| self.get_block(slot.0 as u64).unwrap().txdata[slot.1].output[slot.2].value)
            .sum::<u64>();

          let output_value = input_value - options.fee;

          let (mut psbt, _) = {
            let mut builder = self.wallet.build_tx();

            builder
              .manually_selected_only()
              .fee_absolute(options.fee)
              .allow_dust(true)
              .add_utxos(
                &options
                  .slots
                  .iter()
                  .map(|slot| OutPoint {
                    txid: self.get_block(slot.0 as u64).unwrap().txdata[slot.1].txid(),
                    vout: slot.2 as u32,
                  })
                  .collect::<Vec<OutPoint>>(),
              )?
              .set_recipients(vec![
                (
                  self
                    .wallet
                    .get_address(AddressIndex::Peek(0))?
                    .address
                    .script_pubkey(),
                  output_value / options.output_count as u64
                );
                options.output_count
              ]);

            builder.finish()?
          };

          if !self.wallet.sign(&mut psbt, SignOptions::default())? {
            panic!("Failed to sign transaction");
          }

          self.client.call::<Txid>(
            "sendrawtransaction",
            &[psbt.extract_tx().raw_hex().into(), 21000000.into()],
          )?;
        }
      }
    }

    let child = if let Some(child) = child {
      log::info!("Killing server child process...");
      signal::kill(Pid::from_raw(child.id() as i32), Signal::SIGINT)?;
      child
    } else {
      log::info!("Spawning ord child process...");
      Command::new(executable_path("ord"))
        .envs(self.envs.clone())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if !matches!(self.expected_stderr, Expected::Ignore) {
          Stdio::piped()
        } else {
          Stdio::inherit()
        })
        .current_dir(&self.tempdir)
        .arg(format!("--rpc-url=127.0.0.1:{}", self.rpc_port))
        .arg("--cookie-file=bitcoin/regtest/.cookie")
        .args(self.args.clone())
        .spawn()?
    };

    let output = child.wait_with_output()?;

    let stdout = str::from_utf8(&output.stdout)?;
    let stderr = str::from_utf8(&output.stderr)?;

    if output.status.code() != Some(self.expected_status) {
      panic!(
        "Test failed: {}\nstdout:\n{}\nstderr:\n{}",
        output.status, stdout, stderr
      );
    }

    let log_line_re = Regex::new(r"(?m)^\[.*\n")?;

    for log_line in log_line_re.find_iter(stderr) {
      print!("{}", log_line.as_str())
    }

    let stripped_stderr = log_line_re.replace_all(stderr, "");

    self.expected_stderr.assert_match(&stripped_stderr);
    self.expected_stdout.assert_match(stdout);

    assert_eq!(
      successful_requests,
      self
        .events
        .iter()
        .filter(|event| matches!(event, Event::Request(..)))
        .count(),
      "Unsuccessful requests"
    );

    Ok(Output {
      bitcoind: self.bitcoind,
      client: self.client,
      rpc_port: self.rpc_port,
      stdout: stdout.to_string(),
      tempdir: self.tempdir,
    })
  }

  fn blocks(mut self, n: u64) -> Self {
    self.events.push(Event::Blocks(n));
    self
  }

  fn transaction(mut self, options: TransactionOptions<'a>) -> Self {
    self.events.push(Event::Transaction(options));
    self
  }

  fn write(self, path: &str, contents: &str) -> Result<Self> {
    fs::write(self.tempdir.path().join(path), contents)?;
    Ok(self)
  }
}
