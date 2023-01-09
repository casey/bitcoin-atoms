use super::*;

#[test]
fn inscribe_fails_if_bitcoin_core_is_too_old() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .version(230000)
    .build();

  let txid = rpc_server.mine_blocks(1)[0].txdata[0].txid();

  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 hello.txt"
  ))
  .write("hello.txt", "HELLOWORLD")
  .expected_exit_code(1)
  .expected_stderr("error: Bitcoin Core 24.0.0 or newer required, current version is 23.0.0\n")
  .rpc_server(&rpc_server)
  .run();
}

#[test]
fn inscribe_no_backup() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  let txid = rpc_server.mine_blocks(1)[0].txdata[0].txid();

  create_wallet(&rpc_server);
  assert_eq!(rpc_server.descriptors().len(), 2);

  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 hello.txt --no-backup"
  ))
  .write("hello.txt", "HELLOWORLD")
  .rpc_server(&rpc_server)
  .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
  .run();

  assert_eq!(rpc_server.descriptors().len(), 2);
}

#[test]
fn inscribe() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  let txid = rpc_server.mine_blocks(1)[0].txdata[0].txid();

  assert_eq!(rpc_server.descriptors().len(), 0);

  create_wallet(&rpc_server);

  let stdout = CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 hello.txt"
  ))
  .write("hello.txt", "HELLOWORLD")
  .rpc_server(&rpc_server)
  .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
  .run();

  let inscription_id = reveal_txid_from_inscribe_stdout(&stdout);

  assert_eq!(rpc_server.descriptors().len(), 3);

  rpc_server.mine_blocks(1);

  let request =
    TestServer::spawn_with_args(&rpc_server, &[]).request(&format!("/content/{inscription_id}"));

  assert_eq!(request.status(), 200);
  assert_eq!(
    request.headers().get("content-type").unwrap(),
    "text/plain;charset=utf-8"
  );
  assert_eq!(request.text().unwrap(), "HELLOWORLD");
}

#[test]
fn inscribe_unknown_file_extension() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  create_wallet(&rpc_server);
  let txid = rpc_server.mine_blocks(1)[0].txdata[0].txid();

  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 pepe.xyz"
  ))
  .write("pepe.xyz", [1; 520])
  .rpc_server(&rpc_server)
  .expected_exit_code(1)
  .stderr_regex(r"error: unsupported file extension `\.xyz`, supported extensions: apng .*\n")
  .run();
}

#[test]
fn inscribe_exceeds_push_byte_limit() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Signet)
    .build();
  create_wallet(&rpc_server);
  let txid = rpc_server.mine_blocks(1)[0].txdata[0].txid();

  CommandBuilder::new(format!(
    "--chain signet wallet inscribe --satpoint {txid}:0:0 degenerate.png"
  ))
  .write("degenerate.png", [1; 1025])
  .rpc_server(&rpc_server)
  .expected_exit_code(1)
  .expected_stderr(
    "error: content size of 1025 bytes exceeds 1024 byte limit for signet inscriptions\n",
  )
  .run();
}

#[test]
fn regtest_has_no_content_size_limit() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  create_wallet(&rpc_server);
  let txid = rpc_server.mine_blocks(1)[0].txdata[0].txid();

  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 degenerate.png"
  ))
  .write("degenerate.png", [1; 1025])
  .rpc_server(&rpc_server)
  .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
  .run();
}

#[test]
fn inscribe_does_not_use_inscribed_sats_as_cardinal_utxos() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  create_wallet(&rpc_server);
  let txid = rpc_server.mine_blocks_with_subsidy(1, 800)[0].txdata[0].txid();
  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 degenerate.png"
  ))
  .write("degenerate.png", [1; 100])
  .rpc_server(&rpc_server)
  .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
  .run();

  let txid = rpc_server.mine_blocks_with_subsidy(1, 100)[0].txdata[0].txid();

  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 degenerate.png"
  ))
  .rpc_server(&rpc_server)
  .write("degenerate.png", [1; 100])
  .expected_exit_code(1)
  .expected_stderr("error: wallet does not contain enough cardinal UTXOs, please add additional funds to wallet.\n")
  .run();
}

#[test]
fn refuse_to_reinscribe_sats() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  create_wallet(&rpc_server);

  let txid = rpc_server.mine_blocks_with_subsidy(1, 800)[0].txdata[0].txid();
  let stdout = CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 degenerate.png"
  ))
  .write("degenerate.png", [1; 100])
  .rpc_server(&rpc_server)
  .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
  .run();

  let first_inscription_id = reveal_txid_from_inscribe_stdout(&stdout);

  rpc_server.mine_blocks_with_subsidy(1, 100)[0].txdata[0].txid();

  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {first_inscription_id}:0:0 hello.txt"
  ))
  .write("hello.txt", "HELLOWORLD")
  .rpc_server(&rpc_server)
  .expected_exit_code(1)
  .expected_stderr(format!(
    "error: sat at {first_inscription_id}:0:0 already inscribed\n"
  ))
  .run();
}

#[test]
fn refuse_to_inscribe_already_inscribed_utxo() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  create_wallet(&rpc_server);

  let txid = rpc_server.mine_blocks(1)[0].txdata[0].txid();
  let stdout = CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {txid}:0:0 degenerate.png"
  ))
  .write("degenerate.png", [1; 100])
  .rpc_server(&rpc_server)
  .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
  .run();

  rpc_server.mine_blocks(1);

  let inscription_id = reveal_txid_from_inscribe_stdout(&stdout);

  let inscription_utxo = OutPoint {
    txid: reveal_txid_from_inscribe_stdout(&stdout),
    vout: 0,
  };

  CommandBuilder::new(format!(
    "--chain regtest wallet inscribe --satpoint {inscription_utxo}:55555 hello.txt"
  ))
  .write("hello.txt", "HELLOWORLD")
  .rpc_server(&rpc_server)
  .expected_exit_code(1)
  .expected_stderr(format!(
    "error: utxo {inscription_utxo} already inscribed with inscription {inscription_id} on sat {inscription_utxo}:0\n",
  ))
  .run();
}

#[test]
fn inscribe_with_optional_satpoint_arg() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();
  create_wallet(&rpc_server);
  rpc_server.mine_blocks(1);

  let stdout = CommandBuilder::new("--chain regtest wallet inscribe hello.txt")
    .write("hello.txt", "HELLOWORLD")
    .rpc_server(&rpc_server)
    .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
    .run();

  let inscription_id = reveal_txid_from_inscribe_stdout(&stdout);

  rpc_server.mine_blocks(1);

  TestServer::spawn_with_args(&rpc_server, &["--index-sats"]).assert_response_regex(
    "/sat/5000000000",
    format!(".*<a href=/inscription/{inscription_id}>.*"),
  );

  TestServer::spawn_with_args(&rpc_server, &[])
    .assert_response_regex(format!("/content/{inscription_id}",), ".*HELLOWORLD.*");
}

#[test]
fn inscribe_with_fee_rate() {
  let rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Signet)
    .build();
  rpc_server.mine_blocks(1);

  CommandBuilder::new("--chain signet --index-sats wallet inscribe degenerate.png --fee-rate 2.0")
    .write("degenerate.png", [1; 520])
    .rpc_server(&rpc_server)
    .stdout_regex("commit\t[[:xdigit:]]{64}\nreveal\t[[:xdigit:]]{64}\n")
    .run();
}
