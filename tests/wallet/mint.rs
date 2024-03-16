use {
  super::*,
  bitcoin::Witness,
  ord::{
    runes::{Etching, Mint},
    subcommand::wallet::mint::Output,
  },
};

#[test]
fn minting_rune_works() {
  let bitcoin_rpc_server = test_bitcoincore_rpc::builder()
    .network(Network::Regtest)
    .build();

  let ord_rpc_server =
    TestServer::spawn_with_server_args(&bitcoin_rpc_server, &["--index-runes", "--regtest"], &[]);

  bitcoin_rpc_server.mine_blocks(1);

  create_wallet(&bitcoin_rpc_server, &ord_rpc_server);

  CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .bitcoin_rpc_server(&bitcoin_rpc_server)
  .ord_rpc_server(&ord_rpc_server)
  .expected_exit_code(1)
  .expected_stderr("error: Rune AAAAAAAAAAAAA does not exist\n")
  .run_and_extract_stdout();

  bitcoin_rpc_server.broadcast_tx(TransactionTemplate {
    inputs: &[(1, 0, 0, Witness::new())],
    op_return: Some(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1111),
            term: Some(2),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      }
      .encipher(),
    ),
    ..Default::default()
  });

  bitcoin_rpc_server.mine_blocks(1);

  let output = CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .bitcoin_rpc_server(&bitcoin_rpc_server)
  .ord_rpc_server(&ord_rpc_server)
  .run_and_deserialize_output::<mint::Output>();

  bitcoin_rpc_server.mine_blocks(1);

  let balances = CommandBuilder::new("--regtest --index-runes balances")
    .bitcoin_rpc_server(&bitcoin_rpc_server)
    .ord_rpc_server(&ord_rpc_server)
    .run_and_deserialize_output::<ord::subcommand::balances::Output>();

  assert_eq!(
    balances,
    ord::subcommand::balances::Output {
      runes: vec![(
        Rune(RUNE),
        vec![(
          OutPoint {
            txid: output.txid,
            vout: 1
          },
          1111
        )]
        .into_iter()
        .collect()
      ),]
      .into_iter()
      .collect(),
    }
  );

  bitcoin_rpc_server.mine_blocks(1);

  CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .bitcoin_rpc_server(&bitcoin_rpc_server)
  .ord_rpc_server(&ord_rpc_server)
  .expected_exit_code(1)
  .expected_stderr("error: Mint block height end of 4 for rune AAAAAAAAAAAAA has passed\n")
  .run_and_extract_stdout();
}
