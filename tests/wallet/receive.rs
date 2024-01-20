use {super::*, ord::subcommand::wallet::receive};

#[test]
fn receive() {
  let rpc_server = test_bitcoincore_rpc::spawn();
  create_wallet(&rpc_server);

  let output = CommandBuilder::new("wallet receive")
    .bitcoin_rpc_server(&rpc_server)
    .run_and_deserialize_output::<receive::Output>();

  assert!(output.address.is_valid_for_network(Network::Bitcoin));
}
