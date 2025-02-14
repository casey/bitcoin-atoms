use {super::*, ord::subcommand::wallet::offer::view::Role};

type View = ord::subcommand::wallet::offer::view::Output;
type Create = ord::subcommand::wallet::offer::create::Output;

#[test]
fn view_offer() {
  let core = mockcore::spawn();

  let ord = TestServer::spawn_with_server_args(&core, &[], &[]);

  create_wallet(&core, &ord);

  let (inscription, _) = inscribe_with_options(&core, &ord, Some(9000), 0);

  let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    .parse::<Address<NetworkUnchecked>>()
    .unwrap()
    .require_network(Network::Bitcoin)
    .unwrap();

  CommandBuilder::new(format!("wallet send --fee-rate 0 {address} {inscription}"))
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<Send>();

  core.mine_blocks(1);

  let create = CommandBuilder::new(format!(
    "wallet offer create --inscription {inscription} --amount 1btc --fee-rate 1"
  ))
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output::<Create>();

  let view = CommandBuilder::new(format!("wallet offer view --psbt {}", create.psbt,))
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<View>();

  assert_eq!(view.psbt, create.psbt);

  assert_eq!(view.role, Role::Buyer);

  assert_eq!(view.seller_address, address.as_unchecked().clone());

  assert_eq!(view.inscription, inscription);

  assert_eq!(view.balance_change, -(COIN_VALUE as i64 + 226_i64));
}
