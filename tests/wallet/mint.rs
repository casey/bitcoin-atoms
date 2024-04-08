use {super::*, ord::subcommand::wallet::mint};

#[test]
fn minting_rune_and_fails_if_after_end() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-runes", "--regtest"], &[]);

  core.mine_blocks(1);

  create_wallet(&core, &ord);

  batch(
    &core,
    &ord,
    batch::File {
      etching: Some(batch::Etching {
        divisibility: 1,
        rune: SpacedRune {
          rune: Rune(RUNE),
          spacers: 0,
        },
        premine: "0".parse().unwrap(),
        symbol: '¢',
        supply: "111.1".parse().unwrap(),
        terms: Some(batch::Terms {
          cap: 1,
          offset: Some(batch::Range {
            end: Some(2),
            start: None,
          }),
          amount: "111.1".parse().unwrap(),
          height: None,
        }),
      }),
      inscriptions: vec![batch::Entry {
        file: "inscription.jpeg".into(),
        ..default()
      }],
      ..default()
    },
  );

  let output = CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output::<mint::Output>();

  core.mine_blocks(1);

  let balances = CommandBuilder::new("--regtest --index-runes balances")
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<ord::subcommand::balances::Output>();

  pretty_assert_eq!(
    output.pile,
    Pile {
      amount: 1111,
      divisibility: 1,
      symbol: Some('¢'),
    }
  );

  pretty_assert_eq!(
    balances,
    ord::subcommand::balances::Output {
      runes: vec![(
        output.rune,
        vec![(
          OutPoint {
            txid: output.mint,
            vout: 1
          },
          output.pile,
        )]
        .into_iter()
        .collect()
      ),]
      .into_iter()
      .collect(),
    }
  );

  core.mine_blocks(1);

  CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .expected_exit_code(1)
  .expected_stderr("error: rune AAAAAAAAAAAAA mint ended on block 11\n")
  .run_and_extract_stdout();
}

#[test]
fn minting_rune_fails_if_not_mintable() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-runes", "--regtest"], &[]);

  create_wallet(&core, &ord);

  batch(
    &core,
    &ord,
    batch::File {
      etching: Some(batch::Etching {
        divisibility: 1,
        rune: SpacedRune {
          rune: Rune(RUNE),
          spacers: 0,
        },
        supply: "1000".parse().unwrap(),
        premine: "1000".parse().unwrap(),
        symbol: '¢',
        terms: None,
      }),
      inscriptions: vec![batch::Entry {
        file: "inscription.jpeg".into(),
        ..default()
      }],
      ..default()
    },
  );

  CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .expected_exit_code(1)
  .expected_stderr("error: rune AAAAAAAAAAAAA not mintable\n")
  .run_and_extract_stdout();
}

#[test]
fn minting_rune_with_no_rune_index_fails() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord = TestServer::spawn_with_server_args(&core, &["--regtest"], &[]);

  core.mine_blocks(1);

  create_wallet(&core, &ord);

  CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .expected_exit_code(1)
  .expected_stderr("error: `ord wallet etch` requires index created with `--index-runes` flag\n")
  .run_and_extract_stdout();
}

#[test]
fn minting_rune_and_then_sending_works() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-runes", "--regtest"], &[]);

  core.mine_blocks(1);

  create_wallet(&core, &ord);

  batch(
    &core,
    &ord,
    batch::File {
      etching: Some(batch::Etching {
        divisibility: 0,
        rune: SpacedRune {
          rune: Rune(RUNE),
          spacers: 0,
        },
        premine: "111".parse().unwrap(),
        supply: "132".parse().unwrap(),
        symbol: '¢',
        terms: Some(batch::Terms {
          cap: 1,
          offset: Some(batch::Range {
            end: Some(10),
            start: None,
          }),
          amount: "21".parse().unwrap(),
          height: None,
        }),
      }),
      inscriptions: vec![batch::Entry {
        file: "inscription.jpeg".into(),
        ..default()
      }],
      ..default()
    },
  );

  let balance = CommandBuilder::new("--chain regtest --index-runes wallet balance")
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<ord::subcommand::wallet::balance::Output>();

  assert_eq!(
    *balance.runes.unwrap().first_key_value().unwrap().1,
    111_u128
  );

  assert_eq!(balance.runic.unwrap(), 10000_u64);

  let output = CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {}",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output::<mint::Output>();

  core.mine_blocks(1);

  let balance = CommandBuilder::new("--chain regtest --index-runes wallet balance")
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<ord::subcommand::wallet::balance::Output>();

  assert_eq!(
    *balance.runes.unwrap().first_key_value().unwrap().1,
    132_u128
  );

  assert_eq!(balance.runic.unwrap(), 20000_u64);

  pretty_assert_eq!(
    output.pile,
    Pile {
      amount: 21,
      divisibility: 0,
      symbol: Some('¢'),
    }
  );

  CommandBuilder::new(format!(
    "--regtest --index-runes wallet send bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw 5:{} --fee-rate 1",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output::<ord::subcommand::wallet::send::Output>();
}

#[test]
fn minting_rune_with_postage() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-runes", "--regtest"], &[]);

  core.mine_blocks(1);

  create_wallet(&core, &ord);

  batch(
    &core,
    &ord,
    batch::File {
      etching: Some(batch::Etching {
        divisibility: 0,
        rune: SpacedRune {
          rune: Rune(RUNE),
          spacers: 0,
        },
        premine: "0".parse().unwrap(),
        supply: "21".parse().unwrap(),
        symbol: '¢',
        terms: Some(batch::Terms {
          cap: 1,
          offset: Some(batch::Range {
            end: Some(10),
            start: None,
          }),
          amount: "21".parse().unwrap(),
          height: None,
        }),
      }),
      inscriptions: vec![batch::Entry {
        file: "inscription.jpeg".into(),
        ..default()
      }],
      ..default()
    },
  );

  let output = CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet mint --fee-rate 1 --rune {} --postage 1000sat",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output::<mint::Output>();

  pretty_assert_eq!(
    output.pile,
    Pile {
      amount: 21,
      divisibility: 0,
      symbol: Some('¢'),
    }
  );

  core.mine_blocks(1);

  let balance = CommandBuilder::new("--chain regtest --index-runes wallet balance")
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<ord::subcommand::wallet::balance::Output>();

  assert_eq!(balance.runic.unwrap(), 1000_u64);
}
