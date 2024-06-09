use bitcoin::hashes::Hash;

use super::*;

#[test]
fn airdrop() {
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
        premine: "100".parse().unwrap(),
        symbol: '¢',
        supply: "100".parse().unwrap(),
        turbo: false,
        ..default()
      }),
      inscriptions: vec![batch::Entry {
        file: Some("inscription.jpeg".into()),
        ..default()
      }],
      ..default()
    },
  );

  pretty_assert_eq!(
    CommandBuilder::new("--regtest wallet balance")
      .core(&core)
      .ord(&ord)
      .run_and_deserialize_output::<Balance>(),
    Balance {
      cardinal: 39999980000,
      ordinal: 10000,
      runic: Some(10000),
      runes: Some(
        vec![(
          SpacedRune {
            rune: Rune(RUNE),
            spacers: 0
          },
          "100".parse().unwrap()
        )]
        .into_iter()
        .collect()
      ),
      total: 400 * COIN_VALUE,
    }
  );

  let output =  CommandBuilder::new(format!(
      "--regtest wallet airdrop --rune {} --fee-rate 1 --destinations whitelist.tsv",
      Rune(RUNE)
    ))
    .write("whitelist.tsv", "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw\nbcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw\nbcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<Airdrop>();

  pretty_assert_eq!(
    output.rune,
    SpacedRune {
      rune: Rune(RUNE),
      spacers: 0,
    },
  );

  core.mine_blocks(1);

  let balances = CommandBuilder::new("--regtest --index-runes balances")
    .core(&core)
    .ord(&ord)
    .run_and_deserialize_output::<ord::subcommand::balances::Output>();

  pretty_assert_eq!(
    balances,
    ord::subcommand::balances::Output {
      runes: vec![(
        SpacedRune::new(Rune(RUNE), 0),
        vec![
          (
            OutPoint {
              txid: output.txid,
              vout: 1
            },
            Pile {
              amount: 250,
              divisibility: 1,
              symbol: Some('¢')
            }
          ),
          (
            OutPoint {
              txid: output.txid,
              vout: 2
            },
            Pile {
              amount: 250,
              divisibility: 1,
              symbol: Some('¢')
            }
          ),
          (
            OutPoint {
              txid: output.txid,
              vout: 3
            },
            Pile {
              amount: 250,
              divisibility: 1,
              symbol: Some('¢')
            }
          ),
          (
            OutPoint {
              txid: output.txid,
              vout: 4
            },
            Pile {
              amount: 250,
              divisibility: 1,
              symbol: Some('¢')
            }
          )
        ]
        .into_iter()
        .collect()
      ),]
      .into_iter()
      .collect(),
    }
  );
}
