use {
  super::*,
  bitcoin::{BlockHash, ScriptBuf},
  ord::subcommand::wallet::send::Output,
  ord::{Envelope, Inscription},
};

#[test]
fn get_sat_without_sat_index() {
  let core = mockcore::spawn();

  let response =
    TestServer::spawn_with_server_args(&core, &[], &[]).json_request("/sat/2099999997689999");

  assert_eq!(response.status(), StatusCode::OK);

  let mut sat_json: api::Sat = serde_json::from_str(&response.text().unwrap()).unwrap();

  // this is a hack to ignore the timestamp, since it changes for every request
  sat_json.timestamp = 0;

  pretty_assert_eq!(
    sat_json,
    api::Sat {
      address: None,
      number: 2099999997689999,
      decimal: "6929999.0".into(),
      degree: "5°209999′1007″0‴".into(),
      name: "a".into(),
      block: 6929999,
      cycle: 5,
      epoch: 32,
      period: 3437,
      offset: 0,
      rarity: Rarity::Uncommon,
      percentile: "100%".into(),
      satpoint: None,
      timestamp: 0,
      inscriptions: Vec::new(),
      charms: vec![Charm::Uncommon],
    }
  )
}

#[test]
fn get_sat_with_inscription_and_sat_index() {
  let core = mockcore::spawn();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-sats"], &[]);

  create_wallet(&core, &ord);

  let (inscription_id, reveal) = inscribe(&core, &ord);

  let response = ord.json_request(format!("/sat/{}", 50 * COIN_VALUE));

  assert_eq!(response.status(), StatusCode::OK);

  let mut sat_json: api::Sat = serde_json::from_str(&response.text().unwrap()).unwrap();

  assert_regex_match!(sat_json.address.unwrap(), r"bc1p.*");
  sat_json.address = None;

  pretty_assert_eq!(
    sat_json,
    api::Sat {
      address: None,
      number: 50 * COIN_VALUE,
      decimal: "1.0".into(),
      degree: "0°1′1″0‴".into(),
      name: "nvtcsezkbth".into(),
      block: 1,
      cycle: 0,
      epoch: 0,
      period: 0,
      offset: 0,
      rarity: Rarity::Uncommon,
      percentile: "0.00023809523835714296%".into(),
      satpoint: Some(SatPoint::from_str(&format!("{}:{}:{}", reveal, 0, 0)).unwrap()),
      timestamp: 1,
      inscriptions: vec![inscription_id],
      charms: vec![Charm::Coin, Charm::Uncommon],
    }
  )
}

#[test]
fn get_sat_with_inscription_on_common_sat_and_more_inscriptions() {
  let core = mockcore::spawn();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-sats"], &[]);

  create_wallet(&core, &ord);

  inscribe(&core, &ord);

  let txid = core.mine_blocks(1)[0].txdata[0].compute_txid();

  let Batch { reveal, .. } = CommandBuilder::new(format!(
    "wallet inscribe --satpoint {}:0:1 --fee-rate 1 --file foo.txt",
    txid
  ))
  .write("foo.txt", "FOO")
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output();

  core.mine_blocks(1);

  let inscription_id = InscriptionId {
    txid: reveal,
    index: 0,
  };

  let response = ord.json_request(format!("/sat/{}", 3 * 50 * COIN_VALUE + 1));

  assert_eq!(response.status(), StatusCode::OK);

  let mut sat_json: api::Sat = serde_json::from_str(&response.text().unwrap()).unwrap();

  assert_regex_match!(sat_json.address.unwrap(), r"bc1p.*");
  sat_json.address = None;

  pretty_assert_eq!(
    sat_json,
    api::Sat {
      address: None,
      number: 3 * 50 * COIN_VALUE + 1,
      decimal: "3.1".into(),
      degree: "0°3′3″1‴".into(),
      name: "nvtblvikkiq".into(),
      block: 3,
      cycle: 0,
      epoch: 0,
      period: 0,
      offset: 1,
      rarity: Rarity::Common,
      percentile: "0.000714285715119048%".into(),
      satpoint: Some(SatPoint::from_str(&format!("{}:{}:{}", reveal, 0, 0)).unwrap()),
      timestamp: 3,
      inscriptions: vec![inscription_id],
      charms: Vec::new(),
    }
  )
}

#[test]
fn get_inscription() {
  let core = mockcore::spawn();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-sats"], &[]);

  create_wallet(&core, &ord);

  let (inscription_id, reveal) = inscribe(&core, &ord);

  let response = ord.json_request(format!("/inscription/{}", inscription_id));

  assert_eq!(response.status(), StatusCode::OK);

  let mut inscription_json: api::Inscription =
    serde_json::from_str(&response.text().unwrap()).unwrap();
  assert_regex_match!(inscription_json.address.unwrap(), r"bc1p.*");
  inscription_json.address = None;

  pretty_assert_eq!(
    inscription_json,
    api::Inscription {
      address: None,
      charms: vec![Charm::Coin, Charm::Uncommon],
      child_count: 0,
      children: Vec::new(),
      content_length: Some(3),
      content_type: Some("text/plain;charset=utf-8".to_string()),
      effective_content_type: Some("text/plain;charset=utf-8".to_string()),
      fee: 138,
      height: 2,
      id: inscription_id,
      number: 0,
      next: None,
      value: Some(10000),
      parents: Vec::new(),
      previous: None,
      rune: None,
      sat: Some(Sat(50 * COIN_VALUE)),
      satpoint: SatPoint::from_str(&format!("{}:{}:{}", reveal, 0, 0)).unwrap(),
      timestamp: 2,
      metaprotocol: None
    }
  )
}

#[test]
fn get_inscription_with_metaprotocol() {
  let core = mockcore::spawn();
  let ord = TestServer::spawn_with_server_args(&core, &["--index-sats"], &[]);

  create_wallet(&core, &ord);

  core.mine_blocks(1);

  let output = CommandBuilder::new(format!(
    "--chain {} wallet inscribe --fee-rate 1 --file foo.txt --metaprotocol foo",
    core.network()
  ))
  .write("foo.txt", "FOO")
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output::<Batch>();

  core.mine_blocks(1);

  let response = ord.json_request(format!("/inscription/{}", output.inscriptions[0].id));

  assert_eq!(response.status(), StatusCode::OK);

  let mut inscription_json: api::Inscription =
    serde_json::from_str(&response.text().unwrap()).unwrap();
  assert_regex_match!(inscription_json.address.unwrap(), r"bc1p.*");
  inscription_json.address = None;

  pretty_assert_eq!(
    inscription_json,
    api::Inscription {
      address: None,
      charms: vec![Charm::Coin, Charm::Uncommon],
      child_count: 0,
      children: Vec::new(),
      content_length: Some(3),
      content_type: Some("text/plain;charset=utf-8".to_string()),
      effective_content_type: Some("text/plain;charset=utf-8".to_string()),
      fee: 140,
      height: 2,
      id: output.inscriptions[0].id,
      number: 0,
      next: None,
      value: Some(10000),
      parents: Vec::new(),
      previous: None,
      rune: None,
      sat: Some(Sat(50 * COIN_VALUE)),
      satpoint: SatPoint::from_str(&format!("{}:{}:{}", output.reveal, 0, 0)).unwrap(),
      timestamp: 2,
      metaprotocol: Some("foo".to_string())
    }
  );
}

#[test]
fn get_inscriptions() {
  let core = mockcore::spawn();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-sats"], &[]);

  create_wallet(&core, &ord);

  let witness = envelope(&[b"ord", &[1], b"text/plain;charset=utf-8", &[], b"bar"]);

  let mut inscriptions = Vec::new();

  // Create 150 inscriptions
  for i in 0..50 {
    core.mine_blocks(1);
    core.mine_blocks(1);
    core.mine_blocks(1);

    let txid = core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (i * 3 + 1, 0, 0, witness.clone()),
        (i * 3 + 2, 0, 0, witness.clone()),
        (i * 3 + 3, 0, 0, witness.clone()),
      ],
      ..default()
    });

    inscriptions.push(InscriptionId { txid, index: 0 });
    inscriptions.push(InscriptionId { txid, index: 1 });
    inscriptions.push(InscriptionId { txid, index: 2 });
  }

  core.mine_blocks(1);

  let response = ord.json_request("/inscriptions");
  assert_eq!(response.status(), StatusCode::OK);
  let inscriptions_json: api::Inscriptions =
    serde_json::from_str(&response.text().unwrap()).unwrap();

  assert_eq!(inscriptions_json.ids.len(), 100);
  assert!(inscriptions_json.more);
  assert_eq!(inscriptions_json.page_index, 0);

  let response = ord.json_request("/inscriptions/1");
  assert_eq!(response.status(), StatusCode::OK);
  let inscriptions_json: api::Inscriptions =
    serde_json::from_str(&response.text().unwrap()).unwrap();

  assert_eq!(inscriptions_json.ids.len(), 50);
  assert!(!inscriptions_json.more);
  assert_eq!(inscriptions_json.page_index, 1);
}

#[test]
fn get_inscriptions_in_block() {
  let core = mockcore::spawn();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-sats"], &[]);

  create_wallet(&core, &ord);

  core.mine_blocks(10);

  let envelope = envelope(&[b"ord", &[1], b"text/plain;charset=utf-8", &[], b"bar"]);

  let txid = core.broadcast_tx(TransactionTemplate {
    inputs: &[
      (1, 0, 0, envelope.clone()),
      (2, 0, 0, envelope.clone()),
      (3, 0, 0, envelope.clone()),
    ],
    ..default()
  });

  core.mine_blocks(1);

  let _ = core.broadcast_tx(TransactionTemplate {
    inputs: &[(4, 0, 0, envelope.clone()), (5, 0, 0, envelope.clone())],
    ..default()
  });

  core.mine_blocks(1);

  let _ = core.broadcast_tx(TransactionTemplate {
    inputs: &[(6, 0, 0, envelope.clone())],
    ..default()
  });

  core.mine_blocks(1);

  // get all inscriptions from block 11
  let response = ord.json_request(format!("/inscriptions/block/{}", 11));
  assert_eq!(response.status(), StatusCode::OK);

  let inscriptions_json: api::Inscriptions =
    serde_json::from_str(&response.text().unwrap()).unwrap();

  pretty_assert_eq!(
    inscriptions_json.ids,
    vec![
      InscriptionId { txid, index: 0 },
      InscriptionId { txid, index: 1 },
      InscriptionId { txid, index: 2 },
    ]
  );
}

#[test]
fn get_output() {
  let core = mockcore::spawn();
  let ord = TestServer::spawn(&core);

  create_wallet(&core, &ord);
  core.mine_blocks(3);

  let envelope = envelope(&[b"ord", &[1], b"text/plain;charset=utf-8", &[], b"bar"]);

  let txid = core.broadcast_tx(TransactionTemplate {
    inputs: &[
      (1, 0, 0, envelope.clone()),
      (2, 0, 0, envelope.clone()),
      (3, 0, 0, envelope.clone()),
    ],
    ..default()
  });

  core.mine_blocks(1);

  let server = TestServer::spawn_with_server_args(&core, &["--index-sats"], &["--no-sync"]);

  let response = reqwest::blocking::Client::new()
    .get(server.url().join(&format!("/output/{}:0", txid)).unwrap())
    .header(reqwest::header::ACCEPT, "application/json")
    .send()
    .unwrap();

  assert_eq!(response.status(), StatusCode::OK);

  assert!(
    !serde_json::from_str::<api::Output>(&response.text().unwrap())
      .unwrap()
      .indexed
  );

  let server = TestServer::spawn_with_server_args(&core, &["--index-sats"], &[]);

  let response = server.json_request(format!("/output/{}:0", txid));
  assert_eq!(response.status(), StatusCode::OK);

  let output_json: api::Output = serde_json::from_str(&response.text().unwrap()).unwrap();

  pretty_assert_eq!(
    output_json,
    api::Output {
      address: Some(
        "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs"
          .parse()
          .unwrap()
      ),
      outpoint: OutPoint { txid, vout: 0 },
      inscriptions: Some(vec![
        InscriptionId { txid, index: 0 },
        InscriptionId { txid, index: 1 },
        InscriptionId { txid, index: 2 },
      ]),
      indexed: true,
      runes: None,
      sat_ranges: Some(vec![
        (5000000000, 10000000000,),
        (10000000000, 15000000000,),
        (15000000000, 20000000000,),
      ],),
      script_pubkey: ScriptBuf::from(
        "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9e75rs"
          .parse::<Address<NetworkUnchecked>>()
          .unwrap()
          .assume_checked()
      ),
      spent: false,
      transaction: txid,
      value: 3 * 50 * COIN_VALUE,
    }
  );
}

#[test]
fn json_request_fails_when_disabled() {
  let core = mockcore::spawn();

  let response = TestServer::spawn_with_server_args(&core, &[], &["--disable-json-api"])
    .json_request("/sat/2099999997689999");

  assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);
}

#[test]
fn get_block() {
  let core = mockcore::spawn();

  core.mine_blocks(1);

  let response = TestServer::spawn_with_server_args(&core, &[], &[]).json_request("/block/0");

  assert_eq!(response.status(), StatusCode::OK);

  let block_json: api::Block = serde_json::from_str(&response.text().unwrap()).unwrap();

  assert_eq!(
    block_json,
    api::Block {
      hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        .parse::<BlockHash>()
        .unwrap(),
      target: "00000000ffff0000000000000000000000000000000000000000000000000000"
        .parse::<BlockHash>()
        .unwrap(),
      best_height: 1,
      height: 0,
      inscriptions: Vec::new(),
      runes: Vec::new(),
      transactions: block_json.transactions.clone(),
    }
  );
}

#[test]
fn get_blocks() {
  let core = mockcore::spawn();
  let ord = TestServer::spawn(&core);

  let blocks: Vec<BlockHash> = core
    .mine_blocks(101)
    .iter()
    .rev()
    .take(100)
    .map(|block| block.block_hash())
    .collect();

  ord.sync_server();

  let response = ord.json_request("/blocks");

  assert_eq!(response.status(), StatusCode::OK);

  let blocks_json: api::Blocks = serde_json::from_str(&response.text().unwrap()).unwrap();

  pretty_assert_eq!(
    blocks_json,
    api::Blocks {
      last: 101,
      blocks: blocks.clone(),
      featured_blocks: blocks
        .into_iter()
        .take(5)
        .map(|block_hash| (block_hash, Vec::new()))
        .collect(),
    }
  );
}

#[test]
fn get_transaction() {
  let core = mockcore::spawn();

  let ord = TestServer::spawn(&core);

  let transaction = core.mine_blocks(1)[0].txdata[0].clone();

  let txid = transaction.compute_txid();

  let response = ord.json_request(format!("/tx/{txid}"));

  assert_eq!(response.status(), StatusCode::OK);

  assert_eq!(
    serde_json::from_str::<api::Transaction>(&response.text().unwrap()).unwrap(),
    api::Transaction {
      chain: Chain::Mainnet,
      runestone: None,
      etching: None,
      inscription_count: 0,
      transaction,
      txid,
    }
  );
}

#[test]
fn get_status() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord =
    TestServer::spawn_with_server_args(&core, &["--regtest", "--index-sats", "--index-runes"], &[]);

  create_wallet(&core, &ord);
  core.mine_blocks(1);

  inscribe(&core, &ord);

  let response = ord.json_request("/status");

  assert_eq!(response.status(), StatusCode::OK);

  let mut status_json: api::Status = serde_json::from_str(&response.text().unwrap()).unwrap();

  let dummy_started = "2012-12-12 12:12:12+00:00"
    .parse::<DateTime<Utc>>()
    .unwrap();

  let dummy_duration = Duration::from_secs(1);

  status_json.initial_sync_time = dummy_duration;
  status_json.started = dummy_started;
  status_json.uptime = dummy_duration;

  pretty_assert_eq!(
    status_json,
    api::Status {
      address_index: false,
      blessed_inscriptions: 1,
      chain: Chain::Regtest,
      cursed_inscriptions: 0,
      height: Some(3),
      initial_sync_time: dummy_duration,
      inscription_index: true,
      inscriptions: 1,
      json_api: true,
      lost_sats: 0,
      minimum_rune_for_next_block: Rune(99218849511960410),
      rune_index: true,
      runes: 0,
      sat_index: true,
      started: dummy_started,
      transaction_index: false,
      unrecoverably_reorged: false,
      uptime: dummy_duration,
    }
  );
}

#[test]
fn get_runes() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-runes", "--regtest"], &[]);

  create_wallet(&core, &ord);

  core.mine_blocks(3);

  let a = etch(&core, &ord, Rune(RUNE));
  let b = etch(&core, &ord, Rune(RUNE + 1));
  let c = etch(&core, &ord, Rune(RUNE + 2));

  core.mine_blocks(1);

  let response = ord.json_request(format!("/rune/{}", a.output.rune.unwrap().rune));
  assert_eq!(response.status(), StatusCode::OK);

  let rune_json: api::Rune = serde_json::from_str(&response.text().unwrap()).unwrap();

  pretty_assert_eq!(
    rune_json,
    api::Rune {
      entry: RuneEntry {
        block: a.id.block,
        burned: 0,
        terms: None,
        divisibility: 0,
        etching: a.output.reveal,
        mints: 0,
        number: 0,
        premine: 1000,
        spaced_rune: SpacedRune {
          rune: Rune(RUNE),
          spacers: 0
        },
        symbol: Some('¢'),
        timestamp: 10,
        turbo: false,
      },
      id: RuneId { block: 10, tx: 1 },
      mintable: false,
      parent: Some(InscriptionId {
        txid: a.output.reveal,
        index: 0,
      }),
    }
  );

  let response = ord.json_request("/runes");

  assert_eq!(response.status(), StatusCode::OK);

  let runes_json: api::Runes = serde_json::from_str(&response.text().unwrap()).unwrap();

  pretty_assert_eq!(
    runes_json,
    api::Runes {
      entries: vec![
        (
          RuneId { block: 24, tx: 1 },
          RuneEntry {
            block: c.id.block,
            burned: 0,
            terms: None,
            divisibility: 0,
            etching: c.output.reveal,
            mints: 0,
            number: 2,
            premine: 1000,
            spaced_rune: SpacedRune {
              rune: Rune(RUNE + 2),
              spacers: 0
            },
            symbol: Some('¢'),
            timestamp: 24,
            turbo: false,
          }
        ),
        (
          RuneId { block: 17, tx: 1 },
          RuneEntry {
            block: b.id.block,
            burned: 0,
            terms: None,
            divisibility: 0,
            etching: b.output.reveal,
            mints: 0,
            number: 1,
            premine: 1000,
            spaced_rune: SpacedRune {
              rune: Rune(RUNE + 1),
              spacers: 0
            },
            symbol: Some('¢'),
            timestamp: 17,
            turbo: false,
          }
        ),
        (
          RuneId { block: 10, tx: 1 },
          RuneEntry {
            block: a.id.block,
            burned: 0,
            terms: None,
            divisibility: 0,
            etching: a.output.reveal,
            mints: 0,
            number: 0,
            premine: 1000,
            spaced_rune: SpacedRune {
              rune: Rune(RUNE),
              spacers: 0
            },
            symbol: Some('¢'),
            timestamp: 10,
            turbo: false,
          }
        )
      ],
      more: false,
      next: None,
      prev: None,
    }
  );
}

#[test]
fn get_decode_tx() {
  let core = mockcore::builder().network(Network::Regtest).build();

  let ord = TestServer::spawn_with_server_args(&core, &["--index-runes", "--regtest"], &[]);

  create_wallet(&core, &ord);
  core.mine_blocks(3);

  let envelope = envelope(&[b"ord", &[1], b"text/plain;charset=utf-8", &[], b"bar"]);

  let txid = core.broadcast_tx(TransactionTemplate {
    inputs: &[(1, 0, 0, envelope.clone())],
    ..default()
  });

  let transaction = core.mine_blocks(1)[0].txdata[0].clone();

  let inscriptions = vec![Envelope {
    payload: Inscription {
      body: Some(vec![98, 97, 114]),
      content_type: Some(b"text/plain;charset=utf-8".into()),
      ..default()
    },
    input: 0,
    offset: 0,
    pushnum: false,
    stutter: false,
  }];
  let runestone = Runestone::decipher(&transaction);
  let response = ord.json_request(format!("/decode/{txid}"));

  assert_eq!(response.status(), StatusCode::OK);

  assert_eq!(
    serde_json::from_str::<api::Decode>(&response.text().unwrap()).unwrap(),
    api::Decode {
      inscriptions,
      runestone,
    }
  );
}

#[test]
fn outputs_address() {
  let core = mockcore::builder().network(Network::Regtest).build();
  let ord =
    TestServer::spawn_with_args(&core, &["--index-runes", "--index-addresses", "--regtest"]);

  create_wallet(&core, &ord);

  let address = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";

  let (inscription_id, reveal) = inscribe(&core, &ord);

  let inscription_send = CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet send --fee-rate 1 {address} {inscription_id}",
  ))
  .core(&core)
  .ord(&ord)
  .stdout_regex(".*")
  .run_and_deserialize_output::<Output>();

  core.mine_blocks(1);

  etch(&core, &ord, Rune(RUNE));

  let rune_send = CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet send --fee-rate 1 {address} 1000:{}",
    Rune(RUNE)
  ))
  .core(&core)
  .ord(&ord)
  .stdout_regex(".*")
  .run_and_deserialize_output::<Output>();

  let cardinal_send = CommandBuilder::new(format!(
    "--chain regtest --index-runes wallet send --fee-rate 13.3 {address} 2btc"
  ))
  .core(&core)
  .ord(&ord)
  .run_and_deserialize_output::<Send>();

  core.mine_blocks(6);

  let cardinals_response = ord.json_request(format!("/outputs/{}?type=cardinal", address));

  assert_eq!(cardinals_response.status(), StatusCode::OK);

  let cardinals_json: Vec<api::Output> =
    serde_json::from_str(&cardinals_response.text().unwrap()).unwrap();

  pretty_assert_eq!(
    cardinals_json,
    vec![api::Output {
      address: Some(address.parse().unwrap()),
      inscriptions: Some(vec![]),
      outpoint: OutPoint {
        txid: cardinal_send.txid,
        vout: 0
      },
      indexed: true,
      runes: Some(BTreeMap::new()),
      sat_ranges: None,
      script_pubkey: ScriptBuf::from(
        address
          .parse::<Address<NetworkUnchecked>>()
          .unwrap()
          .assume_checked()
      ),
      spent: false,
      transaction: cardinal_send.txid,
      value: 2 * COIN_VALUE,
    }]
  );

  let runes_response = ord.json_request(format!("/outputs/{}?type=runic", address));

  assert_eq!(runes_response.status(), StatusCode::OK);

  let runes_json: Vec<api::Output> = serde_json::from_str(&runes_response.text().unwrap()).unwrap();

  let mut expected_runes = BTreeMap::new();

  expected_runes.insert(
    SpacedRune {
      rune: Rune(RUNE),
      spacers: 0,
    },
    Pile {
      amount: 1000,
      divisibility: 0,
      symbol: Some('¢'),
    },
  );

  pretty_assert_eq!(
    runes_json,
    vec![api::Output {
      address: Some(address.parse().unwrap()),
      inscriptions: Some(vec![]),
      outpoint: OutPoint {
        txid: rune_send.txid,
        vout: 0
      },
      indexed: true,
      runes: Some(expected_runes),
      sat_ranges: None,
      script_pubkey: ScriptBuf::from(
        address
          .parse::<Address<NetworkUnchecked>>()
          .unwrap()
          .assume_checked()
      ),
      spent: false,
      transaction: rune_send.txid,
      value: 9901,
    }]
  );

  let inscriptions_response = ord.json_request(format!("/outputs/{}?type=inscribed", address));

  assert_eq!(inscriptions_response.status(), StatusCode::OK);

  let inscriptions_json: Vec<api::Output> =
    serde_json::from_str(&inscriptions_response.text().unwrap()).unwrap();

  pretty_assert_eq!(
    inscriptions_json,
    vec![api::Output {
      address: Some(address.parse().unwrap()),
      inscriptions: Some(vec![InscriptionId {
        txid: reveal,
        index: 0
      },]),
      outpoint: OutPoint {
        txid: inscription_send.txid,
        vout: 0
      },
      indexed: true,
      runes: Some(BTreeMap::new()),
      sat_ranges: None,
      script_pubkey: ScriptBuf::from(
        address
          .parse::<Address<NetworkUnchecked>>()
          .unwrap()
          .assume_checked()
      ),
      spent: false,
      transaction: inscription_send.txid,
      value: 9901,
    }]
  );

  let any: Vec<api::Output> = serde_json::from_str(
    &ord
      .json_request(format!("/outputs/{}?type=any", address))
      .text()
      .unwrap(),
  )
  .unwrap();

  let default: Vec<api::Output> = serde_json::from_str(
    &ord
      .json_request(format!("/outputs/{}", address))
      .text()
      .unwrap(),
  )
  .unwrap();

  assert_eq!(any.len(), 3);
  assert!(any
    .iter()
    .any(|output| output.runes.clone().unwrap_or_default().len() == 1));
  assert!(any
    .iter()
    .any(|output| output.inscriptions.clone().unwrap_or_default().len() == 1));
  assert!(any.iter().any(
    |output| output.inscriptions.clone().unwrap_or_default().is_empty()
      && output.runes.clone().unwrap_or_default().is_empty()
  ));
  assert_eq!(any, default);
}

#[test]
fn outputs_address_returns_400_for_missing_indices() {
  let core = mockcore::builder().network(Network::Regtest).build();
  let ord = TestServer::spawn_with_args(
    &core,
    &[
      "--no-index-inscriptions",
      "--index-runes",
      "--index-addresses",
      "--regtest",
    ],
  );

  let address = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";

  let inscriptions_response = ord.json_request(format!("/outputs/{}?type=inscribed", address));
  assert_eq!(inscriptions_response.status(), StatusCode::BAD_REQUEST);

  let runes_response = ord.json_request(format!("/outputs/{}?type=runic", address));
  assert_eq!(runes_response.status(), StatusCode::BAD_REQUEST);

  let cardinal_response = ord.json_request(format!("/outputs/{}?type=runic", address));
  assert_eq!(cardinal_response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn outputs_address_returns_400_for_missing_rune_index() {
  let core = mockcore::builder().network(Network::Regtest).build();
  let ord = TestServer::spawn_with_args(&core, &["--index-addresses", "--regtest"]);

  let address = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";

  let inscriptions_response = ord.json_request(format!("/outputs/{}?type=inscribed", address));
  assert_eq!(inscriptions_response.status(), StatusCode::BAD_REQUEST);

  let runes_response = ord.json_request(format!("/outputs/{}?type=runic", address));
  assert_eq!(runes_response.status(), StatusCode::BAD_REQUEST);

  let cardinal_response = ord.json_request(format!("/outputs/{}?type=runic", address));
  assert_eq!(cardinal_response.status(), StatusCode::BAD_REQUEST);
}
