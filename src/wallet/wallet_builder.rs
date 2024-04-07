use super::*;

#[derive(Clone)]
pub(crate) struct WalletBuilder {
  ord_client: reqwest::blocking::Client,
  name: String,
  no_sync: bool,
  rpc_url: Url,
  settings: Settings,
}

impl WalletBuilder {
  pub(crate) fn new(name: String, no_sync: bool, settings: Settings, rpc_url: Url) -> Result<Self> {
    let mut headers = HeaderMap::new();
    headers.insert(
      header::ACCEPT,
      header::HeaderValue::from_static("application/json"),
    );

    if let Some((username, password)) = settings.credentials() {
      let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
      headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
      );
    }

    Ok(Self {
      ord_client: reqwest::blocking::ClientBuilder::new()
        .default_headers(headers.clone())
        .build()?,
      name,
      no_sync,
      rpc_url,
      settings,
    })
  }
  pub(crate) fn build(self) -> Result<Wallet> {
    let database = Wallet::open_database(&self.name, &self.settings)?;

    let bitcoin_client = {
      let client =
        Wallet::check_version(self.settings.bitcoin_rpc_client(Some(self.name.clone()))?)?;

      if !client.list_wallets()?.contains(&self.name) {
        client.load_wallet(&self.name)?;
      }

      Wallet::check_descriptors(&self.name, client.list_descriptors(None)?.descriptors)?;

      client
    };

    let chain_block_count = bitcoin_client.get_block_count().unwrap() + 1;

    if !self.no_sync {
      for i in 0.. {
        let response = self.get("/blockcount")?;

        if response
          .text()?
          .parse::<u64>()
          .expect("wallet failed to talk to server. Make sure `ord server` is running.")
          >= chain_block_count
        {
          break;
        } else if i == 20 {
          bail!("wallet failed to synchronize with `ord server` after {i} attempts");
        }
        std::thread::sleep(Duration::from_millis(50));
      }
    }

    let mut utxos = Self::get_utxos(&bitcoin_client)?;
    let locked_utxos = Self::get_locked_utxos(&bitcoin_client)?;
    utxos.extend(locked_utxos.clone());

    let output_artifacts = self.get_output_artifacts(utxos.clone().into_keys().collect())?;

    let inscriptions = output_artifacts
      .iter()
      .flat_map(|(_output, info)| info.inscriptions.clone())
      .collect::<Vec<InscriptionId>>();

    let (inscriptions, inscriptions_info) = self.get_inscriptions(&inscriptions)?;

    let status = self.get_server_status()?;

    Ok(Wallet {
      bitcoin_client,
      database,
      has_rune_index: status.rune_index,
      has_sat_index: status.sat_index,
      inscriptions_info,
      inscriptions,
      locked_utxos,
      ord_client: self.ord_client,
      output_artifacts,
      rpc_url: self.rpc_url,
      settings: self.settings,
      utxos,
    })
  }

  fn get_output_artifacts(
    &self,
    outputs: Vec<OutPoint>,
  ) -> Result<BTreeMap<OutPoint, api::OutputArtifacts>> {
    let response = self.post("/outputs", &outputs)?;

    if !response.status().is_success() {
      bail!("wallet failed get outputs: {}", response.text()?);
    }

    let output_artifacts: BTreeMap<OutPoint, api::OutputArtifacts> = outputs
      .into_iter()
      .zip(serde_json::from_str::<Vec<api::OutputArtifacts>>(
        &response.text()?,
      )?)
      .collect();

    for (output, artifacts) in &output_artifacts {
      if !artifacts.indexed {
        bail!("output in wallet but not in ord server: {output}");
      }
    }

    Ok(output_artifacts)
  }

  fn get_inscriptions(
    &self,
    inscriptions: &Vec<InscriptionId>,
  ) -> Result<(
    BTreeMap<SatPoint, Vec<InscriptionId>>,
    BTreeMap<InscriptionId, api::Inscription>,
  )> {
    let response = self.post("/inscriptions", inscriptions)?;

    if !response.status().is_success() {
      bail!("wallet failed get inscriptions: {}", response.text()?);
    }

    let mut inscriptions = BTreeMap::new();
    let mut inscriptions_info = BTreeMap::new();
    for info in serde_json::from_str::<Vec<api::Inscription>>(&response.text()?)? {
      inscriptions
        .entry(info.satpoint)
        .or_insert_with(Vec::new)
        .push(info.id);

      inscriptions_info.insert(info.id, info);
    }

    Ok((inscriptions, inscriptions_info))
  }

  fn get_utxos(bitcoin_client: &Client) -> Result<BTreeMap<OutPoint, TxOut>> {
    Ok(
      bitcoin_client
        .list_unspent(None, None, None, None, None)?
        .into_iter()
        .map(|utxo| {
          let outpoint = OutPoint::new(utxo.txid, utxo.vout);
          let txout = TxOut {
            script_pubkey: utxo.script_pub_key,
            value: utxo.amount.to_sat(),
          };

          (outpoint, txout)
        })
        .collect(),
    )
  }

  fn get_locked_utxos(bitcoin_client: &Client) -> Result<BTreeMap<OutPoint, TxOut>> {
    #[derive(Deserialize)]
    pub(crate) struct JsonOutPoint {
      txid: Txid,
      vout: u32,
    }

    let outpoints = bitcoin_client.call::<Vec<JsonOutPoint>>("listlockunspent", &[])?;

    let mut utxos = BTreeMap::new();

    for outpoint in outpoints {
      let txout = bitcoin_client
        .get_raw_transaction(&outpoint.txid, None)?
        .output
        .get(TryInto::<usize>::try_into(outpoint.vout).unwrap())
        .cloned()
        .ok_or_else(|| anyhow!("Invalid output index"))?;

      utxos.insert(OutPoint::new(outpoint.txid, outpoint.vout), txout);
    }

    Ok(utxos)
  }

  fn get_server_status(&self) -> Result<api::Status> {
    let response = self.get("/status")?;

    if !response.status().is_success() {
      bail!("could not get status: {}", response.text()?)
    }

    Ok(serde_json::from_str(&response.text()?)?)
  }

  pub fn get(&self, path: &str) -> Result<reqwest::blocking::Response> {
    self
      .ord_client
      .get(self.rpc_url.join(path)?)
      .send()
      .map_err(|err| anyhow!(err))
  }

  pub fn post(&self, path: &str, body: &impl Serialize) -> Result<reqwest::blocking::Response> {
    self
      .ord_client
      .post(self.rpc_url.join(path)?)
      .json(body)
      .header(reqwest::header::ACCEPT, "application/json")
      .send()
      .map_err(|err| anyhow!(err))
  }
}
