use {
  self::{
    accept_encoding::AcceptEncoding,
    accept_json::AcceptJson,
    error::{OptionExt, ServerError, ServerResult},
  },
  super::*,
  crate::templates::{
    AddressHtml, BlockHtml, BlocksHtml, ChildrenHtml, ClockSvg, CollectionsHtml, HomeHtml,
    InputHtml, InscriptionHtml, InscriptionsBlockHtml, InscriptionsHtml, OutputHtml, PageContent,
    PageHtml, ParentsHtml, PreviewAudioHtml, PreviewCodeHtml, PreviewFontHtml, PreviewImageHtml,
    PreviewMarkdownHtml, PreviewModelHtml, PreviewPdfHtml, PreviewTextHtml, PreviewUnknownHtml,
    PreviewVideoHtml, RareTxt, RuneHtml, RuneNotFoundHtml, RunesHtml, SatHtml, SatscardHtml,
    TransactionHtml,
  },
  axum::{
    extract::{DefaultBodyLimit, Extension, Json, Path, Query},
    http::{self, header, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
  },
  axum_server::Handle,
  brotli::Decompressor,
  rust_embed::RustEmbed,
  rustls_acme::{
    acme::{LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY},
    axum::AxumAcceptor,
    caches::DirCache,
    AcmeConfig,
  },
  std::{str, sync::Arc},
  tokio_stream::StreamExt,
  tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
    validate_request::ValidateRequestHeaderLayer,
  },
};

pub use server_config::ServerConfig;

mod accept_encoding;
mod accept_json;
mod error;
pub mod query;
mod r;
mod server_config;

enum SpawnConfig {
  Https(AxumAcceptor),
  Http,
  Redirect(String),
}

#[derive(Deserialize)]
pub(crate) struct OutputsQuery {
  #[serde(rename = "type")]
  pub(crate) ty: Option<OutputType>,
}

#[derive(Clone, Copy, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OutputType {
  #[default]
  Any,
  Cardinal,
  Inscribed,
  Runic,
}

#[derive(Deserialize)]
struct Search {
  query: String,
}

#[derive(RustEmbed)]
#[folder = "static"]
struct StaticAssets;

#[derive(Debug, Parser, Clone)]
pub struct Server {
  #[arg(
    long,
    help = "Listen on <ADDRESS> for incoming requests. [default: 0.0.0.0]"
  )]
  pub(crate) address: Option<String>,
  #[arg(
    long,
    help = "Request ACME TLS certificate for <ACME_DOMAIN>. This ord instance must be reachable at <ACME_DOMAIN>:443 to respond to Let's Encrypt ACME challenges."
  )]
  pub(crate) acme_domain: Vec<String>,
  #[arg(
    long,
    help = "Use <CSP_ORIGIN> in Content-Security-Policy header. Set this to the public-facing URL of your ord instance."
  )]
  pub(crate) csp_origin: Option<String>,
  #[arg(
    long,
    help = "Decompress encoded content. Currently only supports brotli. Be careful using this on production instances. A decompressed inscription may be arbitrarily large, making decompression a DoS vector."
  )]
  pub(crate) decompress: bool,
  #[arg(long, env = "ORD_SERVER_DISABLE_JSON_API", help = "Disable JSON API.")]
  pub(crate) disable_json_api: bool,
  #[arg(
    long,
    help = "Listen on <HTTP_PORT> for incoming HTTP requests. [default: 80]"
  )]
  pub(crate) http_port: Option<u16>,
  #[arg(
    long,
    group = "port",
    help = "Listen on <HTTPS_PORT> for incoming HTTPS requests. [default: 443]"
  )]
  pub(crate) https_port: Option<u16>,
  #[arg(long, help = "Store ACME TLS certificates in <ACME_CACHE>.")]
  pub(crate) acme_cache: Option<PathBuf>,
  #[arg(long, help = "Provide ACME contact <ACME_CONTACT>.")]
  pub(crate) acme_contact: Vec<String>,
  #[arg(long, help = "Serve HTTP traffic on <HTTP_PORT>.")]
  pub(crate) http: bool,
  #[arg(long, help = "Serve HTTPS traffic on <HTTPS_PORT>.")]
  pub(crate) https: bool,
  #[arg(long, help = "Redirect HTTP traffic to HTTPS.")]
  pub(crate) redirect_http_to_https: bool,
  #[arg(long, alias = "nosync", help = "Do not update the index.")]
  pub(crate) no_sync: bool,
  #[arg(
    long,
    help = "Proxy `/content/INSCRIPTION_ID` and other recursive endpoints to `<PROXY>` if the inscription is not present on current chain."
  )]
  pub(crate) proxy: Option<Url>,
  #[arg(
    long,
    default_value = "5s",
    help = "Poll Bitcoin Core every <POLLING_INTERVAL>."
  )]
  pub(crate) polling_interval: humantime::Duration,
}

impl Server {
  pub fn run(self, settings: Settings, index: Arc<Index>, handle: Handle) -> SubcommandResult {
    Runtime::new()?.block_on(async {
      let index_clone = index.clone();
      let integration_test = settings.integration_test();

      let index_thread = thread::spawn(move || loop {
        if SHUTTING_DOWN.load(atomic::Ordering::Relaxed) {
          break;
        }

        if !self.no_sync {
          if let Err(error) = index_clone.update() {
            log::warn!("Updating index: {error}");
          }
        }

        thread::sleep(if integration_test {
          Duration::from_millis(100)
        } else {
          self.polling_interval.into()
        });
      });

      INDEXER.lock().unwrap().replace(index_thread);

      let settings = Arc::new(settings);
      let acme_domains = self.acme_domains()?;

      let server_config = Arc::new(ServerConfig {
        chain: settings.chain(),
        csp_origin: self.csp_origin.clone(),
        decompress: self.decompress,
        domain: acme_domains.first().cloned(),
        index_sats: index.has_sat_index(),
        json_api_enabled: !self.disable_json_api,
        proxy: self.proxy.clone(),
      });

      // non-recursive endpoints
      let router = Router::new()
        .route("/", get(Self::home))
        .route("/address/{address}", get(Self::address))
        .route("/block/{query}", get(Self::block))
        .route("/blockcount", get(Self::block_count))
        .route("/blocks", get(Self::blocks))
        .route("/bounties", get(Self::bounties))
        .route("/children/{inscription_id}", get(Self::children))
        .route(
          "/children/{inscription_id}/{page}",
          get(Self::children_paginated),
        )
        .route("/clock", get(Self::clock))
        .route("/collections", get(Self::collections))
        .route("/collections/{page}", get(Self::collections_paginated))
        .route("/decode/{txid}", get(Self::decode))
        .route("/faq", get(Self::faq))
        .route("/favicon.ico", get(Self::favicon))
        .route("/feed.xml", get(Self::feed))
        .route("/input/{block}/{transaction}/{input}", get(Self::input))
        .route("/inscription/{inscription_query}", get(Self::inscription))
        .route(
          "/inscription/{inscription_query}/{child}",
          get(Self::inscription_child),
        )
        .route("/inscriptions", get(Self::inscriptions))
        .route("/inscriptions", post(Self::inscriptions_json))
        .route(
          "/inscriptions/block/{height}",
          get(Self::inscriptions_in_block),
        )
        .route(
          "/inscriptions/block/{height}/{page}",
          get(Self::inscriptions_in_block_paginated),
        )
        .route("/inscriptions/{page}", get(Self::inscriptions_paginated))
        .route("/install.sh", get(Self::install_script))
        .route("/ordinal/{sat}", get(Self::ordinal))
        .route("/output/{output}", get(Self::output))
        .route("/outputs", post(Self::outputs))
        .route("/outputs/{address}", get(Self::outputs_address))
        .route("/parents/{inscription_id}", get(Self::parents))
        .route(
          "/parents/{inscription_id}/{page}",
          get(Self::parents_paginated),
        )
        .route("/preview/{inscription_id}", get(Self::preview))
        .route("/rare.txt", get(Self::rare_txt))
        .route("/rune/{rune}", get(Self::rune))
        .route("/runes", get(Self::runes))
        .route("/runes/{page}", get(Self::runes_paginated))
        .route("/sat/{sat}", get(Self::sat))
        .route("/satpoint/{satpoint}", get(Self::satpoint))
        .route("/satscard", get(Self::satscard))
        .route("/search", get(Self::search_by_query))
        .route("/search/{*query}", get(Self::search_by_path))
        .route("/static/{*path}", get(Self::static_asset))
        .route("/status", get(Self::status))
        .route("/tx/{txid}", get(Self::transaction))
        .route("/update", get(Self::update));

      // recursive endpoints
      let router = router
        .route("/blockhash", get(r::blockhash_string))
        .route("/blockhash/{height}", get(r::block_hash_from_height_string))
        .route("/blockheight", get(r::blockheight_string))
        .route("/blocktime", get(r::blocktime_string))
        .route("/r/blockhash", get(r::blockhash))
        .route("/r/blockhash/{height}", get(r::blockhash_at_height))
        .route("/r/blockheight", get(r::blockheight_string))
        .route("/r/blockinfo/{query}", get(r::blockinfo))
        .route("/r/blocktime", get(r::blocktime_string))
        .route(
          "/r/children/{inscription_id}/inscriptions",
          get(r::children_inscriptions),
        )
        .route(
          "/r/children/{inscription_id}/inscriptions/{page}",
          get(r::children_inscriptions_paginated),
        )
        .route("/r/parents/{inscription_id}", get(r::parents))
        .route(
          "/r/parents/{inscription_id}/{page}",
          get(r::parents_paginated),
        )
        .route("/r/sat/{sat_number}", get(r::sat))
        .route("/r/sat/{sat_number}/at/{index}", get(r::sat_at_index))
        .route("/r/sat/{sat_number}/{page}", get(r::sat_paginated))
        .route("/r/tx/{txid}", get(r::tx))
        .route(
          "/r/undelegated-content/{inscription_id}",
          get(r::undelegated_content),
        )
        .route("/r/utxo/{outpoint}", get(Self::utxo));

      let proxiable_routes = Router::new()
        .route("/content/{inscription_id}", get(r::content))
        .route("/r/children/{inscription_id}", get(r::children))
        .route(
          "/r/children/{inscription_id}/{page}",
          get(r::children_paginated),
        )
        .route("/r/inscription/{inscription_id}", get(r::inscription))
        .route("/r/metadata/{inscription_id}", get(r::metadata))
        .route(
          "/r/sat/{sat_number}/at/{index}/content",
          get(r::sat_at_index_content),
        )
        .layer(axum::middleware::from_fn(Self::proxy_fallback));

      let router = router.merge(proxiable_routes);

      let router = router
        .fallback(Self::fallback)
        .layer(Extension(index))
        .layer(Extension(server_config.clone()))
        .layer(Extension(settings.clone()))
        .layer(SetResponseHeaderLayer::if_not_present(
          header::CONTENT_SECURITY_POLICY,
          HeaderValue::from_static("default-src 'self'"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
          header::STRICT_TRANSPORT_SECURITY,
          HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        .layer(
          CorsLayer::new()
            .allow_methods([http::Method::GET, http::Method::POST])
            .allow_headers([http::header::CONTENT_TYPE])
            .allow_origin(Any),
        )
        .layer(CompressionLayer::new())
        .with_state(server_config.clone());

      let router = if server_config.json_api_enabled {
        router.layer(DefaultBodyLimit::disable())
      } else {
        router
      };

      let router = if let Some((username, password)) = settings.credentials() {
        router.layer(ValidateRequestHeaderLayer::basic(username, password))
      } else {
        router
      };

      match (self.http_port(), self.https_port()) {
        (Some(http_port), None) => {
          self
            .spawn(&settings, router, handle, http_port, SpawnConfig::Http)?
            .await??
        }
        (None, Some(https_port)) => {
          self
            .spawn(
              &settings,
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&settings)?),
            )?
            .await??
        }
        (Some(http_port), Some(https_port)) => {
          let http_spawn_config = if self.redirect_http_to_https {
            SpawnConfig::Redirect(if https_port == 443 {
              format!("https://{}", acme_domains[0])
            } else {
              format!("https://{}:{https_port}", acme_domains[0])
            })
          } else {
            SpawnConfig::Http
          };

          let (http_result, https_result) = tokio::join!(
            self.spawn(
              &settings,
              router.clone(),
              handle.clone(),
              http_port,
              http_spawn_config
            )?,
            self.spawn(
              &settings,
              router,
              handle,
              https_port,
              SpawnConfig::Https(self.acceptor(&settings)?),
            )?
          );
          http_result.and(https_result)??;
        }
        (None, None) => unreachable!(),
      }

      Ok(None)
    })
  }

  fn spawn(
    &self,
    settings: &Settings,
    router: Router,
    handle: Handle,
    port: u16,
    config: SpawnConfig,
  ) -> Result<task::JoinHandle<io::Result<()>>> {
    let address = match &self.address {
      Some(address) => address.as_str(),
      None => {
        if cfg!(test) || settings.integration_test() {
          "127.0.0.1"
        } else {
          "0.0.0.0"
        }
      }
    };

    let addr = (address, port)
      .to_socket_addrs()?
      .next()
      .ok_or_else(|| anyhow!("failed to get socket addrs"))?;

    if !settings.integration_test() && !cfg!(test) {
      eprintln!(
        "Listening on {}://{addr}",
        match config {
          SpawnConfig::Https(_) => "https",
          _ => "http",
        }
      );
    }

    Ok(tokio::spawn(async move {
      match config {
        SpawnConfig::Https(acceptor) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .acceptor(acceptor)
            .serve(router.into_make_service())
            .await
        }
        SpawnConfig::Redirect(destination) => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(
              Router::new()
                .fallback(Self::redirect_http_to_https)
                .layer(Extension(destination))
                .into_make_service(),
            )
            .await
        }
        SpawnConfig::Http => {
          axum_server::Server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service())
            .await
        }
      }
    }))
  }

  fn acme_cache(acme_cache: Option<&PathBuf>, settings: &Settings) -> PathBuf {
    match acme_cache {
      Some(acme_cache) => acme_cache.clone(),
      None => settings.data_dir().join("acme-cache"),
    }
  }

  fn acme_domains(&self) -> Result<Vec<String>> {
    if !self.acme_domain.is_empty() {
      Ok(self.acme_domain.clone())
    } else {
      Ok(vec![
        System::host_name().ok_or(anyhow!("no hostname found"))?
      ])
    }
  }

  fn http_port(&self) -> Option<u16> {
    if self.http || self.http_port.is_some() || (self.https_port.is_none() && !self.https) {
      Some(self.http_port.unwrap_or(80))
    } else {
      None
    }
  }

  fn https_port(&self) -> Option<u16> {
    if self.https || self.https_port.is_some() {
      Some(self.https_port.unwrap_or(443))
    } else {
      None
    }
  }

  fn acceptor(&self, settings: &Settings) -> Result<AxumAcceptor> {
    static RUSTLS_PROVIDER_INSTALLED: LazyLock<bool> = LazyLock::new(|| {
      rustls::crypto::ring::default_provider()
        .install_default()
        .is_ok()
    });

    let config = AcmeConfig::new(self.acme_domains()?)
      .contact(&self.acme_contact)
      .cache_option(Some(DirCache::new(Self::acme_cache(
        self.acme_cache.as_ref(),
        settings,
      ))))
      .directory(if cfg!(test) {
        LETS_ENCRYPT_STAGING_DIRECTORY
      } else {
        LETS_ENCRYPT_PRODUCTION_DIRECTORY
      });

    let mut state = config.state();

    ensure! {
      *RUSTLS_PROVIDER_INSTALLED,
      "failed to install rustls ring crypto provider",
    }

    let mut server_config = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_cert_resolver(state.resolver());

    server_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];

    let acceptor = state.axum_acceptor(Arc::new(server_config));

    tokio::spawn(async move {
      while let Some(result) = state.next().await {
        match result {
          Ok(ok) => log::info!("ACME event: {:?}", ok),
          Err(err) => log::error!("ACME error: {:?}", err),
        }
      }
    });

    Ok(acceptor)
  }

  async fn proxy_fallback(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    request: http::Request<axum::body::Body>,
    next: axum::middleware::Next,
  ) -> ServerResult {
    let mut path = request.uri().path().to_string();

    path.remove(0); // remove leading slash

    let response = next.run(request).await;
    let status = response.status();

    if let Some(proxy) = server_config.proxy.as_ref() {
      if status == StatusCode::NOT_FOUND {
        return task::block_in_place(|| Server::proxy(proxy, &path));
      }
    }

    Ok(response)
  }

  fn index_height(index: &Index) -> ServerResult<Height> {
    index.block_height()?.ok_or_not_found(|| "genesis block")
  }

  async fn clock(Extension(index): Extension<Arc<Index>>) -> ServerResult {
    task::block_in_place(|| {
      Ok(
        (
          [(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'unsafe-inline'"),
          )],
          ClockSvg::new(Self::index_height(&index)?),
        )
          .into_response(),
      )
    })
  }

  async fn fallback(Extension(index): Extension<Arc<Index>>, uri: Uri) -> ServerResult<Response> {
    task::block_in_place(|| {
      let path = urlencoding::decode(uri.path().trim_matches('/'))
        .map_err(|err| ServerError::BadRequest(err.to_string()))?;

      let prefix = if re::INSCRIPTION_ID.is_match(&path) || re::INSCRIPTION_NUMBER.is_match(&path) {
        "inscription"
      } else if re::RUNE_ID.is_match(&path) || re::SPACED_RUNE.is_match(&path) {
        "rune"
      } else if re::OUTPOINT.is_match(&path) {
        "output"
      } else if re::SATPOINT.is_match(&path) {
        "satpoint"
      } else if re::HASH.is_match(&path) {
        if index.block_header(path.parse().unwrap())?.is_some() {
          "block"
        } else {
          "tx"
        }
      } else if re::ADDRESS.is_match(&path) {
        "address"
      } else {
        return Ok(StatusCode::NOT_FOUND.into_response());
      };

      Ok(Redirect::to(&format!("/{prefix}/{path}")).into_response())
    })
  }

  async fn satscard(
    Extension(settings): Extension<Arc<Settings>>,
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    uri: Uri,
  ) -> ServerResult<Response> {
    #[derive(Debug, Deserialize)]
    struct Form {
      url: DeserializeFromStr<Url>,
    }

    if let Ok(form) = Query::<Form>::try_from_uri(&uri) {
      return if let Some(fragment) = form.url.0.fragment() {
        Ok(Redirect::to(&format!("/satscard?{}", fragment)).into_response())
      } else {
        Err(ServerError::BadRequest(
          "satscard URL missing fragment".into(),
        ))
      };
    }

    let satscard = if let Some(query) = uri.query() {
      let satscard = Satscard::from_query_parameters(settings.chain(), query).map_err(|err| {
        ServerError::BadRequest(format!("invalid satscard query parameters: {err}"))
      })?;

      let address_info = Self::address_info(&index, &satscard.address)?.map(
        |api::AddressInfo {
           outputs,
           inscriptions,
           sat_balance,
           runes_balances,
         }| AddressHtml {
          address: satscard.address.clone(),
          header: false,
          inscriptions,
          outputs,
          runes_balances,
          sat_balance,
        },
      );

      Some((satscard, address_info))
    } else {
      None
    };

    Ok(
      SatscardHtml { satscard }
        .page(server_config)
        .into_response(),
    )
  }

  async fn sat(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(sat)): Path<DeserializeFromStr<Sat>>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let inscriptions = index.get_inscription_ids_by_sat(sat)?;
      let satpoint = index.rare_sat_satpoint(sat)?.or_else(|| {
        inscriptions.first().and_then(|&first_inscription_id| {
          index
            .get_inscription_satpoint_by_id(first_inscription_id)
            .ok()
            .flatten()
        })
      });
      let blocktime = index.block_time(sat.height())?;

      let charms = sat.charms();

      let address = if let Some(satpoint) = satpoint {
        if satpoint.outpoint == unbound_outpoint() {
          None
        } else {
          let tx = index
            .get_transaction(satpoint.outpoint.txid)?
            .context("could not get transaction for sat")?;

          let tx_out = tx
            .output
            .get::<usize>(satpoint.outpoint.vout.try_into().unwrap())
            .context("could not get vout for sat")?;

          server_config
            .chain
            .address_from_script(&tx_out.script_pubkey)
            .ok()
        }
      } else {
        None
      };

      Ok(if accept_json {
        Json(api::Sat {
          address: address.map(|address| address.to_string()),
          block: sat.height().0,
          charms: Charm::charms(charms),
          cycle: sat.cycle(),
          decimal: sat.decimal().to_string(),
          degree: sat.degree().to_string(),
          epoch: sat.epoch().0,
          inscriptions,
          name: sat.name(),
          number: sat.0,
          offset: sat.third(),
          percentile: sat.percentile(),
          period: sat.period(),
          rarity: sat.rarity(),
          satpoint,
          timestamp: blocktime.timestamp().timestamp(),
        })
        .into_response()
      } else {
        SatHtml {
          address,
          blocktime,
          inscriptions,
          sat,
          satpoint,
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn ordinal(Path(sat): Path<String>) -> Redirect {
    Redirect::to(&format!("/sat/{sat}"))
  }

  async fn output(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(outpoint): Path<OutPoint>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let (output_info, txout) = index
        .get_output_info(outpoint)?
        .ok_or_not_found(|| format!("output {outpoint}"))?;

      Ok(if accept_json {
        Json(output_info).into_response()
      } else {
        OutputHtml {
          chain: server_config.chain,
          inscriptions: output_info.inscriptions,
          outpoint,
          output: txout,
          runes: output_info.runes,
          sat_ranges: output_info.sat_ranges,
          spent: output_info.spent,
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn utxo(
    Extension(index): Extension<Arc<Index>>,
    Path(outpoint): Path<OutPoint>,
  ) -> ServerResult {
    task::block_in_place(|| {
      Ok(
        Json(
          index
            .get_utxo_recursive(outpoint)?
            .ok_or_not_found(|| format!("output {outpoint}"))?,
        )
        .into_response(),
      )
    })
  }

  async fn satpoint(
    Extension(index): Extension<Arc<Index>>,
    Path(satpoint): Path<SatPoint>,
  ) -> ServerResult<Redirect> {
    task::block_in_place(|| {
      let (output_info, _) = index
        .get_output_info(satpoint.outpoint)?
        .ok_or_not_found(|| format!("satpoint {satpoint}"))?;

      let Some(ranges) = output_info.sat_ranges else {
        return Err(ServerError::NotFound("sat index required".into()));
      };

      let mut total = 0;
      for (start, end) in ranges {
        let size = end - start;
        if satpoint.offset < total + size {
          let sat = start + satpoint.offset - total;

          return Ok(Redirect::to(&format!("/sat/{sat}")));
        }
        total += size;
      }

      Err(ServerError::NotFound(format!(
        "satpoint {satpoint} not found"
      )))
    })
  }

  async fn outputs(
    Extension(index): Extension<Arc<Index>>,
    AcceptJson(accept_json): AcceptJson,
    Json(outputs): Json<Vec<OutPoint>>,
  ) -> ServerResult {
    task::block_in_place(|| {
      Ok(if accept_json {
        let mut response = Vec::new();
        for outpoint in outputs {
          let (output_info, _) = index
            .get_output_info(outpoint)?
            .ok_or_not_found(|| format!("output {outpoint}"))?;

          response.push(output_info);
        }
        Json(response).into_response()
      } else {
        StatusCode::NOT_FOUND.into_response()
      })
    })
  }

  async fn outputs_address(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    AcceptJson(accept_json): AcceptJson,
    Path(address): Path<Address<NetworkUnchecked>>,
    Query(query): Query<OutputsQuery>,
  ) -> ServerResult {
    task::block_in_place(|| {
      if !index.has_address_index() {
        return Err(ServerError::NotFound(
          "this server has no address index".to_string(),
        ));
      }

      if !accept_json {
        return Ok(StatusCode::NOT_FOUND.into_response());
      }

      let output_type = query.ty.unwrap_or_default();

      if output_type != OutputType::Any {
        if !index.has_rune_index() {
          return Err(ServerError::BadRequest(
            "this server has no runes index".to_string(),
          ));
        }

        if !index.has_inscription_index() {
          return Err(ServerError::BadRequest(
            "this server has no inscriptions index".to_string(),
          ));
        }
      }

      let address = address
        .require_network(server_config.chain.network())
        .map_err(|err| ServerError::BadRequest(err.to_string()))?;

      let outputs = index.get_address_info(&address)?;

      let mut response = Vec::new();
      for output in outputs.into_iter() {
        let include = match output_type {
          OutputType::Any => true,
          OutputType::Cardinal => {
            index
              .get_inscriptions_on_output_with_satpoints(output)?
              .unwrap_or_default()
              .is_empty()
              && index
                .get_rune_balances_for_output(output)?
                .unwrap_or_default()
                .is_empty()
          }
          OutputType::Inscribed => !index
            .get_inscriptions_on_output_with_satpoints(output)?
            .unwrap_or_default()
            .is_empty(),
          OutputType::Runic => !index
            .get_rune_balances_for_output(output)?
            .unwrap_or_default()
            .is_empty(),
        };

        if include {
          let (output_info, _) = index
            .get_output_info(output)?
            .ok_or_not_found(|| format!("output {output}"))?;

          response.push(output_info);
        }
      }

      Ok(Json(response).into_response())
    })
  }

  async fn rare_txt(Extension(index): Extension<Arc<Index>>) -> ServerResult<RareTxt> {
    task::block_in_place(|| Ok(RareTxt(index.rare_sat_satpoints()?)))
  }

  async fn rune(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(rune_query)): Path<DeserializeFromStr<query::Rune>>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      if !index.has_rune_index() {
        return Err(ServerError::NotFound(
          "this server has no rune index".to_string(),
        ));
      }

      let rune = match rune_query {
        query::Rune::Spaced(spaced_rune) => spaced_rune.rune,
        query::Rune::Id(rune_id) => index
          .get_rune_by_id(rune_id)?
          .ok_or_not_found(|| format!("rune {rune_id}"))?,
        query::Rune::Number(number) => index
          .get_rune_by_number(usize::try_from(number).unwrap())?
          .ok_or_not_found(|| format!("rune number {number}"))?,
      };

      let Some((id, entry, parent)) = index.rune(rune)? else {
        return Ok(if accept_json {
          StatusCode::NOT_FOUND.into_response()
        } else {
          let unlock = if let Some(height) = rune.unlock_height(server_config.chain.network()) {
            Some((height, index.block_time(height)?.timestamp()))
          } else {
            None
          };

          (
            StatusCode::NOT_FOUND,
            RuneNotFoundHtml { rune, unlock }.page(server_config),
          )
            .into_response()
        });
      };

      let block_height = index.block_height()?.unwrap_or(Height(0));

      let mintable = entry.mintable((block_height.n() + 1).into()).is_ok();

      Ok(if accept_json {
        Json(api::Rune {
          entry,
          id,
          mintable,
          parent,
        })
        .into_response()
      } else {
        RuneHtml {
          entry,
          id,
          mintable,
          parent,
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn runes(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    accept_json: AcceptJson,
  ) -> ServerResult<Response> {
    Self::runes_paginated(
      Extension(server_config),
      Extension(index),
      Path(0),
      accept_json,
    )
    .await
  }

  async fn runes_paginated(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(page_index): Path<usize>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let (entries, more) = index.runes_paginated(50, page_index)?;

      let prev = page_index.checked_sub(1);

      let next = more.then_some(page_index + 1);

      Ok(if accept_json {
        Json(RunesHtml {
          entries,
          more,
          prev,
          next,
        })
        .into_response()
      } else {
        RunesHtml {
          entries,
          more,
          prev,
          next,
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn home(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult<PageHtml<HomeHtml>> {
    task::block_in_place(|| {
      Ok(
        HomeHtml {
          inscriptions: index.get_home_inscriptions()?,
        }
        .page(server_config),
      )
    })
  }

  async fn blocks(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let blocks = index.blocks(100)?;
      let mut featured_blocks = BTreeMap::new();
      for (height, hash) in blocks.iter().take(5) {
        let (inscriptions, _total_num) =
          index.get_highest_paying_inscriptions_in_block(*height, 8)?;

        featured_blocks.insert(*hash, inscriptions);
      }

      Ok(if accept_json {
        Json(api::Blocks::new(blocks, featured_blocks)).into_response()
      } else {
        BlocksHtml::new(blocks, featured_blocks)
          .page(server_config)
          .into_response()
      })
    })
  }

  async fn install_script() -> Redirect {
    Redirect::to("https://raw.githubusercontent.com/ordinals/ord/master/install.sh")
  }

  async fn address(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(address): Path<Address<NetworkUnchecked>>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let address = address
        .require_network(server_config.chain.network())
        .map_err(|err| ServerError::BadRequest(err.to_string()))?;

      let Some(info) = Self::address_info(&index, &address)? else {
        return Err(ServerError::NotFound(
          "this server has no address index".to_string(),
        ));
      };

      Ok(if accept_json {
        Json(info).into_response()
      } else {
        let api::AddressInfo {
          sat_balance,
          outputs,
          inscriptions,
          runes_balances,
        } = info;

        AddressHtml {
          address,
          header: true,
          inscriptions,
          outputs,
          runes_balances,
          sat_balance,
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  fn address_info(index: &Index, address: &Address) -> ServerResult<Option<api::AddressInfo>> {
    if !index.has_address_index() {
      return Ok(None);
    }

    let mut outputs = index.get_address_info(address)?;

    outputs.sort();

    let sat_balance = index.get_sat_balances_for_outputs(&outputs)?;

    let inscriptions = index.get_inscriptions_for_outputs(&outputs)?;

    let runes_balances = index.get_aggregated_rune_balances_for_outputs(&outputs)?;

    Ok(Some(api::AddressInfo {
      sat_balance,
      outputs,
      inscriptions,
      runes_balances,
    }))
  }

  async fn block(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(DeserializeFromStr(query)): Path<DeserializeFromStr<query::Block>>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let (block, height) = match query {
        query::Block::Height(height) => {
          let block = index
            .get_block_by_height(height)?
            .ok_or_not_found(|| format!("block {height}"))?;

          (block, height)
        }
        query::Block::Hash(hash) => {
          let info = index
            .block_header_info(hash)?
            .ok_or_not_found(|| format!("block {hash}"))?;

          let block = index
            .get_block_by_hash(hash)?
            .ok_or_not_found(|| format!("block {hash}"))?;

          (block, u32::try_from(info.height).unwrap())
        }
      };

      let runes = index.get_runes_in_block(u64::from(height))?;
      Ok(if accept_json {
        let inscriptions = index.get_inscriptions_in_block(height)?;
        Json(api::Block::new(
          block,
          Height(height),
          Self::index_height(&index)?,
          inscriptions,
          runes,
        ))
        .into_response()
      } else {
        let (featured_inscriptions, total_num) =
          index.get_highest_paying_inscriptions_in_block(height, 8)?;
        BlockHtml::new(
          block,
          Height(height),
          Self::index_height(&index)?,
          total_num,
          featured_inscriptions,
          runes,
        )
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn transaction(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(txid): Path<Txid>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let transaction = index
        .get_transaction(txid)?
        .ok_or_not_found(|| format!("transaction {txid}"))?;

      let inscription_count = index.inscription_count(txid)?;

      let runestone = Runestone::decipher(&transaction).and_then(|artifact| match artifact {
        Artifact::Runestone(runestone) => Some(runestone),
        Artifact::Cenotaph(_) => None,
      });

      Ok(if accept_json {
        Json(api::Transaction {
          chain: server_config.chain,
          etching: index.get_etching(txid)?,
          inscription_count,
          runestone,
          transaction,
          txid,
        })
        .into_response()
      } else {
        TransactionHtml {
          chain: server_config.chain,
          etching: index.get_etching(txid)?,
          inscription_count,
          runestone,
          transaction,
          txid,
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn decode(
    Extension(index): Extension<Arc<Index>>,
    Path(txid): Path<Txid>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let transaction = index
        .get_transaction(txid)?
        .ok_or_not_found(|| format!("transaction {txid}"))?;

      let inscriptions = ParsedEnvelope::from_transaction(&transaction);
      let runestone = Runestone::decipher(&transaction);

      Ok(if accept_json {
        Json(api::Decode {
          inscriptions,
          runestone,
        })
        .into_response()
      } else {
        StatusCode::NOT_FOUND.into_response()
      })
    })
  }

  async fn update(
    Extension(settings): Extension<Arc<Settings>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult {
    task::block_in_place(|| {
      if settings.integration_test() {
        index.update()?;
        Ok(index.block_count()?.to_string().into_response())
      } else {
        Ok(StatusCode::NOT_FOUND.into_response())
      }
    })
  }

  async fn status(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      Ok(if accept_json {
        Json(index.status(server_config.json_api_enabled)?).into_response()
      } else {
        index
          .status(server_config.json_api_enabled)?
          .page(server_config)
          .into_response()
      })
    })
  }

  async fn search_by_query(
    Extension(index): Extension<Arc<Index>>,
    Query(search): Query<Search>,
  ) -> ServerResult<Redirect> {
    Self::search(index, search.query).await
  }

  async fn search_by_path(
    Extension(index): Extension<Arc<Index>>,
    Path(search): Path<Search>,
  ) -> ServerResult<Redirect> {
    Self::search(index, search.query).await
  }

  async fn search(index: Arc<Index>, query: String) -> ServerResult<Redirect> {
    task::block_in_place(|| {
      let query = query.trim();

      if re::HASH.is_match(query) {
        if index.block_header(query.parse().unwrap())?.is_some() {
          Ok(Redirect::to(&format!("/block/{query}")))
        } else {
          Ok(Redirect::to(&format!("/tx/{query}")))
        }
      } else if re::OUTPOINT.is_match(query) {
        Ok(Redirect::to(&format!("/output/{query}")))
      } else if re::INSCRIPTION_ID.is_match(query) || re::INSCRIPTION_NUMBER.is_match(query) {
        Ok(Redirect::to(&format!("/inscription/{query}")))
      } else if let Some(captures) = re::SATSCARD_URL.captures(query) {
        Ok(Redirect::to(&format!(
          "/satscard?{}",
          &captures["parameters"]
        )))
      } else if re::SPACED_RUNE.is_match(query) {
        Ok(Redirect::to(&format!("/rune/{query}")))
      } else if re::RUNE_ID.is_match(query) {
        let id = query
          .parse::<RuneId>()
          .map_err(|err| ServerError::BadRequest(err.to_string()))?;

        let rune = index.get_rune_by_id(id)?.ok_or_not_found(|| "rune ID")?;

        Ok(Redirect::to(&format!("/rune/{rune}")))
      } else if re::ADDRESS.is_match(query) {
        Ok(Redirect::to(&format!("/address/{query}")))
      } else if re::SATPOINT.is_match(query) {
        Ok(Redirect::to(&format!("/satpoint/{query}")))
      } else {
        Ok(Redirect::to(&format!("/sat/{query}")))
      }
    })
  }

  async fn favicon() -> ServerResult {
    Ok(
      Self::static_asset(Path("/favicon.png".to_string()))
        .await
        .into_response(),
    )
  }

  async fn feed(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult {
    task::block_in_place(|| {
      let mut builder = rss::ChannelBuilder::default();

      let chain = server_config.chain;
      match chain {
        Chain::Mainnet => builder.title("Inscriptions".to_string()),
        _ => builder.title(format!("Inscriptions – {chain:?}")),
      };

      builder.generator(Some("ord".to_string()));

      for (number, id) in index.get_feed_inscriptions(300)? {
        builder.item(
          rss::ItemBuilder::default()
            .title(Some(format!("Inscription {number}")))
            .link(Some(format!("/inscription/{id}")))
            .guid(Some(rss::Guid {
              value: format!("/inscription/{id}"),
              permalink: true,
            }))
            .build(),
        );
      }

      Ok(
        (
          [
            (header::CONTENT_TYPE, "application/rss+xml"),
            (
              header::CONTENT_SECURITY_POLICY,
              "default-src 'unsafe-inline'",
            ),
          ],
          builder.build().to_string(),
        )
          .into_response(),
      )
    })
  }

  async fn static_asset(Path(path): Path<String>) -> ServerResult {
    let content = StaticAssets::get(if let Some(stripped) = path.strip_prefix('/') {
      stripped
    } else {
      &path
    })
    .ok_or_not_found(|| format!("asset {path}"))?;

    let mime = mime_guess::from_path(path).first_or_octet_stream();

    Ok(
      Response::builder()
        .header(header::CONTENT_TYPE, mime.as_ref())
        .body(content.data.into())
        .unwrap(),
    )
  }

  async fn block_count(Extension(index): Extension<Arc<Index>>) -> ServerResult<String> {
    task::block_in_place(|| Ok(index.block_count()?.to_string()))
  }

  async fn input(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(path): Path<(u32, usize, usize)>,
  ) -> ServerResult<PageHtml<InputHtml>> {
    task::block_in_place(|| {
      let not_found = || format!("input /{}/{}/{}", path.0, path.1, path.2);

      let block = index
        .get_block_by_height(path.0)?
        .ok_or_not_found(not_found)?;

      let transaction = block
        .txdata
        .into_iter()
        .nth(path.1)
        .ok_or_not_found(not_found)?;

      let input = transaction
        .input
        .into_iter()
        .nth(path.2)
        .ok_or_not_found(not_found)?;

      Ok(InputHtml { path, input }.page(server_config))
    })
  }

  async fn faq() -> Redirect {
    Redirect::to("https://docs.ordinals.com/faq")
  }

  async fn bounties() -> Redirect {
    Redirect::to("https://docs.ordinals.com/bounties")
  }

  async fn preview(
    Extension(index): Extension<Arc<Index>>,
    Extension(settings): Extension<Arc<Settings>>,
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Path(inscription_id): Path<InscriptionId>,
    accept_encoding: AcceptEncoding,
  ) -> ServerResult {
    task::block_in_place(|| {
      if settings.is_hidden(inscription_id) {
        return Ok(PreviewUnknownHtml.into_response());
      }

      let mut inscription = index
        .get_inscription_by_id(inscription_id)?
        .ok_or_not_found(|| format!("inscription {inscription_id}"))?;

      if let Some(delegate) = inscription.delegate() {
        inscription = index
          .get_inscription_by_id(delegate)?
          .ok_or_not_found(|| format!("delegate {inscription_id}"))?
      }

      let media = inscription.media();

      if let Media::Iframe = media {
        return Ok(
          r::content_response(inscription, accept_encoding, &server_config)?
            .ok_or_not_found(|| format!("inscription {inscription_id} content"))?
            .into_response(),
        );
      }

      let content_security_policy = server_config.preview_content_security_policy(media)?;

      match media {
        Media::Audio => {
          Ok((content_security_policy, PreviewAudioHtml { inscription_id }).into_response())
        }
        Media::Code(language) => Ok(
          (
            content_security_policy,
            PreviewCodeHtml {
              inscription_id,
              language,
            },
          )
            .into_response(),
        ),
        Media::Font => {
          Ok((content_security_policy, PreviewFontHtml { inscription_id }).into_response())
        }
        Media::Iframe => unreachable!(),
        Media::Image(image_rendering) => Ok(
          (
            content_security_policy,
            PreviewImageHtml {
              image_rendering,
              inscription_id,
            },
          )
            .into_response(),
        ),
        Media::Markdown => Ok(
          (
            content_security_policy,
            PreviewMarkdownHtml { inscription_id },
          )
            .into_response(),
        ),
        Media::Model => {
          Ok((content_security_policy, PreviewModelHtml { inscription_id }).into_response())
        }
        Media::Pdf => {
          Ok((content_security_policy, PreviewPdfHtml { inscription_id }).into_response())
        }
        Media::Text => {
          Ok((content_security_policy, PreviewTextHtml { inscription_id }).into_response())
        }
        Media::Unknown => Ok((content_security_policy, PreviewUnknownHtml).into_response()),
        Media::Video => {
          Ok((content_security_policy, PreviewVideoHtml { inscription_id }).into_response())
        }
      }
    })
  }

  async fn inscription(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    AcceptJson(accept_json): AcceptJson,
    Path(DeserializeFromStr(query)): Path<DeserializeFromStr<query::Inscription>>,
  ) -> ServerResult {
    Self::inscription_inner(server_config, &index, accept_json, query, None).await
  }

  async fn inscription_child(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    AcceptJson(accept_json): AcceptJson,
    Path((DeserializeFromStr(query), child)): Path<(DeserializeFromStr<query::Inscription>, usize)>,
  ) -> ServerResult {
    Self::inscription_inner(server_config, &index, accept_json, query, Some(child)).await
  }

  async fn inscription_inner(
    server_config: Arc<ServerConfig>,
    index: &Index,
    accept_json: bool,
    query: query::Inscription,
    child: Option<usize>,
  ) -> ServerResult {
    task::block_in_place(|| {
      if let query::Inscription::Sat(_) = query {
        if !index.has_sat_index() {
          return Err(ServerError::NotFound("sat index required".into()));
        }
      }

      let inscription_info = index.inscription_info(query, child)?;

      Ok(if accept_json {
        let status_code = if inscription_info.is_none() {
          StatusCode::NOT_FOUND
        } else {
          StatusCode::OK
        };

        (status_code, Json(inscription_info.map(|info| info.0))).into_response()
      } else {
        let (info, txout, inscription) =
          inscription_info.ok_or_not_found(|| format!("inscription {query}"))?;

        InscriptionHtml {
          chain: server_config.chain,
          charms: Charm::Vindicated.unset(info.charms.iter().fold(0, |mut acc, charm| {
            charm.set(&mut acc);
            acc
          })),
          child_count: info.child_count,
          children: info.children,
          fee: info.fee,
          height: info.height,
          inscription,
          id: info.id,
          number: info.number,
          next: info.next,
          output: txout,
          parents: info.parents,
          previous: info.previous,
          rune: info.rune,
          sat: info.sat,
          satpoint: info.satpoint,
          timestamp: Utc.timestamp_opt(info.timestamp, 0).unwrap(),
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn inscriptions_json(
    Extension(index): Extension<Arc<Index>>,
    AcceptJson(accept_json): AcceptJson,
    Json(inscriptions): Json<Vec<InscriptionId>>,
  ) -> ServerResult {
    task::block_in_place(|| {
      Ok(if accept_json {
        let mut response = Vec::new();
        for inscription in inscriptions {
          let query = query::Inscription::Id(inscription);
          let (info, _, _) = index
            .inscription_info(query, None)?
            .ok_or_not_found(|| format!("inscription {query}"))?;

          response.push(info);
        }

        Json(response).into_response()
      } else {
        StatusCode::NOT_FOUND.into_response()
      })
    })
  }

  async fn collections(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
  ) -> ServerResult {
    Self::collections_paginated(Extension(server_config), Extension(index), Path(0)).await
  }

  async fn collections_paginated(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(page_index): Path<usize>,
  ) -> ServerResult {
    task::block_in_place(|| {
      let (collections, more_collections) = index.get_collections_paginated(100, page_index)?;

      let prev = page_index.checked_sub(1);

      let next = more_collections.then_some(page_index + 1);

      Ok(
        CollectionsHtml {
          inscriptions: collections,
          prev,
          next,
        }
        .page(server_config)
        .into_response(),
      )
    })
  }

  async fn children(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult {
    Self::children_paginated(
      Extension(server_config),
      Extension(index),
      Path((inscription_id, 0)),
    )
    .await
  }

  async fn children_paginated(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path((parent, page)): Path<(InscriptionId, usize)>,
  ) -> ServerResult {
    task::block_in_place(|| {
      let entry = index
        .get_inscription_entry(parent)?
        .ok_or_not_found(|| format!("inscription {parent}"))?;

      let parent_number = entry.inscription_number;

      let (children, more_children) =
        index.get_children_by_sequence_number_paginated(entry.sequence_number, 100, page)?;

      let prev_page = page.checked_sub(1);

      let next_page = more_children.then_some(page + 1);

      Ok(
        ChildrenHtml {
          parent,
          parent_number,
          children,
          prev_page,
          next_page,
        }
        .page(server_config)
        .into_response(),
      )
    })
  }

  async fn inscriptions(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    accept_json: AcceptJson,
  ) -> ServerResult {
    Self::inscriptions_paginated(
      Extension(server_config),
      Extension(index),
      Path(0),
      accept_json,
    )
    .await
  }

  async fn inscriptions_paginated(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(page_index): Path<u32>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let (inscriptions, more) = index.get_inscriptions_paginated(100, page_index)?;

      let prev = page_index.checked_sub(1);

      let next = more.then_some(page_index + 1);

      Ok(if accept_json {
        Json(api::Inscriptions {
          ids: inscriptions,
          page_index,
          more,
        })
        .into_response()
      } else {
        InscriptionsHtml {
          inscriptions,
          next,
          prev,
        }
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn inscriptions_in_block(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(block_height): Path<u32>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    Self::inscriptions_in_block_paginated(
      Extension(server_config),
      Extension(index),
      Path((block_height, 0)),
      AcceptJson(accept_json),
    )
    .await
  }

  async fn inscriptions_in_block_paginated(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path((block_height, page_index)): Path<(u32, u32)>,
    AcceptJson(accept_json): AcceptJson,
  ) -> ServerResult {
    task::block_in_place(|| {
      let page_size = 100;

      let page_index_usize = usize::try_from(page_index).unwrap_or(usize::MAX);
      let page_size_usize = usize::try_from(page_size).unwrap_or(usize::MAX);

      let mut inscriptions = index
        .get_inscriptions_in_block(block_height)?
        .into_iter()
        .skip(page_index_usize.saturating_mul(page_size_usize))
        .take(page_size_usize.saturating_add(1))
        .collect::<Vec<InscriptionId>>();

      let more = inscriptions.len() > page_size_usize;

      if more {
        inscriptions.pop();
      }

      Ok(if accept_json {
        Json(api::Inscriptions {
          ids: inscriptions,
          page_index,
          more,
        })
        .into_response()
      } else {
        InscriptionsBlockHtml::new(
          block_height,
          index.block_height()?.unwrap_or(Height(0)).n(),
          inscriptions,
          more,
          page_index,
        )?
        .page(server_config)
        .into_response()
      })
    })
  }

  async fn parents(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path(inscription_id): Path<InscriptionId>,
  ) -> ServerResult<Response> {
    Self::parents_paginated(
      Extension(server_config),
      Extension(index),
      Path((inscription_id, 0)),
    )
    .await
  }

  async fn parents_paginated(
    Extension(server_config): Extension<Arc<ServerConfig>>,
    Extension(index): Extension<Arc<Index>>,
    Path((id, page)): Path<(InscriptionId, usize)>,
  ) -> ServerResult<Response> {
    task::block_in_place(|| {
      let child = index
        .get_inscription_entry(id)?
        .ok_or_not_found(|| format!("inscription {id}"))?;

      let (parents, more) = index.get_parents_by_sequence_number_paginated(child.parents, page)?;

      let prev_page = page.checked_sub(1);

      let next_page = more.then_some(page + 1);

      Ok(
        ParentsHtml {
          id,
          number: child.inscription_number,
          parents,
          prev_page,
          next_page,
        }
        .page(server_config)
        .into_response(),
      )
    })
  }

  fn proxy(proxy: &Url, path: &str) -> ServerResult<Response> {
    let response = reqwest::blocking::Client::new()
      .get(format!("{}{}", proxy, path))
      .send()
      .map_err(|err| anyhow!(err))?;

    let status = response.status();

    let mut headers = response.headers().clone();

    headers.insert(
      header::CONTENT_SECURITY_POLICY,
      HeaderValue::from_str(&format!(
        "default-src 'self' {proxy} 'unsafe-eval' 'unsafe-inline' data: blob:"
      ))
      .map_err(|err| ServerError::Internal(Error::from(err)))?,
    );

    Ok(
      (
        status,
        headers,
        response.bytes().map_err(|err| anyhow!(err))?,
      )
        .into_response(),
    )
  }

  async fn redirect_http_to_https(
    Extension(mut destination): Extension<String>,
    uri: Uri,
  ) -> Redirect {
    if let Some(path_and_query) = uri.path_and_query() {
      destination.push_str(path_and_query.as_str());
    }

    Redirect::to(&destination)
  }
}

#[cfg(test)]
mod tests {
  use {
    super::*,
    reqwest::{
      header::{self, HeaderMap},
      StatusCode, Url,
    },
    serde::de::DeserializeOwned,
    std::net::TcpListener,
    tempfile::TempDir,
  };

  const RUNE: u128 = 99246114928149462;

  #[derive(Default)]
  struct Builder {
    core: Option<mockcore::Handle>,
    config: String,
    ord_args: BTreeMap<String, Option<String>>,
    server_args: BTreeMap<String, Option<String>>,
  }

  impl Builder {
    fn core(self, core: mockcore::Handle) -> Self {
      Self {
        core: Some(core),
        ..self
      }
    }

    fn ord_option(mut self, option: &str, value: &str) -> Self {
      self.ord_args.insert(option.into(), Some(value.into()));
      self
    }

    fn ord_flag(mut self, flag: &str) -> Self {
      self.ord_args.insert(flag.into(), None);
      self
    }

    fn server_option(mut self, option: &str, value: &str) -> Self {
      self.server_args.insert(option.into(), Some(value.into()));
      self
    }

    fn server_flag(mut self, flag: &str) -> Self {
      self.server_args.insert(flag.into(), None);
      self
    }

    fn chain(self, chain: Chain) -> Self {
      self.ord_option("--chain", &chain.to_string())
    }

    fn config(self, config: &str) -> Self {
      Self {
        config: config.into(),
        ..self
      }
    }

    fn build(self) -> TestServer {
      let core = self.core.unwrap_or_else(|| {
        mockcore::builder()
          .network(
            self
              .ord_args
              .get("--chain")
              .map(|chain| chain.as_ref().unwrap().parse::<Chain>().unwrap())
              .unwrap_or_default()
              .network(),
          )
          .build()
      });

      let tempdir = TempDir::new().unwrap();

      let cookiefile = tempdir.path().join("cookie");

      fs::write(&cookiefile, "username:password").unwrap();

      let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

      let mut args = vec!["ord".to_string()];

      args.push("--bitcoin-rpc-url".into());
      args.push(core.url());

      args.push("--cookie-file".into());
      args.push(cookiefile.to_str().unwrap().into());

      args.push("--datadir".into());
      args.push(tempdir.path().to_str().unwrap().into());

      if !self.ord_args.contains_key("--chain") {
        args.push("--chain".into());
        args.push(core.network());
      }

      for (arg, value) in self.ord_args {
        args.push(arg);

        if let Some(value) = value {
          args.push(value);
        }
      }

      args.push("server".into());

      args.push("--address".into());
      args.push("127.0.0.1".into());

      args.push("--http-port".into());
      args.push(port.to_string());

      args.push("--polling-interval".into());
      args.push("100ms".into());

      for (arg, value) in self.server_args {
        args.push(arg);

        if let Some(value) = value {
          args.push(value);
        }
      }

      let arguments = Arguments::try_parse_from(args).unwrap();

      let Subcommand::Server(server) = arguments.subcommand else {
        panic!("unexpected subcommand: {:?}", arguments.subcommand);
      };

      let settings = Settings::from_options(arguments.options)
        .or(serde_yaml::from_str::<Settings>(&self.config).unwrap())
        .or_defaults()
        .unwrap();

      let index = Arc::new(Index::open(&settings).unwrap());
      let ord_server_handle = Handle::new();

      {
        let index = index.clone();
        let ord_server_handle = ord_server_handle.clone();
        thread::spawn(|| server.run(settings, index, ord_server_handle).unwrap());
      }

      while index.statistic(crate::index::Statistic::Commits) == 0 {
        thread::sleep(Duration::from_millis(50));
      }

      let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

      for i in 0.. {
        match client.get(format!("http://127.0.0.1:{port}/status")).send() {
          Ok(_) => break,
          Err(err) => {
            if i == 400 {
              panic!("ord server failed to start: {err}");
            }
          }
        }

        thread::sleep(Duration::from_millis(50));
      }

      TestServer {
        core,
        index,
        ord_server_handle,
        tempdir,
        url: Url::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
      }
    }

    fn https(self) -> Self {
      self.server_flag("--https")
    }

    fn index_addresses(self) -> Self {
      self.ord_flag("--index-addresses")
    }

    fn index_runes(self) -> Self {
      self.ord_flag("--index-runes")
    }

    fn index_sats(self) -> Self {
      self.ord_flag("--index-sats")
    }

    fn redirect_http_to_https(self) -> Self {
      self.server_flag("--redirect-http-to-https")
    }
  }

  struct TestServer {
    core: mockcore::Handle,
    index: Arc<Index>,
    ord_server_handle: Handle,
    #[allow(unused)]
    tempdir: TempDir,
    url: Url,
  }

  impl TestServer {
    fn builder() -> Builder {
      Default::default()
    }

    fn new() -> Self {
      Builder::default().build()
    }

    #[track_caller]
    pub(crate) fn etch(
      &self,
      runestone: Runestone,
      outputs: usize,
      witness: Option<Witness>,
    ) -> (Txid, RuneId) {
      let block_count = usize::try_from(self.index.block_count().unwrap()).unwrap();

      self.mine_blocks(1);

      self.core.broadcast_tx(TransactionTemplate {
        inputs: &[(block_count, 0, 0, Default::default())],
        p2tr: true,
        ..default()
      });

      self.mine_blocks((Runestone::COMMIT_CONFIRMATIONS - 1).into());

      let witness = witness.unwrap_or_else(|| {
        let tapscript = script::Builder::new()
          .push_slice::<&PushBytes>(
            runestone
              .etching
              .unwrap()
              .rune
              .unwrap()
              .commitment()
              .as_slice()
              .try_into()
              .unwrap(),
          )
          .into_script();
        let mut witness = Witness::default();
        witness.push(tapscript);
        witness.push([]);
        witness
      });

      let txid = self.core.broadcast_tx(TransactionTemplate {
        inputs: &[(block_count + 1, 1, 0, witness)],
        op_return: Some(runestone.encipher()),
        outputs,
        ..default()
      });

      self.mine_blocks(1);

      (
        txid,
        RuneId {
          block: (self.index.block_count().unwrap() - 1).into(),
          tx: 1,
        },
      )
    }

    #[track_caller]
    fn get(&self, path: impl AsRef<str>) -> reqwest::blocking::Response {
      if let Err(error) = self.index.update() {
        log::error!("{error}");
      }
      reqwest::blocking::get(self.join_url(path.as_ref())).unwrap()
    }

    #[track_caller]
    pub(crate) fn get_json<T: DeserializeOwned>(&self, path: impl AsRef<str>) -> T {
      if let Err(error) = self.index.update() {
        log::error!("{error}");
      }

      let client = reqwest::blocking::Client::new();

      let response = client
        .get(self.join_url(path.as_ref()))
        .header(header::ACCEPT, "application/json")
        .send()
        .unwrap();

      assert_eq!(response.status(), StatusCode::OK);

      response.json().unwrap()
    }

    fn join_url(&self, url: &str) -> Url {
      self.url.join(url).unwrap()
    }

    #[track_caller]
    fn assert_response(&self, path: impl AsRef<str>, status: StatusCode, expected_response: &str) {
      let response = self.get(path);
      assert_eq!(response.status(), status, "{}", response.text().unwrap());
      pretty_assert_eq!(response.text().unwrap(), expected_response);
    }

    #[track_caller]
    fn assert_response_regex(
      &self,
      path: impl AsRef<str>,
      status: StatusCode,
      regex: impl AsRef<str>,
    ) {
      let response = self.get(path);
      assert_eq!(
        response.status(),
        status,
        "response: {}",
        response.text().unwrap()
      );
      assert_regex_match!(response.text().unwrap(), regex.as_ref());
    }

    #[track_caller]
    fn assert_html(&self, path: impl AsRef<str>, content: impl PageContent) {
      self.assert_html_status(path, StatusCode::OK, content);
    }

    #[track_caller]
    fn assert_html_status(
      &self,
      path: impl AsRef<str>,
      status: StatusCode,
      content: impl PageContent,
    ) {
      let response = self.get(path);

      assert_eq!(response.status(), status, "{}", response.text().unwrap());

      let expected_response = PageHtml::new(
        content,
        Arc::new(ServerConfig {
          chain: self.index.chain(),
          domain: Some(System::host_name().unwrap()),
          ..Default::default()
        }),
      )
      .to_string();

      pretty_assert_eq!(response.text().unwrap(), expected_response);
    }

    fn assert_response_csp(
      &self,
      path: impl AsRef<str>,
      status: StatusCode,
      content_security_policy: &str,
      regex: impl AsRef<str>,
    ) {
      let response = self.get(path);
      assert_eq!(response.status(), status);
      assert_eq!(
        response
          .headers()
          .get(header::CONTENT_SECURITY_POLICY,)
          .unwrap(),
        content_security_policy
      );
      assert_regex_match!(response.text().unwrap(), regex.as_ref());
    }

    #[track_caller]
    fn assert_redirect(&self, path: &str, location: &str) {
      let response = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(self.join_url(path))
        .send()
        .unwrap();

      assert_eq!(response.status(), StatusCode::SEE_OTHER);
      assert_eq!(response.headers().get(header::LOCATION).unwrap(), location);
    }

    #[track_caller]
    fn mine_blocks(&self, n: u64) -> Vec<Block> {
      let blocks = self.core.mine_blocks(n);
      self.index.update().unwrap();
      blocks
    }

    fn mine_blocks_with_subsidy(&self, n: u64, subsidy: u64) -> Vec<Block> {
      let blocks = self.core.mine_blocks_with_subsidy(n, subsidy);
      self.index.update().unwrap();
      blocks
    }
  }

  impl Drop for TestServer {
    fn drop(&mut self) {
      self.ord_server_handle.shutdown();
    }
  }

  fn parse_server_args(args: &str) -> (Settings, Server) {
    match Arguments::try_parse_from(args.split_whitespace()) {
      Ok(arguments) => match arguments.subcommand {
        Subcommand::Server(server) => (
          Settings::from_options(arguments.options)
            .or_defaults()
            .unwrap(),
          server,
        ),
        subcommand => panic!("unexpected subcommand: {subcommand:?}"),
      },
      Err(err) => panic!("error parsing arguments: {err}"),
    }
  }

  #[test]
  fn http_and_https_port_dont_conflict() {
    parse_server_args(
      "ord server --http-port 0 --https-port 0 --acme-cache foo --acme-contact bar --acme-domain baz",
    );
  }

  #[test]
  fn http_port_defaults_to_80() {
    assert_eq!(parse_server_args("ord server").1.http_port(), Some(80));
  }

  #[test]
  fn https_port_defaults_to_none() {
    assert_eq!(parse_server_args("ord server").1.https_port(), None);
  }

  #[test]
  fn https_sets_https_port_to_443() {
    assert_eq!(
      parse_server_args("ord server --https --acme-cache foo --acme-contact bar --acme-domain baz")
        .1
        .https_port(),
      Some(443)
    );
  }

  #[test]
  fn https_disables_http() {
    assert_eq!(
      parse_server_args("ord server --https --acme-cache foo --acme-contact bar --acme-domain baz")
        .1
        .http_port(),
      None
    );
  }

  #[test]
  fn https_port_disables_http() {
    assert_eq!(
      parse_server_args(
        "ord server --https-port 433 --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .http_port(),
      None
    );
  }

  #[test]
  fn https_port_sets_https_port() {
    assert_eq!(
      parse_server_args(
        "ord server --https-port 1000 --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .https_port(),
      Some(1000)
    );
  }

  #[test]
  fn http_with_https_leaves_http_enabled() {
    assert_eq!(
      parse_server_args(
        "ord server --https --http --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .http_port(),
      Some(80)
    );
  }

  #[test]
  fn http_with_https_leaves_https_enabled() {
    assert_eq!(
      parse_server_args(
        "ord server --https --http --acme-cache foo --acme-contact bar --acme-domain baz"
      )
      .1
      .https_port(),
      Some(443)
    );
  }

  #[test]
  fn acme_contact_accepts_multiple_values() {
    assert!(Arguments::try_parse_from([
      "ord",
      "server",
      "--address",
      "127.0.0.1",
      "--http-port",
      "0",
      "--acme-contact",
      "foo",
      "--acme-contact",
      "bar"
    ])
    .is_ok());
  }

  #[test]
  fn acme_domain_accepts_multiple_values() {
    assert!(Arguments::try_parse_from([
      "ord",
      "server",
      "--address",
      "127.0.0.1",
      "--http-port",
      "0",
      "--acme-domain",
      "foo",
      "--acme-domain",
      "bar"
    ])
    .is_ok());
  }

  #[test]
  fn acme_cache_defaults_to_data_dir() {
    let arguments = Arguments::try_parse_from(["ord", "--datadir", "foo", "server"]).unwrap();

    let settings = Settings::from_options(arguments.options)
      .or_defaults()
      .unwrap();

    let acme_cache = Server::acme_cache(None, &settings).display().to_string();
    assert!(
      acme_cache.contains(if cfg!(windows) {
        r"foo\acme-cache"
      } else {
        "foo/acme-cache"
      }),
      "{acme_cache}"
    )
  }

  #[test]
  fn acme_cache_flag_is_respected() {
    let arguments =
      Arguments::try_parse_from(["ord", "--datadir", "foo", "server", "--acme-cache", "bar"])
        .unwrap();

    let settings = Settings::from_options(arguments.options)
      .or_defaults()
      .unwrap();

    let acme_cache = Server::acme_cache(Some(&"bar".into()), &settings)
      .display()
      .to_string();
    assert_eq!(acme_cache, "bar")
  }

  #[test]
  fn acme_domain_defaults_to_hostname() {
    let (_, server) = parse_server_args("ord server");
    assert_eq!(
      server.acme_domains().unwrap(),
      &[System::host_name().unwrap()]
    );
  }

  #[test]
  fn acme_domain_flag_is_respected() {
    let (_, server) = parse_server_args("ord server --acme-domain example.com");
    assert_eq!(server.acme_domains().unwrap(), &["example.com"]);
  }

  #[test]
  fn install_sh_redirects_to_github() {
    TestServer::new().assert_redirect(
      "/install.sh",
      "https://raw.githubusercontent.com/ordinals/ord/master/install.sh",
    );
  }

  #[test]
  fn ordinal_redirects_to_sat() {
    TestServer::new().assert_redirect("/ordinal/0", "/sat/0");
  }

  #[test]
  fn bounties_redirects_to_docs_site() {
    TestServer::new().assert_redirect("/bounties", "https://docs.ordinals.com/bounties");
  }

  #[test]
  fn faq_redirects_to_docs_site() {
    TestServer::new().assert_redirect("/faq", "https://docs.ordinals.com/faq");
  }

  #[test]
  fn search_by_query_returns_rune() {
    TestServer::new().assert_redirect("/search?query=ABCD", "/rune/ABCD");
  }

  #[test]
  fn search_by_query_returns_spaced_rune() {
    TestServer::new().assert_redirect("/search?query=AB•CD", "/rune/AB•CD");
  }

  #[test]
  fn search_by_query_returns_satscard() {
    TestServer::new().assert_redirect(
      "/search?query=https://satscard.com/start%23foo",
      "/satscard?foo",
    );
    TestServer::new().assert_redirect(
      "/search?query=https://getsatscard.com/start%23foo",
      "/satscard?foo",
    );
  }

  #[test]
  fn search_by_query_returns_inscription() {
    TestServer::new().assert_redirect(
      "/search?query=0000000000000000000000000000000000000000000000000000000000000000i0",
      "/inscription/0000000000000000000000000000000000000000000000000000000000000000i0",
    );
  }

  #[test]
  fn search_by_query_returns_inscription_by_number() {
    TestServer::new().assert_redirect("/search?query=0", "/inscription/0");
  }

  #[test]
  fn search_is_whitespace_insensitive() {
    TestServer::new().assert_redirect("/search/ abc ", "/sat/abc");
  }

  #[test]
  fn search_by_path_returns_sat() {
    TestServer::new().assert_redirect("/search/abc", "/sat/abc");
  }

  #[test]
  fn search_for_blockhash_returns_block() {
    TestServer::new().assert_redirect(
      "/search/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      "/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
  }

  #[test]
  fn search_for_txid_returns_transaction() {
    TestServer::new().assert_redirect(
      "/search/0000000000000000000000000000000000000000000000000000000000000000",
      "/tx/0000000000000000000000000000000000000000000000000000000000000000",
    );
  }

  #[test]
  fn search_for_outpoint_returns_output() {
    TestServer::new().assert_redirect(
      "/search/0000000000000000000000000000000000000000000000000000000000000000:0",
      "/output/0000000000000000000000000000000000000000000000000000000000000000:0",
    );
  }

  #[test]
  fn search_for_inscription_id_returns_inscription() {
    TestServer::new().assert_redirect(
      "/search/0000000000000000000000000000000000000000000000000000000000000000i0",
      "/inscription/0000000000000000000000000000000000000000000000000000000000000000i0",
    );
  }

  #[test]
  fn search_by_path_returns_rune() {
    TestServer::new().assert_redirect("/search/ABCD", "/rune/ABCD");
  }

  #[test]
  fn search_by_path_returns_spaced_rune() {
    TestServer::new().assert_redirect("/search/AB•CD", "/rune/AB•CD");
  }

  #[test]
  fn search_by_rune_id_returns_rune() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(rune),
          ..default()
        }),
        ..default()
      },
      1,
      None,
    );

    server.mine_blocks(1);

    server.assert_redirect("/search/8:1", "/rune/AAAAAAAAAAAAA");
    server.assert_redirect("/search?query=8:1", "/rune/AAAAAAAAAAAAA");

    server.assert_response_regex(
      "/search/100000000000000000000:200000000000000000",
      StatusCode::BAD_REQUEST,
      ".*",
    );
  }

  #[test]
  fn search_by_satpoint_returns_sat() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    let txid = server.mine_blocks(1)[0].txdata[0].compute_txid();

    server.assert_redirect(
      &format!("/search/{txid}:0:0"),
      &format!("/satpoint/{txid}:0:0"),
    );

    server.assert_redirect(
      &format!("/search?query={txid}:0:0"),
      &format!("/satpoint/{txid}:0:0"),
    );

    server.assert_redirect(
      &format!("/satpoint/{txid}:0:0"),
      &format!("/sat/{}", 50 * COIN_VALUE),
    );

    server.assert_response_regex("/search/1:2:3", StatusCode::BAD_REQUEST, ".*");
  }

  #[test]
  fn satpoint_returns_sat_in_multiple_ranges() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    server.mine_blocks(1);

    let split = TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      outputs: 2,
      fee: 0,
      ..default()
    };

    server.core.broadcast_tx(split);

    server.mine_blocks(1);

    let merge = TransactionTemplate {
      inputs: &[(2, 0, 0, Default::default()), (2, 1, 0, Default::default())],
      fee: 0,
      ..default()
    };

    let txid = server.core.broadcast_tx(merge);

    server.mine_blocks(1);

    server.assert_redirect(
      &format!("/satpoint/{txid}:0:0"),
      &format!("/sat/{}", 100 * COIN_VALUE),
    );

    server.assert_redirect(
      &format!("/satpoint/{txid}:0:{}", 50 * COIN_VALUE),
      &format!("/sat/{}", 50 * COIN_VALUE),
    );

    server.assert_redirect(
      &format!("/satpoint/{txid}:0:{}", 50 * COIN_VALUE - 1),
      &format!("/sat/{}", 150 * COIN_VALUE - 1),
    );
  }

  #[test]
  fn fallback() {
    let server = TestServer::new();

    server.assert_redirect("/0", "/inscription/0");
    server.assert_redirect("/0/", "/inscription/0");
    server.assert_redirect("/0//", "/inscription/0");
    server.assert_redirect(
      "/521f8eccffa4c41a3a7728dd012ea5a4a02feed81f41159231251ecf1e5c79dai0",
      "/inscription/521f8eccffa4c41a3a7728dd012ea5a4a02feed81f41159231251ecf1e5c79dai0",
    );
    server.assert_redirect("/-1", "/inscription/-1");
    server.assert_redirect("/FOO", "/rune/FOO");
    server.assert_redirect("/FO.O", "/rune/FO.O");
    server.assert_redirect("/FO•O", "/rune/FO•O");
    server.assert_redirect("/0:0", "/rune/0:0");
    server.assert_redirect(
      "/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0",
      "/output/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0",
    );
    server.assert_redirect(
      "/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0",
      "/satpoint/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0",
    );
    server.assert_redirect(
      "/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      "/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    );
    server.assert_redirect(
      "/000000000000000000000000000000000000000000000000000000000000000f",
      "/tx/000000000000000000000000000000000000000000000000000000000000000f",
    );
    server.assert_redirect(
      "/bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
      "/address/bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
    );
    server.assert_redirect(
      "/bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
      "/address/bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    );
    server.assert_redirect(
      "/1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
      "/address/1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    );

    server.assert_response_regex("/hello", StatusCode::NOT_FOUND, "");

    server.assert_response_regex(
      "/%C3%28",
      StatusCode::BAD_REQUEST,
      "invalid utf-8 sequence of 1 bytes from index 0",
    );
  }

  #[test]
  fn runes_can_be_queried_by_rune_id() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex("/rune/9:1", StatusCode::NOT_FOUND, ".*");

    server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(rune),
          ..default()
        }),
        ..default()
      },
      1,
      None,
    );

    server.mine_blocks(1);

    server.assert_response_regex(
      "/rune/8:1",
      StatusCode::OK,
      ".*<title>Rune AAAAAAAAAAAAA</title>.*",
    );
  }

  #[test]
  fn runes_can_be_queried_by_rune_number() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    server.assert_response_regex("/rune/0", StatusCode::NOT_FOUND, ".*");

    for i in 0..10 {
      let rune = Rune(RUNE + i);
      server.etch(
        Runestone {
          edicts: vec![Edict {
            id: RuneId::default(),
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(rune),
            ..default()
          }),
          ..default()
        },
        1,
        None,
      );

      server.mine_blocks(1);
    }

    server.assert_response_regex(
      "/rune/0",
      StatusCode::OK,
      ".*<title>Rune AAAAAAAAAAAAA</title>.*",
    );

    for i in 1..6 {
      server.assert_response_regex(
        format!("/rune/{}", i),
        StatusCode::OK,
        ".*<title>Rune AAAAAAAAAAAA.*</title>.*",
      );
    }

    server.assert_response_regex(
      "/rune/9",
      StatusCode::OK,
      ".*<title>Rune AAAAAAAAAAAAJ</title>.*",
    );
  }

  #[test]
  fn rune_not_etched_shows_unlock_height() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    server.assert_html_status(
      "/rune/A",
      StatusCode::NOT_FOUND,
      RuneNotFoundHtml {
        rune: Rune(0),
        unlock: Some((
          Height(209999),
          DateTime::from_timestamp(125998800, 0).unwrap(),
        )),
      },
    );
  }

  #[test]
  fn reserved_rune_not_etched_shows_reserved_status() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    server.assert_html_status(
      format!("/rune/{}", Rune(Rune::RESERVED)),
      StatusCode::NOT_FOUND,
      RuneNotFoundHtml {
        rune: Rune(Rune::RESERVED),
        unlock: None,
      },
    );
  }

  #[test]
  fn runes_are_displayed_on_runes_page() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    server.assert_html(
      "/runes",
      RunesHtml {
        entries: Vec::new(),
        more: false,
        prev: None,
        next: None,
      },
    );

    let (txid, id) = server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          symbol: Some('%'),
          premine: Some(u128::MAX),
          ..default()
        }),
        ..default()
      },
      1,
      Default::default(),
    );

    pretty_assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          block: id.block,
          etching: txid,
          spaced_rune: SpacedRune {
            rune: Rune(RUNE),
            spacers: 0
          },
          premine: u128::MAX,
          timestamp: id.block,
          symbol: Some('%'),
          ..default()
        }
      )]
    );

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])]
    );

    server.assert_html(
      "/runes",
      RunesHtml {
        entries: vec![(
          RuneId::default(),
          RuneEntry {
            spaced_rune: SpacedRune {
              rune: Rune(RUNE),
              spacers: 0,
            },
            ..default()
          },
        )],
        more: false,
        prev: None,
        next: None,
      },
    );
  }

  #[test]
  fn runes_are_displayed_on_rune_page() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    let (txid, id) = server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(rune),
          symbol: Some('%'),
          premine: Some(u128::MAX),
          turbo: true,
          ..default()
        }),
        ..default()
      },
      1,
      Some(
        Inscription {
          content_type: Some("text/plain".into()),
          body: Some("hello".into()),
          rune: Some(rune.commitment()),
          ..default()
        }
        .to_witness(),
      ),
    );

    let entry = RuneEntry {
      block: id.block,
      etching: txid,
      spaced_rune: SpacedRune { rune, spacers: 0 },
      premine: u128::MAX,
      symbol: Some('%'),
      timestamp: id.block,
      turbo: true,
      ..default()
    };

    assert_eq!(server.index.runes().unwrap(), [(id, entry)]);

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])]
    );

    let parent = InscriptionId { txid, index: 0 };

    server.assert_html(
      format!("/rune/{rune}"),
      RuneHtml {
        id,
        entry,
        mintable: false,
        parent: Some(parent),
      },
    );

    server.assert_response_regex(
      format!("/inscription/{parent}"),
      StatusCode::OK,
      ".*
<dl>
  <dt>rune</dt>
  <dd><a href=/rune/AAAAAAAAAAAAA>AAAAAAAAAAAAA</a></dd>
  .*
</dl>
.*",
    );
  }

  #[test]
  fn etched_runes_are_displayed_on_block_page() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    let rune0 = Rune(RUNE);

    let (_txid, id) = server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(rune0),
          ..default()
        }),
        ..default()
      },
      1,
      None,
    );

    assert_eq!(
      server.index.get_runes_in_block(id.block - 1).unwrap().len(),
      0
    );
    assert_eq!(server.index.get_runes_in_block(id.block).unwrap().len(), 1);
    assert_eq!(
      server.index.get_runes_in_block(id.block + 1).unwrap().len(),
      0
    );

    server.assert_response_regex(
      format!("/block/{}", id.block),
      StatusCode::OK,
      format!(".*<h2>1 Rune</h2>.*<li><a href=/rune/{rune0}>{rune0}</a></li>.*"),
    );
  }

  #[test]
  fn runes_are_spaced() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    let (txid, id) = server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(rune),
          symbol: Some('%'),
          spacers: Some(1),
          premine: Some(u128::MAX),
          ..default()
        }),
        ..default()
      },
      1,
      Some(
        Inscription {
          content_type: Some("text/plain".into()),
          body: Some("hello".into()),
          rune: Some(rune.commitment()),
          ..default()
        }
        .to_witness(),
      ),
    );

    pretty_assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          block: id.block,
          etching: txid,
          spaced_rune: SpacedRune { rune, spacers: 1 },
          premine: u128::MAX,
          symbol: Some('%'),
          timestamp: id.block,
          ..default()
        }
      )]
    );

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])]
    );

    server.assert_response_regex(
      format!("/rune/{rune}"),
      StatusCode::OK,
      r".*<title>Rune A•AAAAAAAAAAAA</title>.*<h1>A•AAAAAAAAAAAA</h1>.*",
    );

    server.assert_response_regex(
      format!("/inscription/{txid}i0"),
      StatusCode::OK,
      ".*<dt>rune</dt>.*<dd><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></dd>.*",
    );

    server.assert_response_regex(
      "/runes",
      StatusCode::OK,
      ".*<li><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></li>.*",
    );

    server.assert_response_regex(
      format!("/tx/{txid}"),
      StatusCode::OK,
      ".*
  <dt>etching</dt>
  <dd><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></dd>
.*",
    );

    server.assert_response_regex(
      format!("/output/{txid}:0"),
      StatusCode::OK,
      ".*<tr>
        <td><a href=/rune/A•AAAAAAAAAAAA>A•AAAAAAAAAAAA</a></td>
        <td>340282366920938463463374607431768211455\u{A0}%</td>
      </tr>.*",
    );
  }

  #[test]
  fn transactions_link_to_etching() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    server.assert_response_regex(
      "/runes",
      StatusCode::OK,
      ".*<title>Runes</title>.*<h1>Runes</h1>\n<ul>\n</ul>.*",
    );

    let (txid, id) = server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          premine: Some(u128::MAX),
          ..default()
        }),
        ..default()
      },
      1,
      None,
    );

    pretty_assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          block: id.block,
          etching: txid,
          spaced_rune: SpacedRune {
            rune: Rune(RUNE),
            spacers: 0
          },
          premine: u128::MAX,
          timestamp: id.block,
          ..default()
        }
      )]
    );

    pretty_assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])]
    );

    server.assert_response_regex(
      format!("/tx/{txid}"),
      StatusCode::OK,
      ".*
  <dt>etching</dt>
  <dd><a href=/rune/AAAAAAAAAAAAA>AAAAAAAAAAAAA</a></dd>
.*",
    );
  }

  #[test]
  fn runes_are_displayed_on_output_page() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_runes()
      .build();

    server.mine_blocks(1);

    let rune = Rune(RUNE);

    server.assert_response_regex(format!("/rune/{rune}"), StatusCode::NOT_FOUND, ".*");

    let (txid, id) = server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          divisibility: Some(1),
          rune: Some(rune),
          premine: Some(u128::MAX),
          ..default()
        }),
        ..default()
      },
      1,
      None,
    );

    pretty_assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          block: id.block,
          divisibility: 1,
          etching: txid,
          spaced_rune: SpacedRune { rune, spacers: 0 },
          premine: u128::MAX,
          timestamp: id.block,
          ..default()
        }
      )]
    );

    let output = OutPoint { txid, vout: 0 };

    assert_eq!(
      server.index.get_rune_balances().unwrap(),
      [(output, vec![(id, u128::MAX)])]
    );

    server.assert_response_regex(
      format!("/output/{output}"),
      StatusCode::OK,
      format!(
        ".*<title>Output {output}</title>.*<h1>Output <span class=monospace>{output}</span></h1>.*
  <dt>runes</dt>
  <dd>
    <table>
      <tr>
        <th>rune</th>
        <th>balance</th>
      </tr>
      <tr>
        <td><a href=/rune/AAAAAAAAAAAAA>AAAAAAAAAAAAA</a></td>
        <td>34028236692093846346337460743176821145.5\u{A0}¤</td>
      </tr>
    </table>
  </dd>
.*"
      ),
    );

    let address = default_address(Chain::Regtest);

    pretty_assert_eq!(
      server.get_json::<api::Output>(format!("/output/{output}")),
      api::Output {
        value: 5000000000,
        script_pubkey: address.script_pubkey(),
        address: Some(uncheck(&address)),
        transaction: txid,
        sat_ranges: None,
        indexed: true,
        inscriptions: Some(Vec::new()),
        outpoint: output,
        runes: Some(
          vec![(
            SpacedRune {
              rune: Rune(RUNE),
              spacers: 0
            },
            Pile {
              amount: 340282366920938463463374607431768211455,
              divisibility: 1,
              symbol: None,
            }
          )]
          .into_iter()
          .collect()
        ),
        spent: false,
      }
    );
  }

  #[test]
  fn http_to_https_redirect_with_path() {
    TestServer::builder()
      .redirect_http_to_https()
      .https()
      .build()
      .assert_redirect(
        "/sat/0",
        &format!("https://{}/sat/0", System::host_name().unwrap()),
      );
  }

  #[test]
  fn http_to_https_redirect_with_empty() {
    TestServer::builder()
      .redirect_http_to_https()
      .https()
      .build()
      .assert_redirect("/", &format!("https://{}/", System::host_name().unwrap()));
  }

  #[test]
  fn status() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(3);

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/plain;charset=utf-8", "hello").to_witness(),
      )],
      ..default()
    });

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        2,
        0,
        0,
        inscription("text/plain;charset=utf-8", "hello").to_witness(),
      )],
      ..default()
    });

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        3,
        0,
        0,
        Inscription {
          content_type: None,
          body: Some("hello".as_bytes().into()),
          ..default()
        }
        .to_witness(),
      )],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      "/status",
      StatusCode::OK,
      ".*<h1>Status</h1>
<dl>
  <dt>chain</dt>
  <dd>regtest</dd>
  <dt>height</dt>
  <dd><a href=/block/4>4</a></dd>
  <dt>inscriptions</dt>
  <dd><a href=/inscriptions>3</a></dd>
  <dt>blessed inscriptions</dt>
  <dd>3</dd>
  <dt>cursed inscriptions</dt>
  <dd>0</dd>
  <dt>runes</dt>
  <dd><a href=/runes>0</a></dd>
  <dt>lost sats</dt>
  <dd>.*</dd>
  <dt>started</dt>
  <dd>.*</dd>
  <dt>uptime</dt>
  <dd>.*</dd>
  <dt>minimum rune for next block</dt>
  <dd>.*</dd>
  <dt>version</dt>
  <dd>.*</dd>
  <dt>unrecoverably reorged</dt>
  <dd>false</dd>
  <dt>address index</dt>
  <dd>false</dd>
  <dt>inscription index</dt>
  <dd>true</dd>
  <dt>rune index</dt>
  <dd>false</dd>
  <dt>sat index</dt>
  <dd>false</dd>
  <dt>transaction index</dt>
  <dd>false</dd>
  <dt>json api</dt>
  <dd>true</dd>
  <dt>git branch</dt>
  <dd>.*</dd>
  <dt>git commit</dt>
  <dd>
    <a class=collapse href=https://github.com/ordinals/ord/commit/[[:xdigit:]]{40}>
      [[:xdigit:]]{40}
    </a>
  </dd>
</dl>
.*",
    );
  }

  #[test]
  fn block_count_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockcount");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "1");

    test_server.mine_blocks(1);

    let response = test_server.get("/blockcount");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "2");
  }

  #[test]
  fn block_height_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockheight");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "0");

    test_server.mine_blocks(2);

    let response = test_server.get("/blockheight");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "2");
  }

  #[test]
  fn block_hash_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockhash");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.text().unwrap(),
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
  }

  #[test]
  fn block_hash_from_height_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blockhash/0");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.text().unwrap(),
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
  }

  #[test]
  fn block_time_endpoint() {
    let test_server = TestServer::new();

    let response = test_server.get("/blocktime");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().unwrap(), "1231006505");
  }

  #[test]
  fn sat_number() {
    TestServer::new().assert_response_regex("/sat/0", StatusCode::OK, ".*<h1>Sat 0</h1>.*");
  }

  #[test]
  fn sat_decimal() {
    TestServer::new().assert_response_regex("/sat/0.0", StatusCode::OK, ".*<h1>Sat 0</h1>.*");
  }

  #[test]
  fn sat_degree() {
    TestServer::new().assert_response_regex("/sat/0°0′0″0‴", StatusCode::OK, ".*<h1>Sat 0</h1>.*");
  }

  #[test]
  fn sat_name() {
    TestServer::new().assert_response_regex(
      "/sat/nvtdijuwxlp",
      StatusCode::OK,
      ".*<h1>Sat 0</h1>.*",
    );
  }

  #[test]
  fn sat() {
    TestServer::new().assert_response_regex(
      "/sat/0",
      StatusCode::OK,
      ".*<title>Sat 0</title>.*<h1>Sat 0</h1>.*",
    );
  }

  #[test]
  fn block() {
    TestServer::new().assert_response_regex(
      "/block/0",
      StatusCode::OK,
      ".*<title>Block 0</title>.*<h1>Block 0</h1>.*",
    );
  }

  #[test]
  fn sat_out_of_range() {
    TestServer::new().assert_response(
      "/sat/2099999997690000",
      StatusCode::BAD_REQUEST,
      "Invalid URL: failed to parse sat `2099999997690000`: invalid integer range",
    );
  }

  #[test]
  fn invalid_outpoint_hash_returns_400() {
    TestServer::new().assert_response(
      "/output/foo:0",
      StatusCode::BAD_REQUEST,
      "Invalid URL: Cannot parse `output` with value `foo:0`: error parsing TXID",
    );
  }

  #[test]
  fn output_with_sat_index() {
    let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    TestServer::builder()
      .index_sats()
      .build()
      .assert_response_regex(
        format!("/output/{txid}:0"),
        StatusCode::OK,
        format!(
          ".*<title>Output {txid}:0</title>.*<h1>Output <span class=monospace>{txid}:0</span></h1>
<dl>
  <dt>value</dt><dd>5000000000</dd>
  <dt>script pubkey</dt><dd class=monospace>OP_PUSHBYTES_65 [[:xdigit:]]{{130}} OP_CHECKSIG</dd>
  <dt>transaction</dt><dd><a class=collapse href=/tx/{txid}>{txid}</a></dd>
  <dt>spent</dt><dd>false</dd>
</dl>
<h2>1 Sat Range</h2>
<ul class=monospace>
  <li><a href=/sat/0 class=mythic>0</a>-<a href=/sat/4999999999 class=common>4999999999</a> \\(5000000000 sats\\)</li>
</ul>.*"
        ),
      );
  }

  #[test]
  fn output_without_sat_index() {
    let txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    TestServer::new().assert_response_regex(
      format!("/output/{txid}:0"),
      StatusCode::OK,
      format!(
        ".*<title>Output {txid}:0</title>.*<h1>Output <span class=monospace>{txid}:0</span></h1>
<dl>
  <dt>value</dt><dd>5000000000</dd>
  <dt>script pubkey</dt><dd class=monospace>OP_PUSHBYTES_65 [[:xdigit:]]{{130}} OP_CHECKSIG</dd>
  <dt>transaction</dt><dd><a class=collapse href=/tx/{txid}>{txid}</a></dd>
  <dt>spent</dt><dd>false</dd>
</dl>.*"
      ),
    );
  }

  #[test]
  fn null_output_receives_lost_sats() {
    let server = TestServer::builder().index_sats().build();

    server.mine_blocks_with_subsidy(1, 0);

    let txid = "0000000000000000000000000000000000000000000000000000000000000000";

    server.assert_response_regex(
      format!("/output/{txid}:4294967295"),
      StatusCode::OK,
      format!(
        ".*<title>Output {txid}:4294967295</title>.*<h1>Output <span class=monospace>{txid}:4294967295</span></h1>
<dl>
  <dt>value</dt><dd>5000000000</dd>
  <dt>script pubkey</dt><dd class=monospace></dd>
  <dt>transaction</dt><dd><a class=collapse href=/tx/{txid}>{txid}</a></dd>
  <dt>spent</dt><dd>false</dd>
</dl>
<h2>1 Sat Range</h2>
<ul class=monospace>
  <li><a href=/sat/5000000000 class=uncommon>5000000000</a>-<a href=/sat/9999999999 class=common>9999999999</a> \\(5000000000 sats\\)</li>
</ul>.*"
      ),
    );
  }

  #[test]
  fn unbound_output_receives_unbound_inscriptions() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    server.mine_blocks(1);

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      fee: 50 * 100_000_000,
      ..default()
    });

    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        2,
        1,
        0,
        inscription("text/plain;charset=utf-8", "hello").to_witness(),
      )],
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{}", inscription_id),
      StatusCode::OK,
      format!(
        ".*<dl>
  <dt>id</dt>
  <dd class=collapse>{inscription_id}</dd>.*<dt>output</dt>
  <dd><a class=collapse href=/output/0000000000000000000000000000000000000000000000000000000000000000:0>0000000000000000000000000000000000000000000000000000000000000000:0</a></dd>.*"
      ),
    );

    server.assert_response_regex(
      "/output/0000000000000000000000000000000000000000000000000000000000000000:0",
      StatusCode::OK,
      ".*<h1>Output <span class=monospace>0000000000000000000000000000000000000000000000000000000000000000:0</span></h1>
<dl>
  <dt>inscriptions</dt>
  <dd class=thumbnails>
    <a href=/inscription/.*><iframe sandbox=allow-scripts scrolling=no loading=lazy src=/preview/.*></iframe></a>
  </dd>.*",
    );
  }

  #[test]
  fn unbound_output_returns_200() {
    TestServer::new().assert_response_regex(
      "/output/0000000000000000000000000000000000000000000000000000000000000000:0",
      StatusCode::OK,
      ".*",
    );
  }

  #[test]
  fn invalid_output_returns_400() {
    TestServer::new().assert_response(
      "/output/foo:0",
      StatusCode::BAD_REQUEST,
      "Invalid URL: Cannot parse `output` with value `foo:0`: error parsing TXID",
    );
  }

  #[test]
  fn home() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let mut ids = Vec::new();

    for i in 0..101 {
      let txid = server.core.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("image/png", "hello").to_witness())],
        ..default()
      });
      ids.push(InscriptionId { txid, index: 0 });
      server.mine_blocks(1);
    }

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(102, 0, 0, inscription("text/plain", "{}").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      "/",
      StatusCode::OK,
      format!(
        r".*<title>Ordinals</title>.*
<h1>Latest Inscriptions</h1>
<div class=thumbnails>
  <a href=/inscription/{}>.*</a>
  (<a href=/inscription/[[:xdigit:]]{{64}}i0>.*</a>\s*){{99}}
</div>
.*
",
        ids[100]
      ),
    );
  }

  #[test]
  fn blocks() {
    let test_server = TestServer::new();

    test_server.mine_blocks(1);

    test_server.assert_response_regex(
      "/blocks",
      StatusCode::OK,
      ".*<title>Blocks</title>.*
<h1>Blocks</h1>
<div class=block>
  <h2><a href=/block/1>Block 1</a></h2>
  <div class=thumbnails>
  </div>
</div>
<div class=block>
  <h2><a href=/block/0>Block 0</a></h2>
  <div class=thumbnails>
  </div>
</div>
</ol>.*",
    );
  }

  #[test]
  fn nav_displays_chain() {
    TestServer::builder()
      .chain(Chain::Regtest)
      .build()
      .assert_response_regex(
        "/",
        StatusCode::OK,
        ".*<a href=/ title=home>Ordinals<sup>regtest</sup></a>.*",
      );
  }

  #[test]
  fn blocks_block_limit() {
    let test_server = TestServer::new();

    test_server.mine_blocks(101);

    test_server.assert_response_regex(
      "/blocks",
      StatusCode::OK,
      ".*<ol start=96 reversed class=block-list>\n(  <li><a class=collapse href=/block/[[:xdigit:]]{64}>[[:xdigit:]]{64}</a></li>\n){95}</ol>.*"
    );
  }

  #[test]
  fn block_not_found() {
    TestServer::new().assert_response(
      "/block/467a86f0642b1d284376d13a98ef58310caa49502b0f9a560ee222e0a122fe16",
      StatusCode::NOT_FOUND,
      "block 467a86f0642b1d284376d13a98ef58310caa49502b0f9a560ee222e0a122fe16 not found",
    );
  }

  #[test]
  fn unmined_sat() {
    TestServer::new().assert_response_regex(
      "/sat/0",
      StatusCode::OK,
      ".*<dt>timestamp</dt><dd><time>2009-01-03 18:15:05 UTC</time></dd>.*",
    );
  }

  #[test]
  fn mined_sat() {
    TestServer::new().assert_response_regex(
      "/sat/5000000000",
      StatusCode::OK,
      ".*<dt>timestamp</dt><dd><time>.*</time> \\(expected\\)</dd>.*",
    );
  }

  #[test]
  fn static_asset() {
    TestServer::new().assert_response_regex(
      "/static/index.css",
      StatusCode::OK,
      r".*\.rare \{
  background-color: var\(--rare\);
}.*",
    );
  }

  #[test]
  fn favicon() {
    TestServer::new().assert_response_regex("/favicon.ico", StatusCode::OK, r".*");
  }

  #[test]
  fn clock_updates() {
    let test_server = TestServer::new();
    test_server.assert_response_regex("/clock", StatusCode::OK, ".*<text.*>0</text>.*");
    test_server.mine_blocks(1);
    test_server.assert_response_regex("/clock", StatusCode::OK, ".*<text.*>1</text>.*");
  }

  #[test]
  fn block_by_hash() {
    let test_server = TestServer::new();

    test_server.mine_blocks(1);
    let transaction = TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      fee: 0,
      ..default()
    };
    test_server.core.broadcast_tx(transaction);
    let block_hash = test_server.mine_blocks(1)[0].block_hash();

    test_server.assert_response_regex(
      format!("/block/{block_hash}"),
      StatusCode::OK,
      ".*<h1>Block 2</h1>.*",
    );
  }

  #[test]
  fn block_by_height() {
    let test_server = TestServer::new();

    test_server.assert_response_regex("/block/0", StatusCode::OK, ".*<h1>Block 0</h1>.*");
  }

  #[test]
  fn transaction() {
    let test_server = TestServer::new();

    let coinbase_tx = test_server.mine_blocks(1)[0].txdata[0].clone();
    let txid = coinbase_tx.compute_txid();

    test_server.assert_response_regex(
      format!("/tx/{txid}"),
      StatusCode::OK,
      format!(
        ".*<title>Transaction {txid}</title>.*<h1>Transaction <span class=monospace>{txid}</span></h1>
<dl>
</dl>
<h2>1 Input</h2>
<ul>
  <li><a class=collapse href=/output/0000000000000000000000000000000000000000000000000000000000000000:4294967295>0000000000000000000000000000000000000000000000000000000000000000:4294967295</a></li>
</ul>
<h2>1 Output</h2>
<ul class=monospace>
  <li>
    <a href=/output/{txid}:0 class=collapse>
      {txid}:0
    </a>
    <dl>
      <dt>value</dt><dd>5000000000</dd>
      <dt>script pubkey</dt><dd class=monospace>.*</dd>
    </dl>
  </li>
</ul>.*"
      ),
    );
  }

  #[test]
  fn recursive_transaction_hex_endpoint() {
    let test_server = TestServer::new();

    let coinbase_tx = test_server.mine_blocks(1)[0].txdata[0].clone();
    let txid = coinbase_tx.compute_txid();

    test_server.assert_response(
      format!("/r/tx/{txid}"),
      StatusCode::OK,
      "\"02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0151ffffffff0100f2052a01000000225120be7cbbe9ca06a7d7b2a17c6b4ff4b85b362cbcd7ee1970daa66dfaa834df59a000000000\""
    );
  }

  #[test]
  fn recursive_transaction_hex_endpoint_for_genesis_transaction() {
    let test_server = TestServer::new();

    test_server.mine_blocks(1);

    test_server.assert_response(
      "/r/tx/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
      StatusCode::OK,
      "\"01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000\""
    );
  }

  #[test]
  fn detect_unrecoverable_reorg() {
    let test_server = TestServer::new();

    test_server.mine_blocks(21);

    test_server.assert_response_regex(
      "/status",
      StatusCode::OK,
      ".*<dt>unrecoverably reorged</dt>\n  <dd>false</dd>.*",
    );

    for _ in 0..15 {
      test_server.core.invalidate_tip();
    }

    test_server.core.mine_blocks(21);

    test_server.assert_response_regex(
      "/status",
      StatusCode::OK,
      ".*<dt>unrecoverably reorged</dt>\n  <dd>true</dd>.*",
    );
  }

  #[test]
  fn rare_with_sat_index() {
    TestServer::builder().index_sats().build().assert_response(
      "/rare.txt",
      StatusCode::OK,
      "sat\tsatpoint
0\t4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0
",
    );
  }

  #[test]
  fn rare_without_sat_index() {
    TestServer::new().assert_response(
      "/rare.txt",
      StatusCode::OK,
      "sat\tsatpoint
",
    );
  }

  #[test]
  fn show_rare_txt_in_header_with_sat_index() {
    TestServer::builder()
      .index_sats()
      .build()
      .assert_response_regex(
        "/",
        StatusCode::OK,
        ".*
      <a href=/clock title=clock>.*</a>
      <a href=/rare.txt title=rare>.*</a>.*",
      );
  }

  #[test]
  fn rare_sat_location() {
    TestServer::builder()
      .index_sats()
      .build()
      .assert_response_regex(
        "/sat/0",
        StatusCode::OK,
        ".*>4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0<.*",
      );
  }

  #[test]
  fn dont_show_rare_txt_in_header_without_sat_index() {
    TestServer::new().assert_response_regex(
      "/",
      StatusCode::OK,
      ".*
      <a href=/clock title=clock>.*</a>
      <a href=https://docs.ordinals.com/.*",
    );
  }

  #[test]
  fn input() {
    TestServer::new().assert_response_regex(
      "/input/0/0/0",
      StatusCode::OK,
      ".*<title>Input /0/0/0</title>.*<h1>Input /0/0/0</h1>.*<dt>text</dt><dd>.*The Times 03/Jan/2009 Chancellor on brink of second bailout for banks</dd>.*",
    );
  }

  #[test]
  fn input_missing() {
    TestServer::new().assert_response(
      "/input/1/1/1",
      StatusCode::NOT_FOUND,
      "input /1/1/1 not found",
    );
  }

  #[test]
  fn commits_are_tracked() {
    let server = TestServer::new();

    thread::sleep(Duration::from_millis(100));
    assert_eq!(server.index.statistic(crate::index::Statistic::Commits), 1);

    let info = server.index.info().unwrap();
    assert_eq!(info.transactions.len(), 1);
    assert_eq!(info.transactions[0].starting_block_count, 0);

    server.index.update().unwrap();

    assert_eq!(server.index.statistic(crate::index::Statistic::Commits), 1);

    let info = server.index.info().unwrap();
    assert_eq!(info.transactions.len(), 1);
    assert_eq!(info.transactions[0].starting_block_count, 0);

    server.mine_blocks(1);

    thread::sleep(Duration::from_millis(10));
    server.index.update().unwrap();

    assert_eq!(server.index.statistic(crate::index::Statistic::Commits), 2);

    let info = server.index.info().unwrap();
    assert_eq!(info.transactions.len(), 2);
    assert_eq!(info.transactions[0].starting_block_count, 0);
    assert_eq!(info.transactions[1].starting_block_count, 1);
    assert!(
      info.transactions[1].starting_timestamp - info.transactions[0].starting_timestamp >= 10
    );
  }

  #[test]
  fn outputs_traversed_are_tracked() {
    let server = TestServer::builder().index_sats().build();

    assert_eq!(
      server
        .index
        .statistic(crate::index::Statistic::OutputsTraversed),
      1
    );

    server.index.update().unwrap();

    assert_eq!(
      server
        .index
        .statistic(crate::index::Statistic::OutputsTraversed),
      1
    );

    server.mine_blocks(2);

    server.index.update().unwrap();

    assert_eq!(
      server
        .index
        .statistic(crate::index::Statistic::OutputsTraversed),
      3
    );
  }

  #[test]
  fn coinbase_sat_ranges_are_tracked() {
    let server = TestServer::builder().index_sats().build();

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      1
    );

    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      2
    );

    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      3
    );
  }

  #[test]
  fn split_sat_ranges_are_tracked() {
    let server = TestServer::builder().index_sats().build();

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      1
    );

    server.mine_blocks(1);
    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      outputs: 2,
      fee: 0,
      ..default()
    });
    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      4,
    );
  }

  #[test]
  fn fee_sat_ranges_are_tracked() {
    let server = TestServer::builder().index_sats().build();

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      1
    );

    server.mine_blocks(1);
    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Default::default())],
      outputs: 2,
      fee: 2,
      ..default()
    });
    server.mine_blocks(1);

    assert_eq!(
      server.index.statistic(crate::index::Statistic::SatRanges),
      5,
    );
  }

  #[test]
  fn content_response_no_content() {
    assert_eq!(
      r::content_response(
        Inscription {
          content_type: Some("text/plain".as_bytes().to_vec()),
          body: None,
          ..default()
        },
        AcceptEncoding::default(),
        &ServerConfig::default(),
      )
      .unwrap(),
      None
    );
  }

  #[test]
  fn content_response_with_content() {
    let (headers, body) = r::content_response(
      Inscription {
        content_type: Some("text/plain".as_bytes().to_vec()),
        body: Some(vec![1, 2, 3]),
        ..default()
      },
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-type"], "text/plain");
    assert_eq!(body, vec![1, 2, 3]);
  }

  #[test]
  fn content_security_policy_no_origin() {
    let (headers, _) = r::content_response(
      Inscription {
        content_type: Some("text/plain".as_bytes().to_vec()),
        body: Some(vec![1, 2, 3]),
        ..default()
      },
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(
      headers["content-security-policy"],
      HeaderValue::from_static("default-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:")
    );
  }

  #[test]
  fn content_security_policy_with_origin() {
    let (headers, _) = r::content_response(
      Inscription {
        content_type: Some("text/plain".as_bytes().to_vec()),
        body: Some(vec![1, 2, 3]),
        ..default()
      },
      AcceptEncoding::default(),
      &ServerConfig {
        csp_origin: Some("https://ordinals.com".into()),
        ..default()
      },
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-security-policy"], HeaderValue::from_static("default-src https://ordinals.com/content/ https://ordinals.com/blockheight https://ordinals.com/blockhash https://ordinals.com/blockhash/ https://ordinals.com/blocktime https://ordinals.com/r/ 'unsafe-eval' 'unsafe-inline' data: blob:"));
  }

  #[test]
  fn preview_content_security_policy() {
    {
      let server = TestServer::builder().chain(Chain::Regtest).build();

      server.mine_blocks(1);

      let txid = server.core.broadcast_tx(TransactionTemplate {
        inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
        ..default()
      });

      server.mine_blocks(1);

      let inscription_id = InscriptionId { txid, index: 0 };

      server.assert_response_csp(
        format!("/preview/{}", inscription_id),
        StatusCode::OK,
        "default-src 'self'",
        format!(".*<html lang=en data-inscription={}>.*", inscription_id),
      );
    }

    {
      let server = TestServer::builder()
        .chain(Chain::Regtest)
        .server_option("--csp-origin", "https://ordinals.com")
        .build();

      server.mine_blocks(1);

      let txid = server.core.broadcast_tx(TransactionTemplate {
        inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
        ..default()
      });

      server.mine_blocks(1);

      let inscription_id = InscriptionId { txid, index: 0 };

      server.assert_response_csp(
        format!("/preview/{}", inscription_id),
        StatusCode::OK,
        "default-src https://ordinals.com",
        format!(".*<html lang=en data-inscription={}>.*", inscription_id),
      );
    }
  }

  #[test]
  fn code_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/javascript", "hello").to_witness(),
      )],
      ..default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<html lang=en data-inscription={inscription_id} data-language=javascript>.*"),
    );
  }

  #[test]
  fn content_response_no_content_type() {
    let (headers, body) = r::content_response(
      Inscription {
        content_type: None,
        body: Some(Vec::new()),
        ..default()
      },
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-type"], "application/octet-stream");
    assert!(body.is_empty());
  }

  #[test]
  fn content_response_bad_content_type() {
    let (headers, body) = r::content_response(
      Inscription {
        content_type: Some("\n".as_bytes().to_vec()),
        body: Some(Vec::new()),
        ..Default::default()
      },
      AcceptEncoding::default(),
      &ServerConfig::default(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(headers["content-type"], "application/octet-stream");
    assert!(body.is_empty());
  }

  #[test]
  fn text_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/plain;charset=utf-8", "hello").to_witness(),
      )],
      ..default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{}", inscription_id),
      StatusCode::OK,
      "default-src 'self'",
      format!(".*<html lang=en data-inscription={}>.*", inscription_id),
    );
  }

  #[test]
  fn audio_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("audio/flac", "hello").to_witness())],
      ..default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<audio .*>\s*<source src=/content/{inscription_id}>.*"),
    );
  }

  #[test]
  fn font_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("font/ttf", "hello").to_witness())],
      ..default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*src: url\(/content/{inscription_id}\).*"),
    );
  }

  #[test]
  fn pdf_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("application/pdf", "hello").to_witness(),
      )],
      ..default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<canvas data-inscription={inscription_id}></canvas>.*"),
    );
  }

  #[test]
  fn markdown_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/markdown", "hello").to_witness())],
      ..default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<html lang=en data-inscription={inscription_id}>.*"),
    );
  }

  #[test]
  fn image_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("image/png", "hello").to_witness())],
      ..default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      "default-src 'self' 'unsafe-inline'",
      format!(r".*background-image: url\(/content/{inscription_id}\);.*"),
    );
  }

  #[test]
  fn iframe_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/html;charset=utf-8", "hello").to_witness(),
      )],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      "default-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:",
      "hello",
    );
  }

  #[test]
  fn unknown_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_csp(
      format!("/preview/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      "default-src 'self'",
      fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );
  }

  #[test]
  fn video_preview() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("video/webm", "hello").to_witness())],
      ..default()
    });
    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      format!(r".*<video .*>\s*<source src=/content/{inscription_id}>.*"),
    );
  }

  #[test]
  fn inscription_page_title() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      ".*<title>Inscription 0</title>.*",
    );
  }

  #[test]
  fn inscription_page_has_sat_when_sats_are_tracked() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      r".*<dt>sat</dt>\s*<dd><a href=/sat/5000000000>5000000000</a></dd>\s*<dt>sat name</dt>\s*<dd><a href=/sat/nvtcsezkbth>nvtcsezkbth</a></dd>\s*<dt>preview</dt>.*",
    );
  }

  #[test]
  fn inscriptions_can_be_looked_up_by_sat_name() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();
    server.mine_blocks(1);

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{}", Sat(5000000000).name()),
      StatusCode::OK,
      ".*<title>Inscription 0</title.*",
    );
  }

  #[test]
  fn inscriptions_can_be_looked_up_by_sat_name_with_letter_i() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();
    server.assert_response_regex("/inscription/i", StatusCode::NOT_FOUND, ".*");
  }

  #[test]
  fn inscription_page_does_not_have_sat_when_sats_are_not_tracked() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{}", InscriptionId { txid, index: 0 }),
      StatusCode::OK,
      r".*<dt>value</dt>\s*<dd>5000000000</dd>\s*<dt>preview</dt>.*",
    );
  }

  #[test]
  fn strict_transport_security_header_is_set() {
    assert_eq!(
      TestServer::new()
        .get("/status")
        .headers()
        .get(header::STRICT_TRANSPORT_SECURITY)
        .unwrap(),
      "max-age=31536000; includeSubDomains; preload",
    );
  }

  #[test]
  fn feed() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();
    server.mine_blocks(1);

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      "/feed.xml",
      StatusCode::OK,
      ".*<title>Inscription 0</title>.*",
    );
  }

  #[test]
  fn inscription_with_unknown_type_and_no_body_has_unknown_preview() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        Inscription {
          content_type: Some("foo/bar".as_bytes().to_vec()),
          body: None,
          ..default()
        }
        .to_witness(),
      )],
      ..default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      &fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );
  }

  #[test]
  fn inscription_with_known_type_and_no_body_has_unknown_preview() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        Inscription {
          content_type: Some("image/png".as_bytes().to_vec()),
          body: None,
          ..default()
        }
        .to_witness(),
      )],
      ..default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response(
      format!("/preview/{inscription_id}"),
      StatusCode::OK,
      &fs::read_to_string("templates/preview-unknown.html").unwrap(),
    );
  }

  #[test]
  fn content_responses_have_cache_control_headers() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let response = server.get(format!("/content/{}", InscriptionId { txid, index: 0 }));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.headers().get(header::CACHE_CONTROL).unwrap(),
      "public, max-age=1209600, immutable"
    );
  }

  #[test]
  fn error_content_responses_have_max_age_zero_cache_control_headers() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    let response =
      server.get("/content/6ac5cacb768794f4fd7a78bf00f2074891fce68bd65c4ff36e77177237aacacai0");

    assert_eq!(response.status(), 404);
    assert_eq!(
      response.headers().get(header::CACHE_CONTROL).unwrap(),
      "no-store"
    );
  }

  #[test]
  fn inscriptions_page_with_no_prev_or_next() {
    TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build()
      .assert_response_regex("/inscriptions", StatusCode::OK, ".*prev\nnext.*");
  }

  #[test]
  fn inscriptions_page_with_no_next() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    for i in 0..101 {
      server.mine_blocks(1);
      server.core.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("text/foo", "hello").to_witness())],
        ..default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/inscriptions/1",
      StatusCode::OK,
      ".*<a class=prev href=/inscriptions/0>prev</a>\nnext.*",
    );
  }

  #[test]
  fn inscriptions_page_with_no_prev() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    for i in 0..101 {
      server.mine_blocks(1);
      server.core.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("text/foo", "hello").to_witness())],
        ..default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/inscriptions/0",
      StatusCode::OK,
      ".*prev\n<a class=next href=/inscriptions/1>next</a>.*",
    );
  }

  #[test]
  fn collections_page_prev_and_next() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    let mut parent_ids = Vec::new();

    for i in 0..101 {
      server.mine_blocks(1);

      parent_ids.push(InscriptionId {
        txid: server.core.broadcast_tx(TransactionTemplate {
          inputs: &[(i + 1, 0, 0, inscription("text/plain", "hello").to_witness())],
          ..default()
        }),
        index: 0,
      });
    }

    for (i, parent_id) in parent_ids.iter().enumerate().take(101) {
      server.mine_blocks(1);

      server.core.broadcast_tx(TransactionTemplate {
        inputs: &[
          (i + 2, 1, 0, Default::default()),
          (
            i + 102,
            0,
            0,
            Inscription {
              content_type: Some("text/plain".into()),
              body: Some("hello".into()),
              parents: vec![parent_id.value()],
              ..default()
            }
            .to_witness(),
          ),
        ],
        outputs: 2,
        output_values: &[50 * COIN_VALUE, 50 * COIN_VALUE],
        ..default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/collections",
      StatusCode::OK,
      r".*
<h1>Collections</h1>
<div class=thumbnails>
  <a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>
  (<a href=/inscription/[[:xdigit:]]{64}i0>.*</a>\s*){99}
</div>
<div class=center>
prev
<a class=next href=/collections/1>next</a>
</div>.*"
        .to_string()
        .unindent(),
    );

    server.assert_response_regex(
      "/collections/1",
      StatusCode::OK,
      ".*
<h1>Collections</h1>
<div class=thumbnails>
  <a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>
</div>
<div class=center>
<a class=prev href=/collections/0>prev</a>
next
</div>.*"
        .unindent(),
    );
  }

  #[test]
  fn responses_are_gzipped() {
    let server = TestServer::new();

    let mut headers = HeaderMap::new();

    headers.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

    let response = reqwest::blocking::Client::builder()
      .default_headers(headers)
      .build()
      .unwrap()
      .get(server.join_url("/"))
      .send()
      .unwrap();

    assert_eq!(
      response.headers().get(header::CONTENT_ENCODING).unwrap(),
      "gzip"
    );
  }

  #[test]
  fn responses_are_brotlied() {
    let server = TestServer::new();

    let mut headers = HeaderMap::new();

    headers.insert(header::ACCEPT_ENCODING, "br".parse().unwrap());

    let response = reqwest::blocking::Client::builder()
      .default_headers(headers)
      .brotli(false)
      .build()
      .unwrap()
      .get(server.join_url("/"))
      .send()
      .unwrap();

    assert_eq!(
      response.headers().get(header::CONTENT_ENCODING).unwrap(),
      "br"
    );
  }

  #[test]
  fn inscription_links_to_parent() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let parent_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          2,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (2, 1, 0, Default::default()),
      ],
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription 1</title>.*<dt>parents</dt>.*<div class=thumbnails>.**<a href=/inscription/{parent_inscription_id}><iframe .* src=/preview/{parent_inscription_id}></iframe></a>.*"),
    );
    server.assert_response_regex(
      format!("/inscription/{parent_inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription 0</title>.*<dt>children</dt>.*<a href=/inscription/{inscription_id}>.*</a>.*"),
    );

    assert_eq!(
      server
        .get_json::<api::Inscription>(format!("/inscription/{inscription_id}"))
        .parents,
      vec![parent_inscription_id],
    );

    assert_eq!(
      server
        .get_json::<api::Inscription>(format!("/inscription/{parent_inscription_id}"))
        .children,
      [inscription_id],
    );
  }

  #[test]
  fn inscription_with_and_without_children_page() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let parent_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    server.assert_response_regex(
      format!("/children/{parent_inscription_id}"),
      StatusCode::OK,
      ".*<h3>No children</h3>.*",
    );

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          2,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (2, 1, 0, Default::default()),
      ],
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/children/{parent_inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription 0 Children</title>.*<h1><a href=/inscription/{parent_inscription_id}>Inscription 0</a> Children</h1>.*<div class=thumbnails>.*<a href=/inscription/{inscription_id}><iframe .* src=/preview/{inscription_id}></iframe></a>.*"),
    );
  }

  #[test]
  fn inscriptions_page_shows_max_four_children() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let parent_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(6);

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    let _txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          2,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (
          3,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (
          4,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (
          5,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (
          6,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (2, 1, 0, Default::default()),
      ],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{parent_inscription_id}"),
      StatusCode::OK,
      format!(
        ".*<title>Inscription 0</title>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*
    <div class=center>
      <a href=/children/{parent_inscription_id}>all \\(5\\)</a>
    </div>.*"
      ),
    );
  }

  #[test]
  fn inscription_child() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let parent_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(2);

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    let child_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          2,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (
          3,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![parent_inscription_id.value()],
            ..default()
          }
          .to_witness(),
        ),
        (2, 1, 0, Default::default()),
      ],
      ..default()
    });

    server.mine_blocks(1);

    let child0 = InscriptionId {
      txid: child_txid,
      index: 0,
    };

    server.assert_response_regex(
      format!("/inscription/{parent_inscription_id}/0"),
      StatusCode::OK,
      format!(
        ".*<title>Inscription 1</title>.*
.*<dt>id</dt>
.*<dd class=collapse>{child0}</dd>.*"
      ),
    );

    let child1 = InscriptionId {
      txid: child_txid,
      index: 1,
    };

    server.assert_response_regex(
      format!("/inscription/{parent_inscription_id}/1"),
      StatusCode::OK,
      format!(
        ".*<title>Inscription -1</title>.*
.*<dt>id</dt>
.*<dd class=collapse>{child1}</dd>.*"
      ),
    );
  }

  #[test]
  fn inscription_with_parent_page() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(2);

    let parent_a_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    let parent_b_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let parent_a_inscription_id = InscriptionId {
      txid: parent_a_txid,
      index: 0,
    };

    let parent_b_inscription_id = InscriptionId {
      txid: parent_b_txid,
      index: 0,
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (
          3,
          0,
          0,
          Inscription {
            content_type: Some("text/plain".into()),
            body: Some("hello".into()),
            parents: vec![
              parent_a_inscription_id.value(),
              parent_b_inscription_id.value(),
            ],
            ..default()
          }
          .to_witness(),
        ),
        (3, 1, 0, Default::default()),
        (3, 2, 0, Default::default()),
      ],
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/parents/{inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription -1 Parents</title>.*<h1><a href=/inscription/{inscription_id}>Inscription -1</a> Parents</h1>.*<div class=thumbnails>.*<a href=/inscription/{parent_a_inscription_id}><iframe .* src=/preview/{parent_b_inscription_id}></iframe></a>.*"),
    );
  }

  #[test]
  fn inscription_parent_page_pagination() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let mut parent_ids = Vec::new();
    let mut inputs = Vec::new();
    for i in 0..101 {
      parent_ids.push(
        InscriptionId {
          txid: server.core.broadcast_tx(TransactionTemplate {
            inputs: &[(i + 1, 0, 0, inscription("text/plain", "hello").to_witness())],
            ..default()
          }),
          index: 0,
        }
        .value(),
      );

      inputs.push((i + 2, 1, 0, Witness::default()));

      server.mine_blocks(1);
    }

    inputs.insert(
      0,
      (
        102,
        0,
        0,
        Inscription {
          content_type: Some("text/plain".into()),
          body: Some("hello".into()),
          parents: parent_ids,
          ..default()
        }
        .to_witness(),
      ),
    );

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &inputs,
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/parents/{inscription_id}"),
      StatusCode::OK,
      format!(".*<title>Inscription -1 Parents</title>.*<h1><a href=/inscription/{inscription_id}>Inscription -1</a> Parents</h1>.*<div class=thumbnails>(.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*){{100}}.*"),
    );

    server.assert_response_regex(
      format!("/parents/{inscription_id}/1"),
      StatusCode::OK,
      format!(".*<title>Inscription -1 Parents</title>.*<h1><a href=/inscription/{inscription_id}>Inscription -1</a> Parents</h1>.*<div class=thumbnails>(.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*){{1}}.*"),
    );

    server.assert_response_regex(
      format!("/inscription/{inscription_id}"),
      StatusCode::OK,
      ".*<title>Inscription -1</title>.*<h1>Inscription -1</h1>.*<div class=thumbnails>(.*<a href=/inscription/.*><iframe .* src=/preview/.*></iframe></a>.*){4}.*",
    );
  }

  #[test]
  fn inscription_number_endpoint() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(2);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (1, 0, 0, inscription("text/plain", "hello").to_witness()),
        (2, 0, 0, inscription("text/plain", "cursed").to_witness()),
      ],
      outputs: 2,
      ..default()
    });

    let inscription_id = InscriptionId { txid, index: 0 };
    let cursed_inscription_id = InscriptionId { txid, index: 1 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{inscription_id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{inscription_id}</dd>.*"
      ),
    );
    server.assert_response_regex(
      "/inscription/0",
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{inscription_id}</dd>.*"
      ),
    );

    server.assert_response_regex(
      "/inscription/-1",
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{cursed_inscription_id}</dd>.*"
      ),
    )
  }

  #[test]
  fn charm_cursed() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(2);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (1, 0, 0, Witness::default()),
        (2, 0, 0, inscription("text/plain", "cursed").to_witness()),
      ],
      outputs: 2,
      ..default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=cursed>👹</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_vindicated() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(110);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (1, 0, 0, Witness::default()),
        (2, 0, 0, inscription("text/plain", "cursed").to_witness()),
      ],
      outputs: 2,
      ..default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  .*
  <dt>value</dt>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_coin() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    server.mine_blocks(2);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  <dt>charms</dt>
  <dd>.*<span title=coin>🪙</span>.*</dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_uncommon() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    server.mine_blocks(2);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  <dt>charms</dt>
  <dd>.*<span title=uncommon>🌱</span>.*</dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_nineball() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    server.mine_blocks(9);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(9, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  <dt>charms</dt>
  <dd>.*<span title=nineball>9️⃣</span>.*</dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_reinscription() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 1, 0, inscription("text/plain", "bar").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_reinscription_in_same_tx_input() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"foo")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"bar")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice([1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice([])
      .push_slice(b"qix")
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    let witness = Witness::from_slice(&[script.into_bytes(), Vec::new()]);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, witness)],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  .*
  <dt>value</dt>
  .*
</dl>
.*
"
      ),
    );

    let id = InscriptionId { txid, index: 1 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>.*",
    );

    let id = InscriptionId { txid, index: 2 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>.*",
    );
  }

  #[test]
  fn charm_reinscription_in_same_tx_with_pointer() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(3);

    let cursed_inscription = inscription("text/plain", "bar");
    let reinscription: Inscription = InscriptionTemplate {
      pointer: Some(0),
      ..default()
    }
    .into();

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (1, 0, 0, inscription("text/plain", "foo").to_witness()),
        (2, 0, 0, cursed_inscription.to_witness()),
        (3, 0, 0, reinscription.to_witness()),
      ],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  .*
  <dt>value</dt>
  .*
</dl>
.*
"
      ),
    );

    let id = InscriptionId { txid, index: 1 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=cursed>👹</span>.*",
    );

    let id = InscriptionId { txid, index: 2 };
    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      ".*
    <span title=reinscription>♻️</span>
    <span title=cursed>👹</span>.*",
    );
  }

  #[test]
  fn charm_unbound() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, envelope(&[b"ord", &[128], &[0]]))],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription -1</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=cursed>👹</span>
    <span title=unbound>🔓</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn charm_lost() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..default()
    });

    let id = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  .*
  <dt>value</dt>
  <dd>5000000000</dd>
  .*
</dl>
.*
"
      ),
    );

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 1, 0, Default::default())],
      fee: 50 * COIN_VALUE,
      ..default()
    });

    server.mine_blocks_with_subsidy(1, 0);

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 0</h1>.*
<dl>
  <dt>id</dt>
  <dd class=collapse>{id}</dd>
  <dt>charms</dt>
  <dd>
    <span title=lost>🤔</span>
  </dd>
  .*
</dl>
.*
"
      ),
    );
  }

  #[test]
  fn utxo_recursive_endpoint_all() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .index_runes()
      .build();

    let rune = Rune(RUNE);

    let (txid, id) = server.etch(
      Runestone {
        edicts: vec![Edict {
          id: RuneId::default(),
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          divisibility: Some(1),
          rune: Some(rune),
          premine: Some(u128::MAX),
          ..default()
        }),
        ..default()
      },
      1,
      None,
    );

    pretty_assert_eq!(
      server.index.runes().unwrap(),
      [(
        id,
        RuneEntry {
          block: id.block,
          divisibility: 1,
          etching: txid,
          spaced_rune: SpacedRune { rune, spacers: 0 },
          premine: u128::MAX,
          timestamp: id.block,
          ..default()
        }
      )]
    );

    server.mine_blocks(1);

    // merge rune with two inscriptions
    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[
        (6, 0, 0, inscription("text/plain", "foo").to_witness()),
        (7, 0, 0, inscription("text/plain", "bar").to_witness()),
        (7, 1, 0, Witness::new()),
      ],
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };
    let second_inscription_id = InscriptionId { txid, index: 1 };
    let outpoint: OutPoint = OutPoint { txid, vout: 0 };

    let utxo_recursive = server.get_json::<api::UtxoRecursive>(format!("/r/utxo/{}", outpoint));

    pretty_assert_eq!(
      utxo_recursive,
      api::UtxoRecursive {
        inscriptions: Some(vec![inscription_id, second_inscription_id]),
        runes: Some(
          [(
            SpacedRune { rune, spacers: 0 },
            Pile {
              amount: u128::MAX,
              divisibility: 1,
              symbol: None
            }
          )]
          .into_iter()
          .collect()
        ),
        sat_ranges: Some(vec![
          (6 * 50 * COIN_VALUE, 7 * 50 * COIN_VALUE),
          (7 * 50 * COIN_VALUE, 8 * 50 * COIN_VALUE),
          (50 * COIN_VALUE, 2 * 50 * COIN_VALUE)
        ]),
        value: 150 * COIN_VALUE,
      }
    );
  }

  #[test]
  fn utxo_recursive_endpoint_only_inscriptions() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };
    let outpoint: OutPoint = OutPoint { txid, vout: 0 };

    let utxo_recursive = server.get_json::<api::UtxoRecursive>(format!("/r/utxo/{}", outpoint));

    pretty_assert_eq!(
      utxo_recursive,
      api::UtxoRecursive {
        inscriptions: Some(vec![inscription_id]),
        runes: None,
        sat_ranges: None,
        value: 50 * COIN_VALUE,
      }
    );
  }

  #[test]
  fn sat_recursive_endpoints() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    assert_eq!(
      server.get_json::<api::SatInscriptions>("/r/sat/5000000000"),
      api::SatInscriptions {
        ids: Vec::new(),
        page: 0,
        more: false
      }
    );

    assert_eq!(
      server.get_json::<api::SatInscription>("/r/sat/5000000000/at/0"),
      api::SatInscription { id: None }
    );

    server.mine_blocks(1);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "foo").to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let mut ids = Vec::new();
    ids.push(InscriptionId { txid, index: 0 });

    for i in 1..111 {
      let txid = server.core.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 1, 0, inscription("text/plain", "foo").to_witness())],
        ..default()
      });

      server.mine_blocks(1);

      ids.push(InscriptionId { txid, index: 0 });
    }

    let paginated_response = server.get_json::<api::SatInscriptions>("/r/sat/5000000000");

    let equivalent_paginated_response =
      server.get_json::<api::SatInscriptions>("/r/sat/5000000000/0");

    assert_eq!(paginated_response.ids.len(), 100);
    assert!(paginated_response.more);
    assert_eq!(paginated_response.page, 0);

    assert_eq!(
      paginated_response.ids.len(),
      equivalent_paginated_response.ids.len()
    );
    assert_eq!(paginated_response.more, equivalent_paginated_response.more);
    assert_eq!(paginated_response.page, equivalent_paginated_response.page);

    let paginated_response = server.get_json::<api::SatInscriptions>("/r/sat/5000000000/1");

    assert_eq!(paginated_response.ids.len(), 11);
    assert!(!paginated_response.more);
    assert_eq!(paginated_response.page, 1);

    assert_eq!(
      server
        .get_json::<api::SatInscription>("/r/sat/5000000000/at/0")
        .id,
      Some(ids[0])
    );

    assert_eq!(
      server
        .get_json::<api::SatInscription>("/r/sat/5000000000/at/-111")
        .id,
      Some(ids[0])
    );

    assert_eq!(
      server
        .get_json::<api::SatInscription>("/r/sat/5000000000/at/110")
        .id,
      Some(ids[110])
    );

    assert_eq!(
      server
        .get_json::<api::SatInscription>("/r/sat/5000000000/at/-1")
        .id,
      Some(ids[110])
    );

    assert!(server
      .get_json::<api::SatInscription>("/r/sat/5000000000/at/111")
      .id
      .is_none());
  }

  #[test]
  fn children_recursive_endpoint() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let parent_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    server.assert_response(
      format!("/r/children/{parent_inscription_id}"),
      StatusCode::NOT_FOUND,
      &format!("inscription {parent_inscription_id} not found"),
    );

    server.mine_blocks(1);

    let children_json =
      server.get_json::<api::Children>(format!("/r/children/{parent_inscription_id}"));
    assert_eq!(children_json.ids.len(), 0);

    let mut builder = script::Builder::new();
    for _ in 0..111 {
      builder = Inscription {
        content_type: Some("text/plain".into()),
        body: Some("hello".into()),
        parents: vec![parent_inscription_id.value()],
        unrecognized_even_field: false,
        ..default()
      }
      .append_reveal_script_to_builder(builder);
    }

    let witness = Witness::from_slice(&[builder.into_bytes(), Vec::new()]);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, witness), (2, 1, 0, Default::default())],
      ..default()
    });

    server.mine_blocks(1);

    let first_child_inscription_id = InscriptionId { txid, index: 0 };
    let hundredth_child_inscription_id = InscriptionId { txid, index: 99 };
    let hundred_first_child_inscription_id = InscriptionId { txid, index: 100 };
    let hundred_eleventh_child_inscription_id = InscriptionId { txid, index: 110 };

    let children_json =
      server.get_json::<api::Children>(format!("/r/children/{parent_inscription_id}"));

    assert_eq!(children_json.ids.len(), 100);
    assert_eq!(children_json.ids[0], first_child_inscription_id);
    assert_eq!(children_json.ids[99], hundredth_child_inscription_id);
    assert!(children_json.more);
    assert_eq!(children_json.page, 0);

    let children_json =
      server.get_json::<api::Children>(format!("/r/children/{parent_inscription_id}/1"));

    assert_eq!(children_json.ids.len(), 11);
    assert_eq!(children_json.ids[0], hundred_first_child_inscription_id);
    assert_eq!(children_json.ids[10], hundred_eleventh_child_inscription_id);
    assert!(!children_json.more);
    assert_eq!(children_json.page, 1);
  }

  #[test]
  fn parents_recursive_endpoint() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let mut parent_ids = Vec::new();
    let mut inputs = Vec::new();
    for i in 0..111 {
      parent_ids.push(InscriptionId {
        txid: server.core.broadcast_tx(TransactionTemplate {
          inputs: &[(i + 1, 0, 0, inscription("text/plain", "hello").to_witness())],
          ..default()
        }),
        index: 0,
      });

      inputs.push((i + 2, 1, 0, Witness::default()));

      server.mine_blocks(1);
    }

    inputs.insert(
      0,
      (
        112,
        0,
        0,
        Inscription {
          content_type: Some("text/plain".into()),
          body: Some("hello".into()),
          parents: parent_ids.iter().map(|id| id.value()).collect(),
          ..default()
        }
        .to_witness(),
      ),
    );

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &inputs,
      ..default()
    });

    server.mine_blocks(1);

    let inscription_id = InscriptionId { txid, index: 0 };

    let first_parent_inscription_id = parent_ids[0];
    let hundredth_parent_inscription_id = parent_ids[99];
    let hundred_first_parent_inscription_id = parent_ids[100];
    let hundred_eleventh_parent_inscription_id = parent_ids[110];

    let parents_json = server.get_json::<api::Inscriptions>(format!("/r/parents/{inscription_id}"));

    assert_eq!(parents_json.ids.len(), 100);
    assert_eq!(parents_json.ids[0], first_parent_inscription_id);
    assert_eq!(parents_json.ids[99], hundredth_parent_inscription_id);
    assert!(parents_json.more);
    assert_eq!(parents_json.page_index, 0);

    let parents_json =
      server.get_json::<api::Inscriptions>(format!("/r/parents/{inscription_id}/1"));

    assert_eq!(parents_json.ids.len(), 11);
    assert_eq!(parents_json.ids[0], hundred_first_parent_inscription_id);
    assert_eq!(parents_json.ids[10], hundred_eleventh_parent_inscription_id);
    assert!(!parents_json.more);
    assert_eq!(parents_json.page_index, 1);
  }

  #[test]
  fn child_inscriptions_recursive_endpoint() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.mine_blocks(1);

    let parent_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    let parent_inscription_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    server.assert_response(
      format!("/r/children/{parent_inscription_id}/inscriptions"),
      StatusCode::NOT_FOUND,
      &format!("inscription {parent_inscription_id} not found"),
    );

    server.mine_blocks(1);

    let child_inscriptions_json = server.get_json::<api::ChildInscriptions>(format!(
      "/r/children/{parent_inscription_id}/inscriptions"
    ));
    assert_eq!(child_inscriptions_json.children.len(), 0);

    let mut builder = script::Builder::new();
    for _ in 0..111 {
      builder = Inscription {
        content_type: Some("text/plain".into()),
        body: Some("hello".into()),
        parents: vec![parent_inscription_id.value()],
        unrecognized_even_field: false,
        ..default()
      }
      .append_reveal_script_to_builder(builder);
    }

    let witness = Witness::from_slice(&[builder.into_bytes(), Vec::new()]);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, witness), (2, 1, 0, Default::default())],
      ..default()
    });

    server.mine_blocks(1);

    let first_child_inscription_id = InscriptionId { txid, index: 0 };
    let hundredth_child_inscription_id = InscriptionId { txid, index: 99 };
    let hundred_first_child_inscription_id = InscriptionId { txid, index: 100 };
    let hundred_eleventh_child_inscription_id = InscriptionId { txid, index: 110 };

    let child_inscriptions_json = server.get_json::<api::ChildInscriptions>(format!(
      "/r/children/{parent_inscription_id}/inscriptions"
    ));

    assert_eq!(child_inscriptions_json.children.len(), 100);

    assert_eq!(
      child_inscriptions_json.children[0].id,
      first_child_inscription_id
    );
    assert_eq!(child_inscriptions_json.children[0].number, 1); // parent is #0, 1st child is #1

    assert_eq!(
      child_inscriptions_json.children[99].id,
      hundredth_child_inscription_id
    );
    assert_eq!(child_inscriptions_json.children[99].number, -99); // all but 1st child are cursed

    assert!(child_inscriptions_json.more);
    assert_eq!(child_inscriptions_json.page, 0);

    let child_inscriptions_json = server.get_json::<api::ChildInscriptions>(format!(
      "/r/children/{parent_inscription_id}/inscriptions/1"
    ));

    assert_eq!(child_inscriptions_json.children.len(), 11);

    assert_eq!(
      child_inscriptions_json.children[0].id,
      hundred_first_child_inscription_id
    );
    assert_eq!(child_inscriptions_json.children[0].number, -100);

    assert_eq!(
      child_inscriptions_json.children[10].id,
      hundred_eleventh_child_inscription_id
    );
    assert_eq!(child_inscriptions_json.children[10].number, -110);

    assert!(!child_inscriptions_json.more);
    assert_eq!(child_inscriptions_json.page, 1);
  }

  #[test]
  fn inscriptions_in_block_page() {
    let server = TestServer::builder()
      .chain(Chain::Regtest)
      .index_sats()
      .build();

    for _ in 0..101 {
      server.mine_blocks(1);
    }

    for i in 0..101 {
      server.core.broadcast_tx(TransactionTemplate {
        inputs: &[(i + 1, 0, 0, inscription("text/foo", "hello").to_witness())],
        ..default()
      });
    }

    server.mine_blocks(1);

    server.assert_response_regex(
      "/inscriptions/block/102",
      StatusCode::OK,
      r".*(<a href=/inscription/[[:xdigit:]]{64}i0>.*</a>.*){100}.*",
    );

    server.assert_response_regex(
      "/inscriptions/block/102/1",
      StatusCode::OK,
      r".*<a href=/inscription/[[:xdigit:]]{64}i0>.*</a>.*",
    );
  }

  #[test]
  fn inscription_query_display() {
    assert_eq!(
      query::Inscription::Id(inscription_id(1)).to_string(),
      "1111111111111111111111111111111111111111111111111111111111111111i1"
    );
    assert_eq!(query::Inscription::Number(1).to_string(), "1")
  }

  #[test]
  fn inscription_not_found() {
    TestServer::builder()
      .chain(Chain::Regtest)
      .build()
      .assert_response(
        "/inscription/0",
        StatusCode::NOT_FOUND,
        "inscription 0 not found",
      );
  }

  #[test]
  fn looking_up_inscription_by_sat_requires_sat_index() {
    TestServer::builder()
      .chain(Chain::Regtest)
      .build()
      .assert_response(
        "/inscription/abcd",
        StatusCode::NOT_FOUND,
        "sat index required",
      );
  }

  #[test]
  fn delegate() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let delegate = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, delegate.to_witness())],
      ..default()
    });

    let delegate = InscriptionId { txid, index: 0 };

    server.mine_blocks(1);

    let inscription = Inscription {
      delegate: Some(delegate.value()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, inscription.to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response_regex(
      format!("/inscription/{id}"),
      StatusCode::OK,
      format!(
        ".*<h1>Inscription 1</h1>.*
        <dl>
          <dt>id</dt>
          <dd class=collapse>{id}</dd>
          .*
          <dt>delegate</dt>
          <dd><a href=/inscription/{delegate}>{delegate}</a></dd>
          .*
        </dl>.*"
      )
      .unindent(),
    );

    server.assert_response(format!("/content/{id}"), StatusCode::OK, "foo");

    server.assert_response(format!("/preview/{id}"), StatusCode::OK, "foo");

    assert_eq!(
      server
        .get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}"))
        .delegate,
      Some(delegate)
    );
  }

  #[test]
  fn undelegated_content() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let delegate = Inscription {
      content_type: Some("text/plain".into()),
      body: Some("foo".into()),
      ..default()
    };

    let delegate_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, delegate.to_witness())],
      ..default()
    });

    let delegate_id = InscriptionId {
      txid: delegate_txid,
      index: 0,
    };

    server.mine_blocks(1);

    let inscription = Inscription {
      content_type: Some("text/plain".into()),
      body: Some("bar".into()),
      delegate: Some(delegate_id.value()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, inscription.to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response(
      format!("/r/undelegated-content/{id}"),
      StatusCode::OK,
      "bar",
    );

    server.assert_response(format!("/content/{id}"), StatusCode::OK, "foo");

    // Test normal inscription without delegate
    let normal_inscription = Inscription {
      content_type: Some("text/plain".into()),
      body: Some("baz".into()),
      ..default()
    };

    let normal_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(3, 0, 0, normal_inscription.to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let normal_id = InscriptionId {
      txid: normal_txid,
      index: 0,
    };

    server.assert_response(
      format!("/r/undelegated-content/{normal_id}"),
      StatusCode::OK,
      "baz",
    );
    server.assert_response(format!("/content/{normal_id}"), StatusCode::OK, "baz");
  }

  #[test]
  fn content_proxy() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let inscription = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription.to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response(format!("/content/{id}"), StatusCode::OK, "foo");

    let server_with_proxy = TestServer::builder()
      .chain(Chain::Regtest)
      .server_option("--proxy", server.url.as_ref())
      .build();

    server_with_proxy.mine_blocks(1);

    server.assert_response(format!("/content/{id}"), StatusCode::OK, "foo");
    server_with_proxy.assert_response(format!("/content/{id}"), StatusCode::OK, "foo");
  }

  #[test]
  fn metadata_proxy() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let mut metadata = Vec::new();
    ciborium::into_writer("bar", &mut metadata).unwrap();

    let inscription = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      metadata: Some(metadata.clone()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription.to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    server.assert_response(
      format!("/r/metadata/{id}"),
      StatusCode::OK,
      &format!("\"{}\"", hex::encode(metadata.clone())),
    );

    let server_with_proxy = TestServer::builder()
      .chain(Chain::Regtest)
      .server_option("--proxy", server.url.as_ref())
      .build();

    server_with_proxy.mine_blocks(1);

    server.assert_response(
      format!("/r/metadata/{id}"),
      StatusCode::OK,
      &format!("\"{}\"", hex::encode(metadata.clone())),
    );

    server_with_proxy.assert_response(
      format!("/r/metadata/{id}"),
      StatusCode::OK,
      &format!("\"{}\"", hex::encode(metadata.clone())),
    );
  }

  #[test]
  fn children_proxy() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let parent_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/plain", "hello").to_witness())],
      ..default()
    });

    let parent_id = InscriptionId {
      txid: parent_txid,
      index: 0,
    };

    server.assert_response(
      format!("/r/children/{parent_id}"),
      StatusCode::NOT_FOUND,
      &format!("inscription {parent_id} not found"),
    );

    server.mine_blocks(1);

    let children = server.get_json::<api::Children>(format!("/r/children/{parent_id}"));

    assert_eq!(children.ids.len(), 0);

    let mut builder = script::Builder::new();
    for _ in 0..11 {
      builder = Inscription {
        content_type: Some("text/plain".into()),
        body: Some("hello".into()),
        parents: vec![parent_id.value()],
        unrecognized_even_field: false,
        ..default()
      }
      .append_reveal_script_to_builder(builder);
    }

    let witness = Witness::from_slice(&[builder.into_bytes(), Vec::new()]);

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, witness), (2, 1, 0, Default::default())],
      ..default()
    });

    server.mine_blocks(1);

    let first_child_id = InscriptionId { txid, index: 0 };

    let children = server.get_json::<api::Children>(format!("/r/children/{parent_id}"));

    assert_eq!(children.ids.len(), 11);
    assert_eq!(first_child_id, children.ids[0]);

    let server_with_proxy = TestServer::builder()
      .chain(Chain::Regtest)
      .server_option("--proxy", server.url.as_ref())
      .build();

    server_with_proxy.mine_blocks(1);

    let children = server.get_json::<api::Children>(format!("/r/children/{parent_id}"));

    assert_eq!(children.ids.len(), 11);
    assert_eq!(first_child_id, children.ids[0]);

    let children = server_with_proxy.get_json::<api::Children>(format!("/r/children/{parent_id}"));

    assert_eq!(children.ids.len(), 11);
    assert_eq!(first_child_id, children.ids[0]);
  }

  #[test]
  fn inscription_proxy() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let inscription = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription.to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    pretty_assert_eq!(
      server.get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}")),
      api::InscriptionRecursive {
        charms: Vec::new(),
        content_type: Some("text/html".into()),
        content_length: Some(3),
        delegate: None,
        fee: 0,
        height: 2,
        id,
        number: 0,
        output: OutPoint { txid, vout: 0 },
        sat: None,
        satpoint: SatPoint {
          outpoint: OutPoint { txid, vout: 0 },
          offset: 0
        },
        timestamp: 2,
        value: Some(50 * COIN_VALUE),
        address: Some("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202".to_string())
      }
    );

    let server_with_proxy = TestServer::builder()
      .chain(Chain::Regtest)
      .server_option("--proxy", server.url.as_ref())
      .build();

    server_with_proxy.mine_blocks(1);

    pretty_assert_eq!(
      server.get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}")),
      api::InscriptionRecursive {
        charms: Vec::new(),
        content_type: Some("text/html".into()),
        content_length: Some(3),
        delegate: None,
        fee: 0,
        height: 2,
        id,
        number: 0,
        output: OutPoint { txid, vout: 0 },
        sat: None,
        satpoint: SatPoint {
          outpoint: OutPoint { txid, vout: 0 },
          offset: 0
        },
        timestamp: 2,
        value: Some(50 * COIN_VALUE),
        address: Some("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202".to_string())
      }
    );

    assert_eq!(
      server_with_proxy.get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}")),
      api::InscriptionRecursive {
        charms: Vec::new(),
        content_type: Some("text/html".into()),
        content_length: Some(3),
        delegate: None,
        fee: 0,
        height: 2,
        id,
        number: 0,
        output: OutPoint { txid, vout: 0 },
        sat: None,
        satpoint: SatPoint {
          outpoint: OutPoint { txid, vout: 0 },
          offset: 0
        },
        timestamp: 2,
        value: Some(50 * COIN_VALUE),
        address: Some("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202".to_string())
      }
    );
  }

  #[test]
  fn sat_at_index_content_proxy() {
    let server = TestServer::builder()
      .index_sats()
      .chain(Chain::Regtest)
      .build();

    server.mine_blocks(1);

    let inscription = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription.to_witness())],
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };
    let ordinal: u64 = 5000000000;

    pretty_assert_eq!(
      server.get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}")),
      api::InscriptionRecursive {
        charms: vec![Charm::Coin, Charm::Uncommon],
        content_type: Some("text/html".into()),
        content_length: Some(3),
        delegate: None,
        fee: 0,
        height: 2,
        id,
        number: 0,
        output: OutPoint { txid, vout: 0 },
        sat: Some(Sat(ordinal)),
        satpoint: SatPoint {
          outpoint: OutPoint { txid, vout: 0 },
          offset: 0
        },
        timestamp: 2,
        value: Some(50 * COIN_VALUE),
        address: Some("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202".to_string())
      }
    );

    server.assert_response(
      format!("/r/sat/{ordinal}/at/-1/content"),
      StatusCode::OK,
      "foo",
    );

    let server_with_proxy = TestServer::builder()
      .chain(Chain::Regtest)
      .server_option("--proxy", server.url.as_ref())
      .build();
    let sat_indexed_server_with_proxy = TestServer::builder()
      .index_sats()
      .chain(Chain::Regtest)
      .server_option("--proxy", server.url.as_ref())
      .build();

    server_with_proxy.mine_blocks(1);
    sat_indexed_server_with_proxy.mine_blocks(1);

    server.assert_response(
      format!("/r/sat/{ordinal}/at/-1/content"),
      StatusCode::OK,
      "foo",
    );
    server_with_proxy.assert_response(
      format!("/r/sat/{ordinal}/at/-1/content"),
      StatusCode::OK,
      "foo",
    );
    sat_indexed_server_with_proxy.assert_response(
      format!("/r/sat/{ordinal}/at/-1/content"),
      StatusCode::OK,
      "foo",
    );
  }

  #[test]
  fn block_info() {
    let server = TestServer::new();

    pretty_assert_eq!(
      server.get_json::<api::BlockInfo>("/r/blockinfo/0"),
      api::BlockInfo {
        average_fee: 0,
        average_fee_rate: 0,
        bits: 486604799,
        chainwork: [0; 32],
        confirmations: 0,
        difficulty: 0.0,
        hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
          .parse()
          .unwrap(),
        feerate_percentiles: [0, 0, 0, 0, 0],
        height: 0,
        max_fee: 0,
        max_fee_rate: 0,
        max_tx_size: 0,
        median_fee: 0,
        median_time: None,
        merkle_root: TxMerkleNode::all_zeros(),
        min_fee: 0,
        min_fee_rate: 0,
        next_block: None,
        nonce: 0,
        previous_block: None,
        subsidy: 0,
        target: "00000000ffff0000000000000000000000000000000000000000000000000000"
          .parse()
          .unwrap(),
        timestamp: 0,
        total_fee: 0,
        total_size: 0,
        total_weight: 0,
        transaction_count: 0,
        version: 1,
      },
    );

    server.mine_blocks(1);

    pretty_assert_eq!(
      server.get_json::<api::BlockInfo>("/r/blockinfo/1"),
      api::BlockInfo {
        average_fee: 0,
        average_fee_rate: 0,
        bits: 0,
        chainwork: [0; 32],
        confirmations: 0,
        difficulty: 0.0,
        hash: "56d05060a0280d0712d113f25321158747310ece87ea9e299bde06cf385b8d85"
          .parse()
          .unwrap(),
        feerate_percentiles: [0, 0, 0, 0, 0],
        height: 1,
        max_fee: 0,
        max_fee_rate: 0,
        max_tx_size: 0,
        median_fee: 0,
        median_time: None,
        merkle_root: TxMerkleNode::all_zeros(),
        min_fee: 0,
        min_fee_rate: 0,
        next_block: None,
        nonce: 0,
        previous_block: None,
        subsidy: 0,
        target: BlockHash::all_zeros(),
        timestamp: 0,
        total_fee: 0,
        total_size: 0,
        total_weight: 0,
        transaction_count: 0,
        version: 1,
      },
    )
  }

  #[test]
  fn authentication_requires_username_and_password() {
    assert!(Arguments::try_parse_from(["ord", "--server-username", "server", "foo"]).is_err());
    assert!(Arguments::try_parse_from(["ord", "--server-password", "server", "bar"]).is_err());
    assert!(Arguments::try_parse_from([
      "ord",
      "--server-username",
      "foo",
      "--server-password",
      "bar",
      "server"
    ])
    .is_ok());
  }

  #[test]
  fn inscriptions_can_be_hidden_with_config() {
    let core = mockcore::builder()
      .network(Chain::Regtest.network())
      .build();

    core.mine_blocks(1);

    let txid = core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription("text/foo", "hello").to_witness())],
      ..default()
    });

    core.mine_blocks(1);

    let inscription = InscriptionId { txid, index: 0 };

    let server = TestServer::builder()
      .core(core)
      .config(&format!("hidden: [{inscription}]"))
      .build();

    server.assert_response_regex(format!("/inscription/{inscription}"), StatusCode::OK, ".*");

    server.assert_response_regex(
      format!("/content/{inscription}"),
      StatusCode::OK,
      PreviewUnknownHtml.to_string(),
    );
  }

  #[test]
  fn update_endpoint_is_not_available_when_not_in_integration_test_mode() {
    let server = TestServer::builder().build();
    server.assert_response("/update", StatusCode::NOT_FOUND, "");
  }

  #[test]
  fn burned_charm() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let inscription = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      ..default()
    };

    let txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription.to_witness())],
      outputs: 0,
      op_return_index: Some(0),
      op_return_value: Some(50 * COIN_VALUE),
      op_return: Some(
        script::Builder::new()
          .push_opcode(opcodes::all::OP_RETURN)
          .into_script(),
      ),
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId { txid, index: 0 };

    pretty_assert_eq!(
      server.get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}")),
      api::InscriptionRecursive {
        charms: vec![Charm::Burned],
        content_type: Some("text/html".into()),
        content_length: Some(3),
        delegate: None,
        fee: 0,
        height: 2,
        id,
        number: 0,
        output: OutPoint { txid, vout: 0 },
        sat: None,
        satpoint: SatPoint {
          outpoint: OutPoint { txid, vout: 0 },
          offset: 0
        },
        timestamp: 2,
        value: Some(50 * COIN_VALUE),
        address: None
      }
    );
  }

  #[test]
  fn burned_charm_on_transfer() {
    let server = TestServer::builder().chain(Chain::Regtest).build();

    server.mine_blocks(1);

    let inscription = Inscription {
      content_type: Some("text/html".into()),
      body: Some("foo".into()),
      ..default()
    };

    let create_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, inscription.to_witness())],
      outputs: 1,
      ..default()
    });

    server.mine_blocks(1);

    let id = InscriptionId {
      txid: create_txid,
      index: 0,
    };

    pretty_assert_eq!(
      server.get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}")),
      api::InscriptionRecursive {
        charms: vec![],
        content_type: Some("text/html".into()),
        content_length: Some(3),
        delegate: None,
        fee: 0,
        height: 2,
        id,
        number: 0,
        output: OutPoint {
          txid: create_txid,
          vout: 0
        },
        sat: None,
        satpoint: SatPoint {
          outpoint: OutPoint {
            txid: create_txid,
            vout: 0
          },
          offset: 0
        },
        timestamp: 2,
        value: Some(50 * COIN_VALUE),
        address: Some("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202".to_string())
      }
    );

    let transfer_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 1, 0, Default::default())],
      fee: 0,
      outputs: 0,
      op_return_index: Some(0),
      op_return_value: Some(50 * COIN_VALUE),
      op_return: Some(
        script::Builder::new()
          .push_opcode(opcodes::all::OP_RETURN)
          .into_script(),
      ),
      ..default()
    });

    server.mine_blocks(1);

    pretty_assert_eq!(
      server.get_json::<api::InscriptionRecursive>(format!("/r/inscription/{id}")),
      api::InscriptionRecursive {
        charms: vec![Charm::Burned],
        content_type: Some("text/html".into()),
        content_length: Some(3),
        delegate: None,
        fee: 0,
        height: 2,
        id,
        number: 0,
        output: OutPoint {
          txid: transfer_txid,
          vout: 0
        },
        sat: None,
        satpoint: SatPoint {
          outpoint: OutPoint {
            txid: transfer_txid,
            vout: 0
          },
          offset: 0
        },
        timestamp: 2,
        value: Some(50 * COIN_VALUE),
        address: None
      }
    );
  }

  #[test]
  fn unknown_output_returns_404() {
    let server = TestServer::builder().chain(Chain::Regtest).build();
    server.assert_response(
      "/output/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:123",
      StatusCode::NOT_FOUND,
      "output 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:123 not found",
    );
  }

  #[test]
  fn satscard_form_redirects_to_query() {
    TestServer::new().assert_redirect(
      &format!(
        "/satscard?url={}",
        urlencoding::encode(satscard::tests::URL)
      ),
      &format!("/satscard?{}", satscard::tests::query_parameters()),
    );
  }

  #[test]
  fn satscard_missing_form_query_is_error() {
    TestServer::new().assert_response(
      "/satscard?url=https://foo.com",
      StatusCode::BAD_REQUEST,
      "satscard URL missing fragment",
    );
  }

  #[test]
  fn satscard_invalid_query_parameters() {
    TestServer::new().assert_response(
      "/satscard?foo=bar",
      StatusCode::BAD_REQUEST,
      "invalid satscard query parameters: unknown key `foo`",
    );
  }

  #[test]
  fn satscard_display_without_address_index() {
    TestServer::builder()
      .chain(Chain::Mainnet)
      .build()
      .assert_html(
        format!("/satscard?{}", satscard::tests::query_parameters()),
        SatscardHtml {
          satscard: Some((satscard::tests::satscard(), None)),
        },
      );
  }

  #[test]
  fn satscard_display_with_address_index_empty() {
    TestServer::builder()
      .chain(Chain::Mainnet)
      .index_addresses()
      .build()
      .assert_html(
        format!("/satscard?{}", satscard::tests::query_parameters()),
        SatscardHtml {
          satscard: Some((
            satscard::tests::satscard(),
            Some(AddressHtml {
              address: satscard::tests::address(),
              header: false,
              inscriptions: Some(Vec::new()),
              outputs: Vec::new(),
              runes_balances: None,
              sat_balance: 0,
            }),
          )),
        },
      );
  }

  #[test]
  fn satscard_address_recovery_fails_on_wrong_chain() {
    TestServer::builder()
      .chain(Chain::Testnet)
      .build()
      .assert_response(
        format!("/satscard?{}", satscard::tests::query_parameters()),
        StatusCode::BAD_REQUEST,
        "invalid satscard query parameters: address recovery failed",
      );
  }

  #[test]
  fn sat_inscription_at_index_content_endpoint() {
    let server = TestServer::builder()
      .index_sats()
      .chain(Chain::Regtest)
      .build();

    server.mine_blocks(1);

    let first_txid = server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        1,
        0,
        0,
        inscription("text/plain;charset=utf-8", "foo").to_witness(),
      )],
      ..default()
    });

    server.mine_blocks(1);

    let first_inscription_id = InscriptionId {
      txid: first_txid,
      index: 0,
    };

    let first_inscription = server
      .get_json::<api::InscriptionRecursive>(format!("/r/inscription/{first_inscription_id}"));

    let sat = first_inscription.sat.unwrap();

    server.assert_response(format!("/r/sat/{sat}/at/0/content"), StatusCode::OK, "foo");

    server.assert_response(format!("/r/sat/{sat}/at/-1/content"), StatusCode::OK, "foo");

    server.core.broadcast_tx(TransactionTemplate {
      inputs: &[(
        2,
        1,
        first_inscription.satpoint.outpoint.vout.try_into().unwrap(),
        inscription("text/plain;charset=utf-8", "bar").to_witness(),
      )],
      ..default()
    });

    server.mine_blocks(1);

    server.assert_response(format!("/r/sat/{sat}/at/0/content"), StatusCode::OK, "foo");

    server.assert_response(format!("/r/sat/{sat}/at/1/content"), StatusCode::OK, "bar");

    server.assert_response(format!("/r/sat/{sat}/at/-1/content"), StatusCode::OK, "bar");

    server.assert_response(
      "/r/sat/0/at/0/content",
      StatusCode::NOT_FOUND,
      "inscription on sat 0 not found",
    );

    let server = TestServer::new();

    server.assert_response(
      "/r/sat/0/at/0/content",
      StatusCode::NOT_FOUND,
      "this server has no sat index",
    );
  }
}
