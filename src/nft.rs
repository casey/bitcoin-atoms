use super::*;

const ORDINAL_MESSAGE_PREFIX: &[u8] = b"Ordinal Signed Message:";

#[derive(Serialize, Deserialize)]
pub(crate) struct Nft {
  data: Vec<u8>,
  metadata: Vec<u8>,
  signature: Signature,
  public_key: XOnlyPublicKey,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
  ordinal: Ordinal,
}

impl Nft {
  pub(crate) fn mint(ordinal: Ordinal, data: &[u8], signing_key_pair: KeyPair) -> Result<Self> {
    let data_hash = sha256::Hash::hash(data);

    let public_key = signing_key_pair.public_key();

    let metadata = Metadata { ordinal };
    let metadata_cbor = serde_cbor::to_vec(&metadata)?;
    let metadata_hash = sha256::Hash::hash(&metadata_cbor);

    let mut engine = sha256::Hash::engine();
    engine.input(ORDINAL_MESSAGE_PREFIX);
    // We use the metadata hash as input instead of the hashed CBOR for compatibility with Coldcard
    // signed messages (max 240 chars).
    engine.input(&metadata_hash);
    engine.input(&data_hash);

    let message_hash = secp256k1::Message::from_slice(&sha256::Hash::from_engine(engine))?;

    let signature = signing_key_pair.sign_schnorr(message_hash);

    Ok(Self {
      metadata: metadata_cbor,
      signature,
      data: data.into(),
      public_key,
    })
  }

  pub(crate) fn data(&self) -> &[u8] {
    &self.data
  }

  pub(crate) fn encode(&self) -> Vec<u8> {
    serde_cbor::to_vec(self).unwrap()
  }

  pub(crate) fn issuer(&self) -> XOnlyPublicKey {
    self.public_key
  }

  pub(crate) fn data_hash(&self) -> sha256::Hash {
    sha256::Hash::hash(&self.data)
  }

  pub(crate) fn ordinal(&self) -> Result<Ordinal> {
    let metadata: Metadata = serde_cbor::from_slice(&self.metadata)?;
    Ok(metadata.ordinal)
  }

  pub(crate) fn verify(cbor: &[u8]) -> Result<Self> {
    let nft = serde_cbor::from_slice::<Nft>(cbor)?;

    let data_hash = sha256::Hash::hash(&nft.data);

    let metadata_hash = sha256::Hash::hash(&nft.metadata);
    let mut engine = sha256::Hash::engine();
    engine.input(ORDINAL_MESSAGE_PREFIX);
    engine.input(&metadata_hash);
    engine.input(&data_hash);

    let message_hash = secp256k1::Message::from_slice(&sha256::Hash::from_engine(engine))?;

    Secp256k1::new()
      .verify_schnorr(&nft.signature, &message_hash, &nft.public_key)
      .context("Failed to verify NFT signature")?;

    Ok(nft)
  }
}
