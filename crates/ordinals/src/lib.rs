//! This library exposes types for interoperating with ordinals and
//! inscriptions.

use {
  self::deserialize_from_str::DeserializeFromStr,
  bitcoin::{
    consensus::{Decodable, Encodable},
    OutPoint,
  },
  serde::{Deserialize, Deserializer, Serialize, Serializer},
  std::{
    fmt::{self, Display, Formatter},
    io,
    str::FromStr,
  },
  thiserror::Error,
};

pub use sat_point::SatPoint;

mod deserialize_from_str;
mod sat_point;
