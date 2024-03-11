use super::*;

#[derive(Copy, Clone)]
pub(crate) enum Tag {
  Pointer,
  #[allow(unused)]
  Unbound,

  ContentType,
  Parent,
  Metadata,
  Metaprotocol,
  ContentEncoding,
  Delegate,
  #[allow(unused)]
  Nop,
}

enum TagParsingStrategy {
  First,
  Chunked,
  Array,
}

impl Tag {
  fn parsing_strategy(self) -> TagParsingStrategy {
    match self {
      Tag::Metadata => TagParsingStrategy::Chunked,
      Tag::Parent => TagParsingStrategy::Array,
      _ => TagParsingStrategy::First,
    }
  }

  pub(crate) fn bytes(self) -> &'static [u8] {
    match self {
      Self::Pointer => &[2],
      Self::Unbound => &[66],

      Self::ContentType => &[1],
      Self::Parent => &[3],
      Self::Metadata => &[5],
      Self::Metaprotocol => &[7],
      Self::ContentEncoding => &[9],
      Self::Delegate => &[11],
      Self::Nop => &[255],
    }
  }

  pub(crate) fn encode(self, builder: &mut script::Builder, value: &Option<Vec<u8>>) {
    if let Some(value) = value {
      let mut tmp = script::Builder::new();
      mem::swap(&mut tmp, builder);

      match self.parsing_strategy() {
        TagParsingStrategy::First | TagParsingStrategy::Array => {
          tmp = tmp
            .push_slice::<&script::PushBytes>(self.bytes().try_into().unwrap())
            .push_slice::<&script::PushBytes>(value.as_slice().try_into().unwrap());
        }
        TagParsingStrategy::Chunked => {
          for chunk in value.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
            tmp = tmp
              .push_slice::<&script::PushBytes>(self.bytes().try_into().unwrap())
              .push_slice::<&script::PushBytes>(chunk.try_into().unwrap());
          }
        } // TagParsingStrategy::Array => {
          //   unimplemented!()
          // }
      }

      mem::swap(&mut tmp, builder);
    }
  }

  pub(crate) fn remove_field(self, fields: &mut BTreeMap<&[u8], Vec<&[u8]>>) -> Option<Vec<u8>> {
    match self.parsing_strategy() {
      TagParsingStrategy::First => {
        let values = fields.get_mut(self.bytes())?;

        if values.is_empty() {
          None
        } else {
          let value = values.remove(0).to_vec();

          if values.is_empty() {
            fields.remove(self.bytes());
          }

          Some(value)
        }
      }
      TagParsingStrategy::Chunked => {
        let value = fields.remove(self.bytes())?;

        if value.is_empty() {
          None
        } else {
          Some(value.into_iter().flatten().cloned().collect())
        }
      }
      TagParsingStrategy::Array => {
        panic!("Array-type fields must not be removed as a simple byte array.")
      }
    }
  }

  pub(crate) fn remove_array_field(self, fields: &mut BTreeMap<&[u8], Vec<&[u8]>>) -> Vec<Vec<u8>> {
    let values = fields.remove(self.bytes()).unwrap_or(vec![]);
    // .cloned() doesn't work for Vec<&[u8]>
    values.into_iter().map(|v| v.to_vec()).collect()
  }
}
