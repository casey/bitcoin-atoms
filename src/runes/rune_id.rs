use super::*;

#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) struct RuneId {
  pub(crate) height: u32,
  pub(crate) index: u16,
}

impl From<RuneId> for u128 {
  fn from(id: RuneId) -> Self {
    u128::from(id.height) << 16 | u128::from(id.index)
  }
}

impl Display for RuneId {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    write!(f, "{}/{}", self.height, self.index,)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rune_id_to_128() {
    assert_eq!(
      0b11_0000_0000_0000_0001u128,
      RuneId {
        height: 3,
        index: 1,
      }
      .into()
    );
  }

  #[test]
  fn display() {
    assert_eq!(
      RuneId {
        height: 1,
        index: 2
      }
      .to_string(),
      "1/2"
    );
  }
}
