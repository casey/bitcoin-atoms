use super::*;

pub(crate) struct Iframe {
  inscription_id: InscriptionId,
  main: bool,
}

impl Iframe {
  pub(crate) fn preview(inscription_id: InscriptionId) -> Trusted<Self> {
    Trusted(Self {
      inscription_id,
      main: false,
    })
  }

  pub(crate) fn main(inscription_id: InscriptionId) -> Trusted<Self> {
    Trusted(Self {
      inscription_id,
      main: true,
    })
  }
}

impl Display for Iframe {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    if self.main {
      write!(
        f,
        "<a href=/preview/{}><iframe sandbox=allow-scripts scrolling=no src=/preview/{}></iframe></a>",
        self.inscription_id,
        self.inscription_id,
      )
    } else {
      write!(
        f,
        "<a href=/inscription/{}><iframe sandbox=allow-scripts scrolling=no src=/preview/{}></iframe></a>",
        self.inscription_id,
        self.inscription_id,
      )
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn preview() {
    assert_regex_match!(
      Iframe::preview(inscription_id(1))
      .0.to_string(),
      "<a href=/inscription/1{64}i1><iframe sandbox=allow-scripts scrolling=no src=/preview/1{64}i1></iframe></a>",
    );
  }

  #[test]
  fn main() {
    assert_regex_match!(
      Iframe::main(inscription_id(1))
      .0.to_string(),
      "<a href=/preview/1{64}i1><iframe sandbox=allow-scripts scrolling=no src=/preview/1{64}i1></iframe></a>",
    );
  }
}
