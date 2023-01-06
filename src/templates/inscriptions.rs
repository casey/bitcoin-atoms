use super::*;

#[derive(Boilerplate)]
pub(crate) struct InscriptionsHtml {
  pub(crate) inscriptions: Vec<InscriptionId>,
}

impl PageContent for InscriptionsHtml {
  fn title(&self) -> String {
    "Inscriptions".into()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn inscriptions() {
    assert_regex_match!(
      InscriptionsHtml {
        inscriptions: vec![inscription_id(1), inscription_id(2)],
      },
      "
        <h1>Inscriptions</h1>
        <div class=inscriptions>
          <a href=/inscription/1{72}><iframe .* src=/preview/1{72}></iframe></a>
          <a href=/inscription/2{72}><iframe .* src=/preview/2{72}></iframe></a>
        </div>
      "
      .unindent()
    );
  }
}
