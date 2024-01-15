use super::*;

#[derive(Boilerplate)]
pub(crate) struct OutputHtml {
  pub(crate) chain: Chain,
  pub(crate) inscriptions: Vec<InscriptionId>,
  pub(crate) outpoint: OutPoint,
  pub(crate) output: TxOut,
  pub(crate) runes: Vec<(SpacedRune, Pile)>,
  pub(crate) sat_ranges: Option<Vec<(u64, u64)>>,
  pub(crate) spent: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct OutputJson {
  pub address: Option<String>,
  pub indexed: bool,
  pub inscriptions: Vec<InscriptionId>,
  pub runes: BTreeMap<Rune, u128>,
  pub sat_ranges: Option<Vec<(u64, u64)>>,
  pub script_pubkey: String,
  pub spent: bool,
  pub transaction: String,
  pub value: u64,
}

impl OutputJson {
  pub fn new(
    chain: Chain,
    inscriptions: Vec<InscriptionId>,
    outpoint: OutPoint,
    output: TxOut,
    indexed: bool,
    runes: BTreeMap<Rune, u128>,
    sat_ranges: Option<Vec<(u64, u64)>>,
    spent: bool,
  ) -> Self {
    Self {
      address: chain
        .address_from_script(&output.script_pubkey)
        .ok()
        .map(|address| address.to_string()),
      indexed,
      inscriptions,
      runes,
      sat_ranges,
      script_pubkey: output.script_pubkey.to_asm_string(),
      spent,
      transaction: outpoint.txid.to_string(),
      value: output.value,
    }
  }
}

impl PageContent for OutputHtml {
  fn title(&self) -> String {
    format!("Output {}", self.outpoint)
  }
}

#[cfg(test)]
mod tests {
  use {
    super::*,
    bitcoin::{blockdata::script, PubkeyHash},
  };

  #[test]
  fn unspent_output() {
    assert_regex_match!(
      OutputHtml {
        chain: Chain::Mainnet,
        inscriptions: Vec::new(),
        outpoint: outpoint(1),
        output: TxOut { value: 3, script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::all_zeros()), },
        runes: Vec::new(),
        sat_ranges: Some(vec![(0, 1), (1, 3)]),
        spent: false,
      },
      "
        <h1>Output <span class=monospace>1{64}:1</span></h1>
        <dl>
          <dt>value</dt><dd>3</dd>
          <dt>script pubkey</dt><dd class=monospace>OP_DUP OP_HASH160 OP_PUSHBYTES_20 0{40} OP_EQUALVERIFY OP_CHECKSIG</dd>
          <dt>address</dt><dd class=monospace>1111111111111111111114oLvT2</dd>
          <dt>transaction</dt><dd><a class=monospace href=/tx/1{64}>1{64}</a></dd>
          <dt>spent</dt><dd>false</dd>
        </dl>
        <h2>2 Sat Ranges</h2>
        <ul class=monospace>
          <li><a href=/sat/0 class=mythic>0</a></li>
          <li><a href=/range/1/3 class=common>1–3</a></li>
        </ul>
      "
      .unindent()
    );
  }

  #[test]
  fn spent_output() {
    assert_regex_match!(
      OutputHtml {
        chain: Chain::Mainnet,
        inscriptions: Vec::new(),
        outpoint: outpoint(1),
        output: TxOut {
          value: 1,
          script_pubkey: script::Builder::new().push_int(0).into_script(),
        },
        runes: Vec::new(),
        sat_ranges: None,
        spent: true,
      },
      "
        <h1>Output <span class=monospace>1{64}:1</span></h1>
        <dl>
          <dt>value</dt><dd>1</dd>
          <dt>script pubkey</dt><dd class=monospace>OP_0</dd>
          <dt>transaction</dt><dd><a class=monospace href=/tx/1{64}>1{64}</a></dd>
          <dt>spent</dt><dd>true</dd>
        </dl>
      "
      .unindent()
    );
  }

  #[test]
  fn spent_output_with_ranges() {
    assert_regex_match!(
      OutputHtml {
        chain: Chain::Mainnet,
        inscriptions: Vec::new(),
        outpoint: outpoint(1),
        output: TxOut { value: 3, script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::all_zeros()), },
        runes: Vec::new(),
        sat_ranges: Some(vec![(0, 1), (1, 3)]),
        spent: true,
      },
      "
        <h1>Output <span class=monospace>1{64}:1</span></h1>
        <dl>
          <dt>value</dt><dd>3</dd>
          <dt>script pubkey</dt><dd class=monospace>OP_DUP OP_HASH160 OP_PUSHBYTES_20 0{40} OP_EQUALVERIFY OP_CHECKSIG</dd>
          <dt>address</dt><dd class=monospace>1111111111111111111114oLvT2</dd>
          <dt>transaction</dt><dd><a class=monospace href=/tx/1{64}>1{64}</a></dd>
          <dt>spent</dt><dd>true</dd>
        </dl>
        <h2>2 Sat Ranges</h2>
        <ul class=monospace>
          <li><a href=/sat/0 class=mythic>0</a></li>
          <li><a href=/range/1/3 class=common>1–3</a></li>
        </ul>
      "
      .unindent()
    );
  }

  #[test]
  fn no_list() {
    assert_regex_match!(
      OutputHtml {
        chain: Chain::Mainnet,
        inscriptions: Vec::new(),
        outpoint: outpoint(1),
        output: TxOut { value: 3, script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::all_zeros()), },
        runes: Vec::new(),
        sat_ranges: None,
        spent: false,
      }
      .to_string(),
      "
        <h1>Output <span class=monospace>1{64}:1</span></h1>
        <dl>
          <dt>value</dt><dd>3</dd>
          <dt>script pubkey</dt><dd class=monospace>OP_DUP OP_HASH160 OP_PUSHBYTES_20 0{40} OP_EQUALVERIFY OP_CHECKSIG</dd>
          <dt>address</dt><dd class=monospace>1111111111111111111114oLvT2</dd>
          <dt>transaction</dt><dd><a class=monospace href=/tx/1{64}>1{64}</a></dd>
          <dt>spent</dt><dd>false</dd>
        </dl>
      "
      .unindent()
    );
  }

  #[test]
  fn with_inscriptions() {
    assert_regex_match!(
      OutputHtml {
        chain: Chain::Mainnet,
        inscriptions: vec![inscription_id(1)],
        outpoint: outpoint(1),
        output: TxOut {
          value: 3,
          script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::all_zeros()),
        },
        runes: Vec::new(),
        sat_ranges: None,
        spent: false,
      },
      "
        <h1>Output <span class=monospace>1{64}:1</span></h1>
        <dl>
          <dt>inscriptions</dt>
          <dd class=thumbnails>
            <a href=/inscription/1{64}i1><iframe .* src=/preview/1{64}i1></iframe></a>
          </dd>
          .*
        </dl>
      "
      .unindent()
    );
  }

  #[test]
  fn with_runes() {
    assert_regex_match!(
      OutputHtml {
        chain: Chain::Mainnet,
        inscriptions: Vec::new(),
        outpoint: outpoint(1),
        output: TxOut {
          value: 3,
          script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::all_zeros()),
        },
        runes: vec![(
          SpacedRune {
            rune: Rune(26),
            spacers: 1
          },
          Pile {
            amount: 11,
            divisibility: 1,
            symbol: None,
          }
        )],
        sat_ranges: None,
        spent: false,
      },
      "
        <h1>Output <span class=monospace>1{64}:1</span></h1>
        <dl>
          <dt>runes</dt>
          <dd>
            <table>
              <tr>
                <th>rune</th>
                <th>balance</th>
              </tr>
              <tr>
                <td><a href=/rune/A•A>A•A</a></td>
                <td>1.1</td>
              </tr>
            </table>
          </dd>
          .*
        </dl>
      "
      .unindent()
    );
  }
}
