use {super::*, base64::Engine, bitcoin::psbt::Psbt};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Output {
  inputs: Vec<Vec<Range>>,
  outputs: Vec<Vec<Range>>,
  fee: Vec<Range>,
}

#[derive(Debug, Parser)]
pub(crate) struct Flow {
  #[arg(long)]
  binary: bool,
  psbt: PathBuf,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Range {
  start: u64,
  end: u64,
  name: String,
}

impl From<(u64, u64)> for Range {
  fn from((start, end): (u64, u64)) -> Self {
    Self {
      start,
      end,
      name: Sat(start).name(),
    }
  }
}

impl Flow {
  pub(crate) fn run(self, settings: Settings) -> SubcommandResult {
    let psbt = if self.binary {
      fs::read(self.psbt).unwrap()
    } else {
      base64::engine::general_purpose::STANDARD
        .decode(fs::read_to_string(self.psbt).unwrap().trim())
        .unwrap()
    };

    let psbt = Psbt::deserialize(&psbt).unwrap();

    let index = Index::open(&settings)?;

    index.update()?;

    let mut inputs = Vec::new();

    for input in psbt.unsigned_tx.input {
      inputs.push(index.list(input.previous_output)?.unwrap());
    }

    let mut fee: VecDeque<(u64, u64)> = inputs.iter().flatten().copied().collect();

    let input_value = fee.iter().map(|(start, end)| end - start).sum::<u64>();

    let output_value = psbt
      .unsigned_tx
      .output
      .iter()
      .map(|input| input.value)
      .sum::<u64>();

    ensure!(
      input_value >= output_value,
      "insufficient inputs to pay for outputs: {input_value} < {output_value}",
    );

    let mut outputs = Vec::new();

    for output in psbt.unsigned_tx.output {
      let mut ranges = Vec::new();

      let mut deficit = output.value;

      while deficit > 0 {
        let (start, end) = fee
          .pop_front()
          .context("inputs insufficient to pay for outputs")?;

        let size = end - start;

        let (start, end) = if size <= deficit {
          (start, end)
        } else {
          fee.push_front((start + deficit, end));
          (start, start + deficit)
        };

        ranges.push((start, end));

        deficit -= end - start;
      }

      outputs.push(ranges);
    }

    Ok(Some(Box::new(Output {
      fee: fee.into_iter().map(|range| range.into()).collect(),
      inputs: inputs
        .into_iter()
        .map(|ranges| ranges.into_iter().map(|range| range.into()).collect())
        .collect(),
      outputs: outputs
        .into_iter()
        .map(|ranges| ranges.into_iter().map(|range| range.into()).collect())
        .collect(),
    })))
  }
}
