use super::*;

mod epochs;
mod find;
mod range;
mod supply;
mod traits;

#[derive(StructOpt)]
pub(crate) enum Command {
  Epochs,
  Find {
    #[structopt(long)]
    blocksdir: Option<PathBuf>,
    #[structopt(long)]
    as_of_height: u64,
    ordinal: Ordinal,
  },
  Name {
    name: String,
  },
  Range {
    #[structopt(long)]
    name: bool,
    height: Height,
  },
  Supply,
  Traits {
    ordinal: Ordinal,
  },
}

impl Command {
  pub(crate) fn run(self) -> Result<()> {
    match self {
      Self::Epochs => epochs::run(),
      Self::Find {
        blocksdir,
        ordinal,
        as_of_height,
      } => find::run(blocksdir.as_deref(), ordinal, as_of_height),
      Self::Name { name } => name::run(&name),
      Self::Range { height, name } => range::run(height, name),
      Self::Supply => supply::run(),
      Self::Traits { ordinal } => traits::run(ordinal),
    }
  }
}
