use {
  super::*,
  bdk::{ChangeSet, WalletPersister},
};

pub(crate) struct Persister(pub(crate) Arc<Database>);

impl WalletPersister for Persister {
  type Error = Error;

  fn initialize(persister: &mut Self) -> std::result::Result<ChangeSet, Self::Error> {
    let rtx = persister.0.begin_read()?;

    let changeset = match rtx
      .open_table(CHANGESET)?
      .get(())?
      .map(|result| result.value().to_string())
    {
      Some(result) => serde_json::from_str::<ChangeSet>(result.as_str())?,
      None => ChangeSet::default(),
    };

    Ok(changeset)
  }

  fn persist(persister: &mut Self, changeset: &ChangeSet) -> std::result::Result<(), Self::Error> {
    let wtx = persister.0.begin_write()?;

    wtx
      .open_table(CHANGESET)?
      .insert((), serde_json::to_string(changeset)?.as_str())?;

    wtx.commit()?;

    Ok(())
  }
}
