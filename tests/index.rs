use super::*;

#[test]
fn default_index_size() -> Result {
  let state = Test::new()?
    .command("find 0")
    .expected_stdout("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0\n")
    .blocks(1)
    .output()?
    .state;

  assert_eq!(
    state.tempdir.path().join("index.redb").metadata()?.len(),
    1 << 20
  );

  Ok(())
}

#[test]
fn custom_index_size() -> Result {
  let state = Test::new()?
    .command("--max-index-size 1mib find 0")
    .expected_stdout("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0:0\n")
    .blocks(1)
    .output()?
    .state;

  assert_eq!(
    state.tempdir.path().join("index.redb").metadata()?.len(),
    1 << 20
  );

  Ok(())
}
