use super::*;

#[test]
fn empty() {
  CommandBuilder::new("epochs")
    .expected_stdout(
      "
        0
        1050000000000000
        1575000000000000
        1837500000000000
        1968750000000000
        2034375000000000
        2067187500000000
        2083593750000000
        2091796875000000
        2095898437500000
        2097949218750000
        2098974609270000
        2099487304530000
        2099743652160000
        2099871825870000
        2099935912620000
        2099967955890000
        2099983977420000
        2099991988080000
        2099995993410000
        2099997995970000
        2099998997250000
        2099999497890000
        2099999748210000
        2099999873370000
        2099999935950000
        2099999967240000
        2099999982780000
        2099999990550000
        2099999994330000
        2099999996220000
        2099999997060000
        2099999997480000
        2099999997690000
      "
      .unindent(),
    )
    .run();
}
