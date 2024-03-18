use {
  self::{flag::Flag, tag::Tag},
  super::*,
};

pub use {
  edict::Edict, etching::Etching, mint::Mint, pile::Pile, rune::Rune, rune_id::RuneId,
  runestone::Runestone, spaced_rune::SpacedRune,
};

pub const MAX_DIVISIBILITY: u8 = 38;
pub const MAX_LIMIT: u128 = 1 << 64;

const RESERVED: u128 = 6402364363415443603228541259936211926;
const MAGIC_NUMBER: opcodes::All = opcodes::all::OP_PUSHNUM_13;

mod edict;
mod etching;
mod flag;
mod mint;
mod pile;
mod rune;
mod rune_id;
mod runestone;
mod spaced_rune;
mod tag;
pub mod varint;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum MintError {
  Deadline((Rune, u32)),
  End((Rune, u32)),
  Unmintable(Rune),
}

impl fmt::Display for MintError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      MintError::Deadline((rune, deadline)) => {
        write!(f, "rune {rune} mint ended at {deadline}")
      }
      MintError::End((rune, end)) => write!(f, "rune {rune} mint ended on block {end}"),
      MintError::Unmintable(rune) => write!(f, "rune {rune} not mintable"),
    }
  }
}

#[cfg(test)]
mod tests {
  use {super::*, crate::index::testing::Context};

  const RUNE: u128 = 99246114928149462;

  #[test]
  fn index_starts_with_no_runes() {
    let context = Context::builder().arg("--index-runes").build();
    context.assert_runes([], []);
  }

  #[test]
  fn default_index_does_not_index_runes() {
    let context = Context::builder().build();

    context.mine_blocks(1);

    context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes([], []);
  }

  #[test]
  fn empty_runestone_does_not_create_rune() {
    let context = Context::builder().arg("--index-runes").build();

    context.mine_blocks(1);

    context.etch(Default::default(), 1);

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Witness::new())],
      op_return: Some(Runestone::default().encipher()),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes([], []);
  }

  #[test]
  fn etching_with_no_edicts_creates_rune() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn etching_with_edict_creates_rune() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn runes_must_be_greater_than_or_equal_to_minimum_for_height() {
    let minimum = Rune::minimum_at_height(Chain::Regtest, Height(RUNE_COMMIT_INTERVAL + 2)).0;

    {
      let context = Context::builder()
        .chain(Chain::Regtest)
        .arg("--index-runes")
        .build();

      context.etch(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(Rune(minimum - 1)),
            ..Default::default()
          }),
          ..Default::default()
        },
        1,
      );

      context.assert_runes([], []);
    }

    {
      let context = Context::builder()
        .chain(Chain::Regtest)
        .arg("--index-runes")
        .build();

      let (txid, id) = context.etch(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(Rune(minimum)),
            ..Default::default()
          }),
          ..Default::default()
        },
        1,
      );

      context.assert_runes(
        [(
          id,
          RuneEntry {
            etching: txid,
            rune: Rune(minimum),
            supply: u128::MAX,
            timestamp: id.block,
            ..Default::default()
          },
        )],
        [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
      );
    }
  }

  #[test]
  fn etching_cannot_specify_reserved_rune() {
    {
      let context = Context::builder().arg("--index-runes").build();

      context.etch(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(Rune(RESERVED)),
            ..Default::default()
          }),
          ..Default::default()
        },
        1,
      );

      context.assert_runes([], []);
    }

    {
      let context = Context::builder().arg("--index-runes").build();

      let (txid, id) = context.etch(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching {
            rune: Some(Rune(RESERVED - 1)),
            ..Default::default()
          }),
          ..Default::default()
        },
        1,
      );

      context.assert_runes(
        [(
          id,
          RuneEntry {
            etching: txid,
            rune: Rune(RESERVED - 1),
            supply: u128::MAX,
            timestamp: id.block,
            ..Default::default()
          },
        )],
        [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
      );
    }
  }

  #[test]
  fn reserved_runes_may_be_etched() {
    let context = Context::builder().arg("--index-runes").build();

    context.mine_blocks(1);

    let txid0 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching {
            rune: None,
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    let id0 = RuneId { block: 2, tx: 1 };

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id0,
        RuneEntry {
          etching: txid0,
          rune: Rune(RESERVED),
          supply: u128::MAX,
          timestamp: 2,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id0, u128::MAX)],
      )],
    );

    context.mine_blocks(1);

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching {
            rune: None,
            ..Default::default()
          }),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    let id1 = RuneId { block: 4, tx: 1 };

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RESERVED),
            supply: u128::MAX,
            timestamp: 2,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RESERVED + 1),
            supply: u128::MAX,
            timestamp: 4,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid0,
            vout: 0,
          },
          vec![(id0, u128::MAX)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id1, u128::MAX)],
        ),
      ],
    );
  }

  #[test]
  fn etching_with_non_zero_divisibility_and_rune() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          divisibility: 1,
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          rune: Rune(RUNE),
          etching: txid,
          divisibility: 1,
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn allocations_over_max_supply_are_ignored() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          },
          Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn allocations_partially_over_max_supply_are_honored() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: u128::MAX / 2,
            output: 0,
          },
          Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          symbol: None,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn etching_may_allocate_less_than_max_supply() {
    let context = Context::builder().arg("--index-runes").build();

    context.mine_blocks(1);

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: 100,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: 100,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, 100)])],
    );
  }

  #[test]
  fn etching_may_allocate_to_multiple_outputs() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: 100,
            output: 0,
          },
          Edict {
            id: 0,
            amount: 100,
            output: 1,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          burned: 100,
          etching: txid,
          rune: Rune(RUNE),
          supply: 200,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, 100)])],
    );
  }

  #[test]
  fn allocations_to_invalid_outputs_are_ignored() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: 100,
            output: 0,
          },
          Edict {
            id: 0,
            amount: 100,
            output: 3,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: 100,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, 100)])],
    );
  }

  #[test]
  fn input_runes_may_be_allocated() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: id.into(),
            amount: u128::MAX,
            output: 0,
          }],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );
  }

  #[test]
  fn etched_rune_is_allocated_with_zero_supply_for_burned_runestone() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        default_output: None,
        burn: true,
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn etched_rune_open_etching_parameters_are_unset_for_burned_runestone() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            deadline: Some(1),
            limit: Some(1),
            term: Some(1),
          }),
          divisibility: 1,
          symbol: Some('$'),
          spacers: 1,
        }),
        burn: true,
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          burned: 0,
          divisibility: 1,
          etching: txid0,
          mint: None,
          mints: 0,
          number: 0,
          rune: Rune(RUNE),
          spacers: 1,
          supply: 0,
          symbol: Some('$'),
          timestamp: id.block,
        },
      )],
      [],
    );
  }

  #[test]
  fn etched_reserved_rune_is_allocated_with_zero_supply_for_burned_runestone() {
    let context = Context::builder().arg("--index-runes").build();

    context.mine_blocks(1);

    let txid0 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(1, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          }],
          etching: Some(Etching::default()),
          burn: true,
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    let id = RuneId { block: 2, tx: 1 };

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RESERVED),
          timestamp: 2,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn input_runes_are_burned_if_an_unrecognized_even_tag_is_encountered() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(
        Runestone {
          burn: true,
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          burned: u128::MAX,
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn unallocated_runes_are_assigned_to_first_non_op_return_output() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(Runestone::default().encipher()),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );
  }

  #[test]
  fn unallocated_runes_are_burned_if_no_non_op_return_output_is_present() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(Runestone::default().encipher()),
      outputs: 0,
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          burned: u128::MAX,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn unallocated_runes_are_assigned_to_default_output() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          default_output: Some(1),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 1,
        },
        vec![(id, u128::MAX)],
      )],
    );
  }

  #[test]
  fn unallocated_runes_are_assigned_to_first_non_op_return_output_if_default_is_too_large() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          default_output: Some(3),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );
  }

  #[test]
  fn unallocated_runes_are_burned_if_default_output_is_op_return() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          default_output: Some(2),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          burned: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn unallocated_runes_in_transactions_with_no_runestone_are_assigned_to_first_non_op_return_output(
  ) {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: None,
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );
  }

  #[test]
  fn duplicate_runes_are_forbidden() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );

    context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn output_may_hold_multiple_runes() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id0) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id0,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id0.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id0, u128::MAX)],
      )],
    );

    let (txid1, id1) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE + 1)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid0,
            vout: 0,
          },
          vec![(id0, u128::MAX)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id1, u128::MAX)],
        ),
      ],
    );

    let txid2 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (id0.block.try_into().unwrap(), 1, 0, Witness::new()),
        (id1.block.try_into().unwrap(), 1, 0, Witness::new()),
      ],
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [(
        OutPoint {
          txid: txid2,
          vout: 0,
        },
        vec![(id0, u128::MAX), (id1, u128::MAX)],
      )],
    );
  }

  #[test]
  fn multiple_input_runes_on_the_same_input_may_be_allocated() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id0) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id0,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id0.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id0, u128::MAX)],
      )],
    );

    let (txid1, id1) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE + 1)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid0,
            vout: 0,
          },
          vec![(id0, u128::MAX)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id1, u128::MAX)],
        ),
      ],
    );

    let txid2 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (id0.block.try_into().unwrap(), 1, 0, Witness::new()),
        (id1.block.try_into().unwrap(), 1, 0, Witness::new()),
      ],
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [(
        OutPoint {
          txid: txid2,
          vout: 0,
        },
        vec![(id0, u128::MAX), (id1, u128::MAX)],
      )],
    );

    let txid3 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[((id1.block + 1).try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: id0.into(),
              amount: u128::MAX / 2,
              output: 1,
            },
            Edict {
              id: id1.into(),
              amount: u128::MAX / 2,
              output: 1,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid3,
            vout: 0,
          },
          vec![(id0, u128::MAX / 2 + 1), (id1, u128::MAX / 2 + 1)],
        ),
        (
          OutPoint {
            txid: txid3,
            vout: 1,
          },
          vec![(id0, u128::MAX / 2), (id1, u128::MAX / 2)],
        ),
      ],
    );
  }

  #[test]
  fn multiple_input_runes_on_different_inputs_may_be_allocated() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id0) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id0,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id0.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id0, u128::MAX)],
      )],
    );

    let (txid1, id1) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE + 1)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid0,
            vout: 0,
          },
          vec![(id0, u128::MAX)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id1, u128::MAX)],
        ),
      ],
    );

    let txid2 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[
        (id0.block.try_into().unwrap(), 1, 0, Witness::new()),
        (id1.block.try_into().unwrap(), 1, 0, Witness::new()),
      ],
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: id0.into(),
              amount: u128::MAX,
              output: 0,
            },
            Edict {
              id: id1.into(),
              amount: u128::MAX,
              output: 0,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [(
        OutPoint {
          txid: txid2,
          vout: 0,
        },
        vec![(id0, u128::MAX), (id1, u128::MAX)],
      )],
    );
  }

  #[test]
  fn unallocated_runes_are_assigned_to_first_non_op_return_output_when_op_return_is_not_last_output(
  ) {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(
        script::Builder::new()
          .push_opcode(opcodes::all::OP_RETURN)
          .into_script(),
      ),
      op_return_index: Some(0),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 1 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn rune_rarity_is_assigned_correctly() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id0) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    let (txid1, id1) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE + 1)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid0,
            vout: 0,
          },
          vec![(id0, u128::MAX)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id1, u128::MAX)],
        ),
      ],
    );
  }

  #[test]
  fn edicts_with_id_zero_are_skipped() {
    let context = Context::builder().arg("--index-runes").build();

    context.mine_blocks(1);

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: 0,
              amount: 100,
              output: 0,
            },
            Edict {
              id: id.into(),
              amount: u128::MAX,
              output: 0,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );
  }

  #[test]
  fn edicts_which_refer_to_input_rune_with_no_balance_are_skipped() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id0) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id0,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id0.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id0, u128::MAX)],
      )],
    );

    let (txid1, id1) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE + 1)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid0,
            vout: 0,
          },
          vec![(id0, u128::MAX)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id1, u128::MAX)],
        ),
      ],
    );

    let txid2 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id0.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: id0.into(),
              amount: u128::MAX,
              output: 0,
            },
            Edict {
              id: id1.into(),
              amount: u128::MAX,
              output: 0,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [
        (
          id0,
          RuneEntry {
            etching: txid0,
            rune: Rune(RUNE),
            supply: u128::MAX,
            timestamp: id0.block,
            ..Default::default()
          },
        ),
        (
          id1,
          RuneEntry {
            etching: txid1,
            rune: Rune(RUNE + 1),
            supply: u128::MAX,
            timestamp: id1.block,
            number: 1,
            ..Default::default()
          },
        ),
      ],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id1, u128::MAX)],
        ),
        (
          OutPoint {
            txid: txid2,
            vout: 0,
          },
          vec![(id0, u128::MAX)],
        ),
      ],
    );
  }

  #[test]
  fn edicts_over_max_inputs_are_ignored() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX / 2,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX / 2,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX / 2)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: id.into(),
            amount: u128::MAX,
            output: 0,
          }],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX / 2,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, u128::MAX / 2)],
      )],
    );
  }

  #[test]
  fn edicts_may_transfer_runes_to_op_return_outputs() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 1,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          burned: u128::MAX,
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn outputs_with_no_runes_have_no_balance() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn edicts_which_transfer_no_runes_to_output_create_no_balance_entry() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          },
          Edict {
            id: 0,
            amount: 0,
            output: 1,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn split_in_etching() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: 0,
          output: 5,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      4,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (OutPoint { txid, vout: 0 }, vec![(id, u128::MAX / 4 + 1)]),
        (OutPoint { txid, vout: 1 }, vec![(id, u128::MAX / 4 + 1)]),
        (OutPoint { txid, vout: 2 }, vec![(id, u128::MAX / 4 + 1)]),
        (OutPoint { txid, vout: 3 }, vec![(id, u128::MAX / 4)]),
      ],
    );
  }

  #[test]
  fn split_in_etching_with_preceding_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: 1000,
            output: 0,
          },
          Edict {
            id: 0,
            amount: 0,
            output: 5,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      4,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint { txid, vout: 0 },
          vec![(id, 1000 + (u128::MAX - 1000) / 4 + 1)],
        ),
        (
          OutPoint { txid, vout: 1 },
          vec![(id, (u128::MAX - 1000) / 4 + 1)],
        ),
        (
          OutPoint { txid, vout: 2 },
          vec![(id, (u128::MAX - 1000) / 4 + 1)],
        ),
        (
          OutPoint { txid, vout: 3 },
          vec![(id, (u128::MAX - 1000) / 4)],
        ),
      ],
    );
  }

  #[test]
  fn split_in_etching_with_following_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: 0,
            output: 5,
          },
          Edict {
            id: 0,
            amount: 1000,
            output: 0,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      4,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (OutPoint { txid, vout: 0 }, vec![(id, u128::MAX / 4 + 1)]),
        (OutPoint { txid, vout: 1 }, vec![(id, u128::MAX / 4 + 1)]),
        (OutPoint { txid, vout: 2 }, vec![(id, u128::MAX / 4 + 1)]),
        (OutPoint { txid, vout: 3 }, vec![(id, u128::MAX / 4)]),
      ],
    );
  }

  #[test]
  fn split_with_amount_in_etching() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: 1000,
          output: 5,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      4,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: 4000,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (OutPoint { txid, vout: 0 }, vec![(id, 1000)]),
        (OutPoint { txid, vout: 1 }, vec![(id, 1000)]),
        (OutPoint { txid, vout: 2 }, vec![(id, 1000)]),
        (OutPoint { txid, vout: 3 }, vec![(id, 1000)]),
      ],
    );
  }

  #[test]
  fn split_in_etching_with_amount_with_preceding_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: u128::MAX - 3000,
            output: 0,
          },
          Edict {
            id: 0,
            amount: 1000,
            output: 5,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      4,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (OutPoint { txid, vout: 0 }, vec![(id, u128::MAX - 2000)]),
        (OutPoint { txid, vout: 1 }, vec![(id, 1000)]),
        (OutPoint { txid, vout: 2 }, vec![(id, 1000)]),
      ],
    );
  }

  #[test]
  fn split_in_etching_with_amount_with_following_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![
          Edict {
            id: 0,
            amount: 1000,
            output: 5,
          },
          Edict {
            id: 0,
            amount: u128::MAX,
            output: 0,
          },
        ],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      4,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint { txid, vout: 0 },
          vec![(id, u128::MAX - 4000 + 1000)],
        ),
        (OutPoint { txid, vout: 1 }, vec![(id, 1000)]),
        (OutPoint { txid, vout: 2 }, vec![(id, 1000)]),
        (OutPoint { txid, vout: 3 }, vec![(id, 1000)]),
      ],
    );
  }

  #[test]
  fn split() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: id.into(),
            amount: 0,
            output: 3,
          }],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, u128::MAX / 2 + 1)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 1,
          },
          vec![(id, u128::MAX / 2)],
        ),
      ],
    );
  }

  #[test]
  fn split_with_preceding_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: id.into(),
              amount: 1000,
              output: 0,
            },
            Edict {
              id: id.into(),
              amount: 0,
              output: 3,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, 1000 + (u128::MAX - 1000) / 2 + 1)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 1,
          },
          vec![(id, (u128::MAX - 1000) / 2)],
        ),
      ],
    );
  }

  #[test]
  fn split_with_following_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: id.into(),
              amount: 0,
              output: 3,
            },
            Edict {
              id: id.into(),
              amount: 1000,
              output: 1,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, u128::MAX / 2 + 1)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 1,
          },
          vec![(id, u128::MAX / 2)],
        ),
      ],
    );
  }

  #[test]
  fn split_with_amount() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: id.into(),
            amount: 1000,
            output: 3,
          }],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, u128::MAX - 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 1,
          },
          vec![(id, 1000)],
        ),
      ],
    );
  }

  #[test]
  fn split_with_amount_with_preceding_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 4,
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: id.into(),
              amount: u128::MAX - 2000,
              output: 0,
            },
            Edict {
              id: id.into(),
              amount: 1000,
              output: 5,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, u128::MAX - 2000 + 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 1,
          },
          vec![(id, 1000)],
        ),
      ],
    );
  }

  #[test]
  fn split_with_amount_with_following_edict() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 4,
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: id.into(),
              amount: 1000,
              output: 5,
            },
            Edict {
              id: id.into(),
              amount: u128::MAX,
              output: 0,
            },
          ],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, u128::MAX - 4000 + 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 1,
          },
          vec![(id, 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 2,
          },
          vec![(id, 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 3,
          },
          vec![(id, 1000)],
        ),
      ],
    );
  }

  #[test]
  fn etching_may_specify_symbol() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          symbol: Some('$'),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          symbol: Some('$'),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn allocate_all_remaining_runes_in_etching() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: 0,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, u128::MAX)])],
    );
  }

  #[test]
  fn allocate_all_remaining_runes_in_inputs() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: u128::MAX,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, u128::MAX)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 1, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: id.into(),
            amount: 0,
            output: 1,
          }],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: u128::MAX,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 1,
        },
        vec![(id, u128::MAX)],
      )],
    );
  }

  #[test]
  fn max_limit() {
    MAX_LIMIT
      .checked_mul(u128::from(u16::MAX) * u128::from(RUNE_COMMIT_INTERVAL) * 365 * 1_000_000_000)
      .unwrap();
  }

  #[test]
  fn rune_can_be_minted_without_edict() {
    let context = Context::builder().arg("--index-runes").build();

    // etch the rune
    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: id.block,
          mints: 0,
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        },
      )],
      [],
    );

    // claim the rune
    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          mints: 1,
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );
  }

  #[test]
  fn etching_with_limit_can_be_minted() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: id.block,
          mints: 0,
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        },
      )],
      [],
    );

    // claim the rune
    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(3, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1000,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          mints: 1,
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );

    // claim the rune
    let txid2 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(4, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1000,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          mints: 2,
          rune: Rune(RUNE),
          supply: 2000,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid2,
            vout: 0,
          },
          vec![(id, 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, 1000)],
        ),
      ],
    );

    // claim the rune in a burn runestone
    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(5, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          burn: true,
          claim: Some(id),
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1000,
            output: 0,
          }],
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          burned: 1000,
          etching: txid0,
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          mints: 3,
          rune: Rune(RUNE),
          supply: 3000,
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid2,
            vout: 0,
          },
          vec![(id, 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, 1000)],
        ),
      ],
    );
  }

  #[test]
  fn open_etchings_can_be_limited_to_term() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            term: Some(2),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            end: Some(id.block + 2),
            ..Default::default()
          }),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1000,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            end: Some(id.block + 2),
            ..Default::default()
          }),
          supply: 1000,
          timestamp: id.block,
          mints: 1,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(3, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1000,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          mint: Some(MintEntry {
            limit: Some(1000),
            end: Some(id.block + 2),
            ..Default::default()
          }),
          mints: 1,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );
  }

  #[test]
  fn open_etchings_with_term_zero_cannot_be_minted() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        edicts: vec![Edict {
          id: 0,
          amount: 1000,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            term: Some(0),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            end: Some(id.block),
            ..Default::default()
          }),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1,
            output: 3,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          timestamp: id.block,
          mint: Some(MintEntry {
            limit: Some(1000),
            end: Some(id.block),
            ..Default::default()
          }),
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn open_etchings_with_end_before_deadline() {
    let context = Context::builder().arg("--index-runes").build();

    context.mine_blocks(1);

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            deadline: Some(12),
            term: Some(2),
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: 9,
          mint: Some(MintEntry {
            deadline: Some(12),
            end: Some(11),
            limit: Some(1000),
          }),
          ..Default::default()
        },
      )],
      [],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(id.block.try_into().unwrap(), 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: 9,
          mints: 1,
          etching: txid0,
          mint: Some(MintEntry {
            deadline: Some(12),
            end: Some(11),
            limit: Some(1000),
          }),
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(3, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: 9,
          mint: Some(MintEntry {
            limit: Some(1000),
            deadline: Some(12),
            end: Some(11),
          }),
          mints: 1,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );
  }

  #[test]
  fn open_etchings_with_deadline_before_end() {
    let context = Context::builder().arg("--index-runes").build();

    context.mine_blocks(1);

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            deadline: Some(11),
            term: Some(3),
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: id.block,
          mint: Some(MintEntry {
            deadline: Some(11),
            end: Some(12),
            limit: Some(1000),
          }),
          ..Default::default()
        },
      )],
      [],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(3, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          mints: 1,
          etching: txid0,
          mint: Some(MintEntry {
            deadline: Some(11),
            end: Some(12),
            limit: Some(1000),
          }),
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(4, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          mint: Some(MintEntry {
            limit: Some(1000),
            deadline: Some(11),
            end: Some(12),
          }),
          mints: 1,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );
  }

  #[test]
  fn open_etchings_can_be_limited_to_deadline() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            deadline: Some(RUNE_COMMIT_INTERVAL + 4),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: id.block,
          mint: Some(MintEntry {
            deadline: Some(id.block + 2),
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        },
      )],
      [],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1000,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          mints: 1,
          etching: txid0,
          mint: Some(MintEntry {
            deadline: Some(id.block + 2),
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(3, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 1000,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          mint: Some(MintEntry {
            limit: Some(1000),
            deadline: Some(id.block + 2),
            ..Default::default()
          }),
          mints: 1,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );
  }

  #[test]
  fn open_etching_claims_can_use_split() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(3, 0, 0, Witness::new())],
      outputs: 2,
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 0,
            output: 3,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          supply: 1000,
          timestamp: id.block,
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          mints: 1,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, 500)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 1,
          },
          vec![(id, 500)],
        ),
      ],
    );
  }

  #[test]
  fn runes_can_be_etched_and_claimed_in_the_same_transaction() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        }),
        edicts: vec![Edict {
          id: 0,
          amount: 2000,
          output: 0,
        }],
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          timestamp: id.block,
          supply: 1000,
          ..Default::default()
        },
      )],
      [(OutPoint { txid, vout: 0 }, vec![(id, 1000)])],
    );
  }

  #[test]
  fn limit_over_max_is_clamped() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(MAX_LIMIT + 1),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: id.block,
          mint: Some(MintEntry {
            limit: Some(MAX_LIMIT),
            deadline: None,
            end: None,
          }),
          ..Default::default()
        },
      )],
      [],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: MAX_LIMIT + 1,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          timestamp: id.block,
          mints: 1,
          supply: MAX_LIMIT,
          mint: Some(MintEntry {
            limit: Some(MAX_LIMIT),
            deadline: None,
            end: None,
          }),
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, MAX_LIMIT)],
      )],
    );
  }

  #[test]
  fn omitted_limit_defaults_to_max_limit() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            term: Some(1),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: None,
            end: Some(id.block + 1),
            ..Default::default()
          }),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );
  }

  #[test]
  fn transactions_cannot_claim_more_than_limit() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        }),
        edicts: vec![Edict {
          id: 0,
          amount: 2000,
          output: 0,
        }],
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          timestamp: id.block,
          supply: 1000,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid0,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![Edict {
            id: u128::from(id),
            amount: 2000,
            output: 0,
          }],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          timestamp: id.block,
          supply: 2000,
          mints: 1,
          ..Default::default()
        },
      )],
      [
        (
          OutPoint {
            txid: txid0,
            vout: 0,
          },
          vec![(id, 1000)],
        ),
        (
          OutPoint {
            txid: txid1,
            vout: 0,
          },
          vec![(id, 1000)],
        ),
      ],
    );
  }

  #[test]
  fn multiple_edicts_in_one_transaction_may_claim_open_etching() {
    let context = Context::builder().arg("--index-runes").build();

    let (txid0, id) = context.etch(
      Runestone {
        etching: Some(Etching {
          rune: Some(Rune(RUNE)),
          mint: Some(Mint {
            limit: Some(1000),
            ..Default::default()
          }),
          ..Default::default()
        }),
        ..Default::default()
      },
      1,
    );

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          timestamp: id.block,
          ..Default::default()
        },
      )],
      [],
    );

    let txid1 = context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(2, 0, 0, Witness::new())],
      op_return: Some(
        Runestone {
          edicts: vec![
            Edict {
              id: u128::from(id),
              amount: 500,
              output: 0,
            },
            Edict {
              id: u128::from(id),
              amount: 500,
              output: 0,
            },
            Edict {
              id: u128::from(id),
              amount: 500,
              output: 0,
            },
          ],
          claim: Some(id),
          ..Default::default()
        }
        .encipher(),
      ),
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes(
      [(
        id,
        RuneEntry {
          etching: txid0,
          rune: Rune(RUNE),
          mint: Some(MintEntry {
            limit: Some(1000),
            ..Default::default()
          }),
          timestamp: id.block,
          supply: 1000,
          mints: 1,
          ..Default::default()
        },
      )],
      [(
        OutPoint {
          txid: txid1,
          vout: 0,
        },
        vec![(id, 1000)],
      )],
    );
  }

  #[test]
  fn commits_are_not_valid_in_non_taproot_witnesses() {
    let context = Context::builder().arg("--index-runes").build();

    let block_count = usize::try_from(context.index.block_count().unwrap()).unwrap();

    context.mine_blocks(1);

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(block_count, 0, 0, Witness::new())],
      p2tr: false,
      ..Default::default()
    });

    context.mine_blocks(RUNE_COMMIT_INTERVAL.into());

    let mut witness = Witness::new();

    let runestone = Runestone {
      etching: Some(Etching {
        rune: Some(Rune(RUNE)),
        mint: Some(Mint {
          limit: Some(1000),
          ..Default::default()
        }),
        ..Default::default()
      }),
      ..Default::default()
    };

    let tapscript = script::Builder::new()
      .push_slice::<&PushBytes>(
        runestone
          .etching
          .unwrap()
          .rune
          .unwrap()
          .commitment()
          .as_slice()
          .try_into()
          .unwrap(),
      )
      .into_script();

    witness.push(tapscript);

    witness.push([]);

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(block_count + 1, 1, 0, witness)],
      op_return: Some(runestone.encipher()),
      outputs: 1,
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes([], []);
  }

  #[test]
  fn immature_commits_are_not_valid() {
    let context = Context::builder().arg("--index-runes").build();

    let block_count = usize::try_from(context.index.block_count().unwrap()).unwrap();

    context.mine_blocks(1);

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(block_count, 0, 0, Witness::new())],
      p2tr: true,
      ..Default::default()
    });

    context.mine_blocks((RUNE_COMMIT_INTERVAL - 1).into());

    let mut witness = Witness::new();

    let runestone = Runestone {
      etching: Some(Etching {
        rune: Some(Rune(RUNE)),
        mint: Some(Mint {
          limit: Some(1000),
          ..Default::default()
        }),
        ..Default::default()
      }),
      ..Default::default()
    };

    let tapscript = script::Builder::new()
      .push_slice::<&PushBytes>(
        runestone
          .etching
          .unwrap()
          .rune
          .unwrap()
          .commitment()
          .as_slice()
          .try_into()
          .unwrap(),
      )
      .into_script();

    witness.push(tapscript);

    witness.push([]);

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(block_count + 1, 1, 0, witness)],
      op_return: Some(runestone.encipher()),
      outputs: 1,
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes([], []);
  }

  #[test]
  fn etchings_are_not_valid_without_commitment() {
    let context = Context::builder().arg("--index-runes").build();

    let block_count = usize::try_from(context.index.block_count().unwrap()).unwrap();

    context.mine_blocks(1);

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(block_count, 0, 0, Witness::new())],
      p2tr: true,
      ..Default::default()
    });

    context.mine_blocks((RUNE_COMMIT_INTERVAL).into());

    let mut witness = Witness::new();

    let runestone = Runestone {
      etching: Some(Etching {
        rune: Some(Rune(RUNE)),
        mint: Some(Mint {
          limit: Some(1000),
          ..Default::default()
        }),
        ..Default::default()
      }),
      ..Default::default()
    };

    let tapscript = script::Builder::new()
      .push_slice::<&PushBytes>([].as_slice().try_into().unwrap())
      .into_script();

    witness.push(tapscript);

    witness.push([]);

    context.rpc_server.broadcast_tx(TransactionTemplate {
      inputs: &[(block_count + 1, 1, 0, witness)],
      op_return: Some(runestone.encipher()),
      outputs: 1,
      ..Default::default()
    });

    context.mine_blocks(1);

    context.assert_runes([], []);
  }
}
