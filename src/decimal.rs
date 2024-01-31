use super::*;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Decimal {
  value: u128,
  scale: u8,
}

impl Decimal {
  pub(crate) fn to_amount(self, divisibility: u8) -> Result<u128> {
    match divisibility.checked_sub(self.scale) {
      Some(difference) => Ok(
        self
          .value
          .checked_mul(
            10u128
              .checked_pow(u32::from(difference))
              .context("divisibility out of range")?,
          )
          .context("amount out of range")?,
      ),
      None => bail!("excessive precision"),
    }
  }
}

impl Display for Decimal {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let magnitude = 10u128.pow(self.scale.into());

    let integer = self.value / magnitude;
    let fraction = self.value % magnitude;

    write!(f, "{integer}")?;

    if fraction > 0 {
      write!(f, ".{fraction}")?;
    }

    Ok(())
  }
}

impl FromStr for Decimal {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    if let Some((integer, decimal)) = s.split_once('.') {
      if integer.is_empty() && decimal.is_empty() {
        bail!("empty decimal");
      }

      let integer = if integer.is_empty() {
        0
      } else {
        integer.parse::<u128>()?
      };

      let decimal = if decimal.is_empty() {
        0
      } else {
        decimal.parse::<u128>()?
      };

      let scale = s
        .trim_end_matches('0')
        .chars()
        .skip_while(|c| *c != '.')
        .skip(1)
        .count()
        .try_into()?;

      Ok(Self {
        value: integer * 10u128.pow(u32::from(scale)) + decimal,
        scale,
      })
    } else {
      Ok(Self {
        value: s.parse::<u128>()?,
        scale: 0,
      })
    }
  }
}

impl Serialize for Decimal {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.collect_str(self)
  }
}

impl<'de> Deserialize<'de> for Decimal {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    Ok(DeserializeFromStr::deserialize(deserializer)?.0)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn from_str() {
    #[track_caller]
    fn case(s: &str, value: u128, scale: u8) {
      assert_eq!(s.parse::<Decimal>().unwrap(), Decimal { value, scale });
    }

    assert_eq!(
      ".".parse::<Decimal>().unwrap_err().to_string(),
      "empty decimal",
    );

    assert_eq!(
      "a.b".parse::<Decimal>().unwrap_err().to_string(),
      "invalid digit found in string",
    );

    assert_eq!(
      " 0.1 ".parse::<Decimal>().unwrap_err().to_string(),
      "invalid digit found in string",
    );

    case("0", 0, 0);
    case("0.00000", 0, 0);
    case("1.0", 1, 0);
    case("1.1", 11, 1);
    case("1.11", 111, 2);
    case("1.", 1, 0);
    case(".1", 1, 1);
  }

  #[test]
  fn to_amount() {
    #[track_caller]
    fn case(s: &str, divisibility: u8, amount: u128) {
      assert_eq!(
        s.parse::<Decimal>()
          .unwrap()
          .to_amount(divisibility)
          .unwrap(),
        amount,
      );
    }

    assert_eq!(
      Decimal { value: 0, scale: 0 }
        .to_amount(255)
        .unwrap_err()
        .to_string(),
      "divisibility out of range"
    );

    assert_eq!(
      Decimal {
        value: u128::MAX,
        scale: 0,
      }
      .to_amount(1)
      .unwrap_err()
      .to_string(),
      "amount out of range",
    );

    assert_eq!(
      Decimal { value: 1, scale: 1 }
        .to_amount(0)
        .unwrap_err()
        .to_string(),
      "excessive precision",
    );

    case("1", 0, 1);
    case("1.0", 0, 1);
    case("1.0", 1, 10);
    case("1.2", 1, 12);
    case("1.2", 2, 120);
    case("123.456", 3, 123456);
    case("123.456", 6, 123456000);
  }

  #[test]
  fn to_string() {
    #[track_caller]
    fn case(decimal: Decimal, string: &str) {
      assert_eq!(decimal.to_string(), string);
      assert_eq!(decimal, string.parse::<Decimal>().unwrap());
    }

    case(Decimal { value: 1, scale: 0 }, "1");
    case(Decimal { value: 1, scale: 1 }, "0.1");
    case(
      Decimal {
        value: 12,
        scale: 0,
      },
      "12",
    );
    case(
      Decimal {
        value: 12,
        scale: 1,
      },
      "1.2",
    );
    case(
      Decimal {
        value: 12,
        scale: 2,
      },
      "0.12",
    );
    case(
      Decimal {
        value: 123456,
        scale: 3,
      },
      "123.456",
    );
    case(
      Decimal {
        value: 123456789,
        scale: 6,
      },
      "123.456789",
    );
  }
}
