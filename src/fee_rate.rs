use super::*;

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) struct FeeRate(f64);

impl FromStr for FeeRate {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    Self::try_from(f64::from_str(s)?)
  }
}

impl TryFrom<f64> for FeeRate {
  type Error = Error;

  fn try_from(float: f64) -> Result<Self, Self::Error> {
    if float.is_sign_negative() | float.is_nan() | float.is_infinite() {
      return Err(anyhow!("fee rate can not be negative"));
    }
    Ok(Self(float))
  }
}

impl FeeRate {
  pub(crate) fn fee(&self, vsize: usize) -> Amount {
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    Amount::from_sat((self.0 * vsize as f64).round() as u64)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse() {
    assert_eq!("1.1".parse::<FeeRate>().unwrap().0, 1.1);
    assert_eq!("11.19".parse::<FeeRate>().unwrap().0, 11.19);
    assert_eq!("11.1111".parse::<FeeRate>().unwrap().0, 11.1111);
    assert!("-4.2".parse::<FeeRate>().is_err());
    assert!(FeeRate::try_from(f64::INFINITY).is_err());
    assert!(FeeRate::try_from(f64::NAN).is_err());
  }

  #[test]
  fn fee() {
    assert_eq!(
      "2.5".parse::<FeeRate>().unwrap().fee(100),
      Amount::from_sat(250)
    );
    assert_eq!(
      "2.0".parse::<FeeRate>().unwrap().fee(1024),
      Amount::from_sat(2048)
    );
    assert_eq!(
      "1.1".parse::<FeeRate>().unwrap().fee(100),
      Amount::from_sat(110)
    );
    assert_eq!(
      "1.0".parse::<FeeRate>().unwrap().fee(123456789),
      Amount::from_sat(123456789)
    );
  }
}
