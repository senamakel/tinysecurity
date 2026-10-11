use super::*;
#[test]
fn every_reservation_counts_and_exact_window_boundary_refills() -> Result<()> {
    let mut budget = Budget::new(0);
    budget.reserve(0, 10, 2)?;
    budget.reserve(0, 10, 2)?;
    assert_eq!(budget.reserve(9, 10, 2), Err(Error::Budget));
    budget.reserve(10, 10, 2)?;
    assert_eq!(budget.reserve(9, 10, 2), Err(Error::Budget));
    assert_eq!(budget.reserve(100, 10, 2), Err(Error::Budget));
    Ok(())
}
