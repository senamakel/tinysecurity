use super::*;

#[test]
fn cancelled_work_releases_capacity_without_refunding_rate() {
    let mut budget = WorkBudget::default();
    let mut rate = RateCounter::new(0);
    assert_eq!(budget.reserve(&mut rate, 0, 1, 2), Ok(()));
    assert_eq!(
        budget.reserve(&mut rate, 0, 1, 2),
        Err(BudgetError::Capacity)
    );
    budget.release();
    assert_eq!(budget.reserve(&mut rate, 0, 1, 2), Ok(()));
    budget.release();
    assert_eq!(budget.reserve(&mut rate, 0, 1, 2), Err(BudgetError::Rate));
    assert_eq!(budget.reserve(&mut rate, 60_000, 1, 2), Ok(()));
}

#[test]
fn subjects_have_independent_rate_but_share_work_capacity() {
    let mut budget = WorkBudget::default();
    let mut first = RateCounter::new(0);
    let mut second = RateCounter::new(0);
    assert_eq!(budget.reserve(&mut first, 0, 2, 1), Ok(()));
    assert_eq!(budget.reserve(&mut second, 0, 2, 1), Ok(()));
    budget.release();
    assert_eq!(budget.reserve(&mut first, 0, 2, 1), Err(BudgetError::Rate));
    budget.release();
    budget.release();
    assert_eq!(budget.reserve(&mut second, 60_000, 2, 1), Ok(()));
}
