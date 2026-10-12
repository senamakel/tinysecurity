//! Shared admission accounting; no wait queue and no work runs under this owner.
#[derive(Default)]
pub(crate) struct WorkBudget {
    in_flight: u32,
}
pub(crate) struct RateCounter {
    minute: u64,
    operations: u32,
}
impl RateCounter {
    pub(crate) fn new(monotonic: u64) -> Self {
        Self {
            minute: monotonic / 60_000,
            operations: 0,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BudgetError {
    Capacity,
    Rate,
}
impl WorkBudget {
    pub(crate) fn reserve(
        &mut self,
        rate: &mut RateCounter,
        monotonic: u64,
        max_in_flight: u32,
        max_rate: u32,
    ) -> std::result::Result<(), BudgetError> {
        if self.in_flight >= max_in_flight {
            return Err(BudgetError::Capacity);
        }
        let minute = monotonic / 60_000;
        if minute != rate.minute {
            rate.minute = minute;
            rate.operations = 0;
        }
        if rate.operations >= max_rate {
            return Err(BudgetError::Rate);
        }
        rate.operations += 1;
        self.in_flight += 1;
        Ok(())
    }
    pub(crate) fn full(&self, maximum: u32) -> bool {
        self.in_flight >= maximum
    }
    pub(crate) fn release(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
}
#[cfg(test)]
#[path = "work_budget_tests.rs"]
mod tests;
