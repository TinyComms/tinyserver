//! Token buckets for packet rates and audio bitrates.

use std::time::Instant;

/// `rate` units a second, with `burst` above that.
#[derive(Debug, Clone)]
pub(crate) struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    pub fn new(rate: u32, burst: u32, now: Instant) -> Self {
        let burst = f64::from(burst.max(1));
        Self {
            rate: f64::from(rate.max(1)),
            burst,
            tokens: burst,
            at: now,
        }
    }

    /// Takes `cost` units if there are that many.
    pub fn take(&mut self, cost: u32, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        let cost = f64::from(cost);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// When this bucket was last used.
    pub fn used(&self) -> Instant {
        self.at
    }

    /// Refills, then grants `cost` even when the balance falls short of it, drawing the
    /// balance negative: the frames that follow wait for the refill, so the average stays
    /// at the rate. True when the grant went through, which needs half the burst refilled
    /// and `cost` within twice the burst.
    pub fn overdraw(&mut self, cost: u32, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        let cost = f64::from(cost);
        if self.tokens < self.burst / 2.0 || cost > self.burst * 2.0 {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::Bucket;
    use std::time::{Duration, Instant};

    #[test]
    fn a_burst_passes_then_the_rate_refills_it() {
        let start = Instant::now();
        let mut bucket = Bucket::new(10, 3, start);
        assert!(bucket.take(1, start));
        assert!(bucket.take(2, start));
        assert!(!bucket.take(1, start));
        assert!(bucket.take(1, start + Duration::from_millis(100)));
        assert!(!bucket.take(1, start + Duration::from_millis(100)));
    }

    #[test]
    fn a_cost_bigger_than_the_burst_never_passes() {
        let start = Instant::now();
        let mut bucket = Bucket::new(10, 3, start);
        assert!(!bucket.take(4, start + Duration::from_secs(60)));
    }

    #[test]
    fn an_overdraw_draws_the_balance_negative_and_the_refill_pays_it_back() {
        let start = Instant::now();
        let mut bucket = Bucket::new(10, 3, start);
        assert!(bucket.overdraw(6, start));
        assert!(!bucket.take(1, start), "the balance is negative");
        assert!(
            bucket.take(1, start + Duration::from_millis(400)),
            "the refill repaid the overdraft"
        );
        assert!(!bucket.overdraw(7, start + Duration::from_millis(400)));
    }
}
