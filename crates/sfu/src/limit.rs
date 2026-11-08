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

    /// Whether at least half the burst is in. An oversized keyframe passes on half a bucket,
    /// so it cannot come more than about twice a second of the rate.
    pub fn half(&self) -> bool {
        self.tokens >= self.burst / 2.0
    }

    /// Empties the bucket. What a debt keyframe spent, the deltas wait for.
    pub fn drain(&mut self) {
        self.tokens = 0.0;
    }

    /// The largest frame a bucket ever accepts: twice the burst, so detailed content's
    /// keyframes pass while a flood does not.
    pub fn ceiling(&self) -> u32 {
        let doubled = self.burst * 2.0;
        if doubled >= u32::MAX as f64 {
            u32::MAX
        } else {
            doubled as u32
        }
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
}
