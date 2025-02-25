//! Types that should be part of the standard library, but aren't.

use std::time::SystemTime;

pub trait Clock: Clone {
    fn now(&self) -> SystemTime;
}

/// A [`Clock`] impl that returns the current time according to the system clock.
#[derive(Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

impl<C: Clock> Clock for &C {
    fn now(&self) -> SystemTime {
        (*self).now()
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use std::sync::{Arc, RwLock};
    use std::time::SystemTime;

    use std::time::Duration;

    use super::Clock;

    /// A [`Clock`] impl that always returns a constant value for calls to [`now`].
    ///
    /// [`now`]: Clock::now
    #[derive(Clone)]
    pub struct FixedClock {
        now: Arc<RwLock<SystemTime>>,
    }

    impl FixedClock {
        /// Construct a new [`FixedClock`] with the given time as the current instant.
        pub fn new(now: SystemTime) -> Self {
            Self {
                now: Arc::new(RwLock::new(now)),
            }
        }

        /// Update the current time held by this [`FixedClock`] by adding the specified duration to
        /// that instant.
        pub fn tick(&self, delta: Duration) {
            let mut w = self.now.write().unwrap();
            *w = *w + delta;
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            *self.now.read().unwrap()
        }
    }
}
