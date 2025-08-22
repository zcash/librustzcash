//! Types that should be part of the standard library, but aren't.

use std::time::SystemTime;

/// A trait that represents the capability to read the system time.
///
/// Using implementations of this trait instead of accessing the system clock directly allows
/// mocking with a controlled clock for testing purposes.
pub trait Clock {
    /// Returns the current system time, according to this clock.
    fn now(&self) -> SystemTime;
}

/// A [`Clock`] impl that returns the current time according to the system clock.
///
/// This clock may be freely copied, as it is a zero-allocation type that simply delegates to
/// [`SystemTime::now`] to return the current time.
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
    /// Calling `.clone()` on this clock will return a clock that shares the underlying storage and
    /// uses a read-write lock to ensure serialized access to its [`tick`] method.
    ///
    /// [`now`]: Clock::now
    /// [`tick`]: Self::tick
    #[derive(Clone)]
    pub struct FixedClock {
        now: Arc<RwLock<SystemTime>>,
    }

    impl FixedClock {
        /// Constructs a new [`FixedClock`] with the given time as the current instant.
        pub fn new(now: SystemTime) -> Self {
            Self {
                now: Arc::new(RwLock::new(now)),
            }
        }

        /// Updates the current time held by this [`FixedClock`] by adding the specified duration to
        /// that instant.
        pub fn tick(&self, delta: Duration) {
            let mut w = self.now.write().unwrap();
            *w += delta;
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            *self.now.read().unwrap()
        }
    }
}
