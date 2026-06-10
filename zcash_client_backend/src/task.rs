/// Spawns a new asynchronous task, returning a `JoinHandle` for it.
///
/// This is a wrapper for [`tokio::task::spawn`] that takes a task name.
#[cfg(not(tokio_unstable))]
#[macro_export]
macro_rules! spawn {
    ( $name:expr, $f:expr ) => {
        tokio::task::spawn($f)
    };
}

/// Spawns a new asynchronous task, returning a `JoinHandle` for it.
///
/// This is a wrapper for [`tokio::task::spawn`] that takes a task name.
#[cfg(tokio_unstable)]
#[macro_export]
macro_rules! spawn {
    ( $name:expr, $f:expr ) => {
        tokio::task::Builder::new()
            .name($name)
            .spawn($f)
            .expect("spawning a task fails only when the Tokio runtime is shutting down")
    };
}
