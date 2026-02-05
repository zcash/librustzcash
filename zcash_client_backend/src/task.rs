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
            .expect("panic to match tokio::task::spawn")
    };
}

/// Runs the provided closure on a thread where blocking is acceptable.
///
/// This is a wrapper for [`tokio::task::spawn_blocking`] that takes a task name.
#[cfg(not(tokio_unstable))]
#[macro_export]
macro_rules! spawn_blocking {
    ( $name:expr, $f:expr ) => {
        tokio::task::spawn_blocking($f)
    };
}

/// Runs the provided closure on a thread where blocking is acceptable.
///
/// This is a wrapper for [`tokio::task::spawn_blocking`] that takes a task name.
#[cfg(tokio_unstable)]
#[macro_export]
macro_rules! spawn_blocking {
    ( $name:expr, $f:expr ) => {
        tokio::task::Builder::new()
            .name($name)
            .spawn_blocking($f)
            .expect("panic to match tokio::task::spawn_blocking")
    };
}
