//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/it/common` holds the shared fixtures, `tests/it/support` the
//! libSQL snapshot helper `storage` includes. `tests/unit` and `tests/vectors` stay: the
//! library compiles them via `#[path]`.
mod common;
mod published;
mod shared;
mod storage;
