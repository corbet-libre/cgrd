//! Stateless admission, reciprocal matching and Unicode handle checks.
//! All clocks and trust roots come from the caller. No evaluation performs I/O.
//! See `docs/CONTRACT.md` for the signed wire format and trust boundary.
#![forbid(unsafe_code)]

mod guard;
mod handles;
mod matching;
mod model;
pub mod storage;

pub use guard::*;
pub use handles::*;
pub use matching::*;
pub use model::*;
