//! Internal direct-storage consumers. The initial consumer joins actual fixed
//! slots and complete original semantics before one existing checkpoint call;
//! reviewed retirement never dispatches. The private installed reader verifies
//! the actual completed C cut; no public protocol command or unchecked/hash-only
//! publication entry point is provided by this module.
#[path = "direct/backend.rs"]
pub(super) mod backend;
#[path = "direct/initial.rs"]
mod initial;
#[path = "direct/jobs.rs"]
pub(super) mod jobs;
#[path = "direct/pinned.rs"]
mod pinned;
#[path = "direct/prepared.rs"]
pub(super) mod prepared;
#[path = "direct/reader.rs"]
pub(super) mod reader;
#[path = "direct/reservations.rs"]
pub(super) mod reservations;
#[path = "direct/resume.rs"]
mod resume;
#[path = "direct/retired.rs"]
mod retired;
