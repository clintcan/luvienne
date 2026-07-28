//! What an import found, independent of where it came from.
//!
//! Both importers report through this so the confirmation modal does not have
//! to know about PuTTY session files or ssh config syntax — and so adding a
//! third source later is a new scanner, not a new branch in the UI.

use crate::config::Host;

pub struct Imported {
    /// Shown to the user: where these came from.
    pub source: &'static str,
    pub hosts: Vec<Host>,
    /// Entries whose name is already in the inventory, so re-importing is safe.
    pub already_present: usize,
    /// Caveats worth reading *before* agreeing — what was skipped, what will
    /// need attention afterwards. Finding these out one failed connection at a
    /// time is miserable.
    pub notes: Vec<String>,
}

impl Imported {
    pub fn new(source: &'static str) -> Self {
        Self {
            source,
            hosts: Vec::new(),
            already_present: 0,
            notes: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}
