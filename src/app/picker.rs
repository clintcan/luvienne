//! A keyboard-driven file browser for choosing a key file.
//!
//! Deliberately a TUI browser rather than the macOS native dialog. A GUI panel
//! would break the terminal model, and it would be unusable the moment this app
//! runs over SSH on a remote machine — where the keys you want to pick are on
//! the *remote* filesystem, which is exactly what this reads.
//!
//! Hidden entries are shown by default. Key files live in `~/.ssh`, and a
//! browser that hides dot-directories cannot reach the one place people keep
//! keys.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    /// The synthetic `..` row. Every file browser has one, and without it the
    /// only way out of a directory is a key binding in the footer — which is
    /// easy to miss, and leaves the browser feeling like it has trapped you in
    /// whichever directory it opened in.
    pub is_parent: bool,
}

#[derive(Debug)]
pub struct FilePicker {
    pub dir: PathBuf,
    pub entries: Vec<Entry>,
    pub selected: usize,
    pub show_hidden: bool,
    /// Set when a directory could not be read; the browser stays where it was.
    pub error: Option<String>,
}

impl FilePicker {
    /// Open at the most useful directory we can find: the one the path field
    /// already points at, else `~/.ssh`, else home.
    pub fn open(current_value: &str) -> Self {
        let mut picker = Self {
            dir: PathBuf::new(),
            entries: Vec::new(),
            selected: 0,
            show_hidden: true,
            error: None,
        };
        picker.dir = Self::start_dir(current_value);
        picker.refresh();
        picker.selected = picker
            .entries
            .iter()
            .position(|e| !e.is_parent)
            .unwrap_or(0);
        picker
    }

    fn start_dir(current_value: &str) -> PathBuf {
        let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());

        if !current_value.trim().is_empty() {
            let expanded = crate::auth::expand_tilde(Path::new(current_value.trim()));
            // The value may be a directory, a file, or a half-typed path.
            if expanded.is_dir() {
                return expanded;
            }
            if let Some(parent) = expanded.parent()
                && parent.is_dir()
            {
                return parent.to_path_buf();
            }
        }

        if let Some(home) = &home {
            let ssh = home.join(".ssh");
            if ssh.is_dir() {
                return ssh;
            }
            return home.clone();
        }
        PathBuf::from("/")
    }

    /// Re-read the current directory. Directories sort before files, then by
    /// name, case-insensitively — the order people expect from a file list.
    pub fn refresh(&mut self) {
        self.error = None;
        let read = match std::fs::read_dir(&self.dir) {
            Ok(read) => read,
            Err(err) => {
                // Permission denied on a directory is ordinary, not fatal.
                self.error = Some(format!("cannot read {}: {err}", self.dir.display()));
                self.entries.clear();
                self.selected = 0;
                return;
            }
        };

        let mut entries: Vec<Entry> = read
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                if !self.show_hidden && name.starts_with('.') {
                    return None;
                }
                // `file_type` avoids following symlinks into a stat error.
                let is_dir = entry
                    .file_type()
                    .map(|t| t.is_dir() || (t.is_symlink() && entry.path().is_dir()))
                    .unwrap_or(false);
                Some(Entry {
                    name,
                    path: entry.path(),
                    is_dir,
                    is_parent: false,
                })
            })
            .collect();

        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        // `..` first, so going up is visible in the list rather than only in a
        // footer hint. Absent at the filesystem root, where there is no up.
        if let Some(parent) = self.dir.parent() {
            entries.insert(
                0,
                Entry {
                    name: "..".into(),
                    path: parent.to_path_buf(),
                    is_dir: true,
                    is_parent: true,
                },
            );
        }

        self.entries = entries;
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
    }

    pub fn toggle_hidden(&mut self) {
        self.show_hidden = !self.show_hidden;
        self.selected = 0;
        self.refresh();
    }

    pub fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn down(&mut self) {
        let last = self.entries.len().saturating_sub(1);
        self.selected = (self.selected + 1).min(last);
    }

    /// Move to the parent directory, keeping the directory we came from
    /// selected so going up and back down lands where you were.
    pub fn go_up(&mut self) {
        let leaving = self
            .dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string());
        let Some(parent) = self.dir.parent().map(Path::to_path_buf) else {
            return; // already at the root
        };
        self.dir = parent;
        self.selected = 0;
        self.refresh();

        if let Some(leaving) = leaving
            && let Some(index) = self.entries.iter().position(|e| e.name == leaving)
        {
            self.selected = index;
        }
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        self.entries.get(self.selected)
    }

    /// Activate the selection: descend into a directory, or return the chosen
    /// file's path.
    pub fn activate(&mut self) -> Option<PathBuf> {
        let entry = self.selected_entry()?.clone();
        if entry.is_parent {
            // Route through `go_up` so the directory just left stays selected.
            self.go_up();
            return None;
        }
        if entry.is_dir {
            self.dir = entry.path;
            self.selected = 0;
            self.refresh();
            None
        } else {
            Some(entry.path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_tree(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("luvienne-picker-{tag}"));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        std::fs::create_dir_all(root.join(".hidden_dir")).unwrap();
        std::fs::write(root.join("zeta.pem"), "x").unwrap();
        std::fs::write(root.join("alpha.ppk"), "x").unwrap();
        std::fs::write(root.join(".hidden_key"), "x").unwrap();
        root
    }

    fn picker_at(dir: PathBuf) -> FilePicker {
        let mut picker = FilePicker {
            dir,
            entries: Vec::new(),
            selected: 0,
            show_hidden: true,
            error: None,
        };
        picker.refresh();
        picker
    }

    #[test]
    fn directories_sort_before_files_then_alphabetically() {
        let root = fixture_tree("sort");
        let picker = picker_at(root.clone());

        let names: Vec<&str> = picker.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "..",
                ".hidden_dir",
                "subdir",
                ".hidden_key",
                "alpha.ppk",
                "zeta.pem"
            ],
            "`..` first, then directories, then files, each by name"
        );

        // Stated as an invariant too, so the intent survives a fixture change.
        let first_file = picker.entries.iter().position(|e| !e.is_dir).unwrap();
        assert!(picker.entries[0].is_parent, "`..` must lead the listing");
        assert!(
            picker.entries[first_file..].iter().all(|e| !e.is_dir),
            "a directory sorted below a file: {names:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// The reason hidden entries are shown by default: `~/.ssh` is a
    /// dot-directory, so hiding them makes the common case unreachable.
    #[test]
    fn hidden_entries_are_visible_by_default_and_can_be_toggled() {
        let root = fixture_tree("hidden");
        let mut picker = picker_at(root.clone());

        assert!(picker.show_hidden, "hidden entries must be on by default");
        assert!(picker.entries.iter().any(|e| e.name == ".hidden_dir"));

        picker.toggle_hidden();
        assert!(
            !picker
                .entries
                .iter()
                .any(|e| !e.is_parent && e.name.starts_with('.')),
            "dotfiles hidden, but `..` stays"
        );
        assert!(picker.entries[0].is_parent, "`..` is not a dotfile");

        picker.toggle_hidden();
        assert!(picker.entries.iter().any(|e| e.name == ".hidden_key"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn activating_a_file_returns_its_path() {
        let root = fixture_tree("choose");
        let mut picker = picker_at(root.clone());
        let index = picker
            .entries
            .iter()
            .position(|e| e.name == "alpha.ppk")
            .unwrap();
        picker.selected = index;

        let chosen = picker.activate().expect("a file selection returns a path");
        assert_eq!(chosen, root.join("alpha.ppk"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn activating_a_directory_descends_into_it() {
        let root = fixture_tree("descend");
        let mut picker = picker_at(root.clone());
        let index = picker
            .entries
            .iter()
            .position(|e| e.name == "subdir")
            .unwrap();
        picker.selected = index;

        assert!(picker.activate().is_none(), "descending selects nothing");
        assert_eq!(picker.dir, root.join("subdir"));
        std::fs::remove_dir_all(&root).ok();
    }

    /// Going up should leave the directory you came from highlighted, so
    /// stepping in and out doesn't lose your place.
    #[test]
    fn going_up_reselects_the_directory_just_left() {
        let root = fixture_tree("updown");
        let mut picker = picker_at(root.join("subdir"));
        picker.go_up();

        assert_eq!(picker.dir, root);
        assert_eq!(
            picker.selected_entry().map(|e| e.name.as_str()),
            Some("subdir")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn going_up_from_the_root_stays_put() {
        let mut picker = picker_at(PathBuf::from("/"));
        picker.go_up();
        assert_eq!(picker.dir, PathBuf::from("/"));
    }

    /// The root has no up, so offering `..` there would be a dead row.
    #[test]
    fn the_root_has_no_parent_entry() {
        let picker = picker_at(PathBuf::from("/"));
        assert!(!picker.entries.iter().any(|e| e.is_parent));
    }

    /// The fix for "I cannot get out of the directory it opened in": `..` is a
    /// row you can see and activate, not just a footer key hint.
    #[test]
    fn activating_the_parent_row_goes_up() {
        let root = fixture_tree("parentrow");
        let mut picker = picker_at(root.join("subdir"));

        assert_eq!(picker.entries.first().map(|e| e.name.as_str()), Some(".."));
        picker.selected = 0;
        assert!(picker.activate().is_none(), "going up chooses no file");
        assert_eq!(picker.dir, root);
        assert_eq!(
            picker.selected_entry().map(|e| e.name.as_str()),
            Some("subdir"),
            "and lands back on where we came from"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// Opening on `..` would mean a reflexive Enter navigates away from the
    /// directory the picker deliberately chose to start in.
    #[test]
    fn opens_with_a_real_entry_selected_not_the_parent_row() {
        let root = fixture_tree("startsel");
        let picker = FilePicker::open(&root.display().to_string());
        assert!(
            !picker.selected_entry().unwrap().is_parent,
            "selection opened on `..`"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// An unreadable directory is ordinary (permissions), not a crash.
    #[test]
    fn an_unreadable_directory_reports_an_error_instead_of_panicking() {
        let mut picker = picker_at(PathBuf::from("/nonexistent-luvienne-dir"));
        assert!(picker.entries.is_empty());
        assert!(picker.error.is_some());
        // And navigation on an empty listing must not panic.
        picker.down();
        picker.up();
        assert!(picker.activate().is_none());
    }

    #[test]
    fn selection_cannot_run_past_the_listing() {
        let root = fixture_tree("bounds");
        let mut picker = picker_at(root.clone());
        for _ in 0..50 {
            picker.down();
        }
        assert!(picker.selected < picker.entries.len());
        for _ in 0..50 {
            picker.up();
        }
        assert_eq!(picker.selected, 0);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn opens_in_the_directory_the_field_already_points_at() {
        let root = fixture_tree("start");
        let picker = FilePicker::open(&root.join("alpha.ppk").display().to_string());
        assert_eq!(picker.dir, root, "should open beside the existing value");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_empty_field_opens_somewhere_readable() {
        let picker = FilePicker::open("");
        assert!(picker.dir.is_dir(), "opened at {}", picker.dir.display());
    }
}
