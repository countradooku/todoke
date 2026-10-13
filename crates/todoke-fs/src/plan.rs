//! The receiver's destination mapping (PROTOCOL §7.1): before consent,
//! every manifest entry gets the exact local name it will be stored under,
//! with every rename, warning, and rejection, so the receive sheet can
//! show them. Computed again, identically, when files are published.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use todoke_proto::transfer::manifest::{EntryKind, Manifest};

use crate::name::extension::{
    ExtensionRisk, Platforms, extension_risk, final_extension, is_bundle_directory,
};
use crate::name::fold::collision_key;
use crate::name::{Change, Kind, NameRules, sanitize_component, with_suffix};

/// How many suffixes (`" (2)"` … `" (1001)"`) are tried before an entry
/// is reported as having no free name.
pub(crate) const MAX_SUFFIX: u32 = 1001;

/// The most destination lookups (`exists` calls) one plan makes. With a
/// listing of the root, each top-level entry normally costs one; without
/// one, every candidate does. Entries the budget cannot settle are
/// rejected with [`Rejection::NoFreeName`], before consent and visibly.
pub(crate) const MAX_LOOKUPS: usize = 20_000;

/// A name exactly as the peer sent it. Untrusted display data: it may
/// contain direction overrides, look-alike characters, or misleading
/// extensions, so show it only marked as the sender's name, next to the
/// [`LocalName`]. `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedName(String);

impl UntrustedName {
    /// The peer's name. Untrusted; see the type documentation.
    #[must_use]
    pub fn as_untrusted_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for UntrustedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UntrustedName({} bytes)", self.0.len())
    }
}

/// The name an entry gets on this device: one sanitized component.
/// `Debug` does not print it (§14.2: no peer file names in logs).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalName(String);

impl LocalName {
    /// The local name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LocalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalName({} bytes)", self.0.len())
    }
}

/// A file published under another path than the one shown before consent:
/// a name on the way (the file's own, or a top-level directory's) was
/// taken by the time it was published, and the next free name was used
/// instead of overwriting anything. `Debug` prints no names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Renamed {
    planned: Vec<LocalName>,
    actual: Vec<LocalName>,
}

impl Renamed {
    pub(crate) fn new(planned: Vec<String>, actual: Vec<String>) -> Self {
        Self {
            planned: planned.into_iter().map(LocalName).collect(),
            actual: actual.into_iter().map(LocalName).collect(),
        }
    }

    /// The path the user consented to, one name per level.
    #[must_use]
    pub fn planned(&self) -> &[LocalName] {
        &self.planned
    }

    /// Where the file was actually published, one name per level.
    #[must_use]
    pub fn actual(&self) -> &[LocalName] {
        &self.actual
    }
}

/// How path lengths are measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathUnits {
    /// UTF-8 bytes (Linux, Android, macOS, iOS).
    Utf8Bytes,
    /// UTF-16 code units (Windows).
    Utf16Units,
}

/// The longest path the destination can hold, root included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathLimit {
    /// The unit of `max` and `warn_above`.
    pub units: PathUnits,
    /// Longer paths are rejected.
    pub max: usize,
    /// Longer paths get [`Warning::LongPath`]: they work through todoke
    /// but many applications cannot open them.
    pub warn_above: Option<usize>,
}

impl PathLimit {
    /// Linux and Android: `PATH_MAX` is 4096 bytes including the
    /// terminating NUL.
    pub const LINUX: Self = Self {
        units: PathUnits::Utf8Bytes,
        max: 4095,
        warn_above: None,
    };
    /// macOS and iOS: `PATH_MAX` is 1024 bytes including the NUL.
    pub const APPLE: Self = Self {
        units: PathUnits::Utf8Bytes,
        max: 1023,
        warn_above: None,
    };
    /// Windows: 32,767 UTF-16 units for `\\?\` paths (which Rust's
    /// standard library uses for long paths), minus that prefix; above the
    /// classic `MAX_PATH` of 260 (259 without the NUL) many applications
    /// fail.
    pub const WINDOWS: Self = Self {
        units: PathUnits::Utf16Units,
        max: 32_760,
        warn_above: Some(259),
    };

    /// This platform's limit.
    #[must_use]
    pub const fn host() -> Self {
        if cfg!(windows) {
            Self::WINDOWS
        } else if cfg!(target_vendor = "apple") {
            Self::APPLE
        } else {
            Self::LINUX
        }
    }

    /// The length of `text` in this limit's units.
    #[must_use]
    pub fn measure(&self, text: &str) -> usize {
        match self.units {
            PathUnits::Utf8Bytes => text.len(),
            PathUnits::Utf16Units => text.encode_utf16().count(),
        }
    }
}

/// What a destination can represent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsProfile {
    /// Name rewriting rules.
    pub rules: NameRules,
    /// Path length limit.
    pub path: PathLimit,
}

impl FsProfile {
    /// The portable name rules with this platform's path limit.
    #[must_use]
    pub const fn host() -> Self {
        Self {
            rules: NameRules::PORTABLE,
            path: PathLimit::host(),
        }
    }
}

impl Default for FsProfile {
    fn default() -> Self {
        Self::host()
    }
}

/// Something the receive sheet should point out about an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Warning {
    /// The final extension runs code, installs, mounts, or is resolved by
    /// the shell on the listed platforms.
    Risky(ExtensionRisk),
    /// A directory macOS treats as an application or loadable bundle.
    Bundle,
    /// The name starts with a dot, which hides it on macOS and Linux.
    Hidden,
    /// The claimed MIME type does not fit the extension.
    MimeMismatch,
    /// The path is longer than many applications can open.
    LongPath,
}

/// Why an entry cannot be stored. The user can still select other files;
/// selecting a rejected one is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The path is longer than the destination allows.
    PathTooLong,
    /// A parent directory is rejected.
    ParentRejected,
    /// Every candidate name is already taken.
    NoFreeName,
}

/// One manifest entry's mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedEntry {
    id: u32,
    parent: u32,
    kind: Kind,
    original: UntrustedName,
    /// Sanitized and separated from its siblings; for a top-level entry,
    /// before avoiding names already in the destination.
    base: LocalName,
    local: LocalName,
    changes: Vec<Change>,
    warnings: Vec<Warning>,
    rejection: Option<Rejection>,
}

impl PlannedEntry {
    /// The manifest entry ID.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// The parent directory's ID (0 for the destination root).
    #[must_use]
    pub const fn parent(&self) -> u32 {
        self.parent
    }

    /// File or directory.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The peer's name (untrusted).
    #[must_use]
    pub const fn original(&self) -> &UntrustedName {
        &self.original
    }

    /// The local name.
    #[must_use]
    pub const fn local(&self) -> &LocalName {
        &self.local
    }

    /// The rewrites applied, in order of first occurrence.
    #[must_use]
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// Warnings for the receive sheet.
    #[must_use]
    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    /// Why the entry cannot be stored, if it cannot.
    #[must_use]
    pub const fn rejection(&self) -> Option<Rejection> {
        self.rejection
    }
}

/// Every entry's mapping, in manifest ID order. `Debug` prints no names.
#[derive(Clone, PartialEq, Eq)]
pub struct DestinationPlan {
    entries: Vec<PlannedEntry>,
    profile: FsProfile,
    /// Each entry's parent and the collision key of its base name, to its
    /// ID.
    sibling_keys: BTreeMap<(u32, String), u32>,
}

impl DestinationPlan {
    /// Maps `manifest` onto a destination whose root path is `root_len`
    /// long (in `profile.path` units). `exists` reports whether a name is
    /// already taken in the destination root (filesystem semantics,
    /// without following links); it is asked only about top-level names,
    /// at most [`MAX_LOOKUPS`] times.
    pub fn new(
        manifest: &Manifest,
        profile: &FsProfile,
        root_len: usize,
        exists: &mut dyn FnMut(&str) -> bool,
    ) -> Self {
        Self::with_listing(manifest, profile, root_len, None, exists)
    }

    /// As [`Self::new`], with the collision keys of every name the root
    /// held when it was listed: candidates whose key is listed are skipped
    /// without a lookup, so `exists` normally only confirms each entry's
    /// chosen name (a name created since the listing is still caught).
    pub(crate) fn with_listing(
        manifest: &Manifest,
        profile: &FsProfile,
        root_len: usize,
        listed: Option<&BTreeSet<String>>,
        exists: &mut dyn FnMut(&str) -> bool,
    ) -> Self {
        let mut plan = Self::sanitized(manifest, profile);
        plan.avoid_existing(listed, exists);
        plan.check_paths(root_len);
        plan
    }

    /// The plan the user consented to, rebuilt from the manifest and the
    /// local names recorded at the Accept (`names`, by entry ID): those
    /// entries get exactly those names, whatever the destination holds
    /// now. Entries not in `names` keep their sanitized names.
    pub(crate) fn consented(
        manifest: &Manifest,
        profile: &FsProfile,
        names: &BTreeMap<u32, String>,
    ) -> Self {
        let mut plan = Self::sanitized(manifest, profile);
        for (&id, name) in names {
            let Some(entry) = plan.entry_mut(id) else {
                continue;
            };
            if entry.parent == 0 && entry.local.0 != *name {
                push_change(&mut entry.changes, Change::Exists);
            }
            entry.local = LocalName(name.clone());
            entry.rejection = None;
        }
        plan
    }

    /// The local names of `selection`'s files and of every directory on
    /// their paths, by entry ID: what [`Self::consented`] rebuilds from.
    pub(crate) fn names_for(&self, selection: &[u32]) -> Option<BTreeMap<u32, String>> {
        let mut names = BTreeMap::new();
        for &file_id in selection {
            let mut id = file_id;
            while id != 0 && !names.contains_key(&id) {
                let entry = self.entry(id)?;
                names.insert(id, entry.local.0.clone());
                id = entry.parent;
            }
        }
        Some(names)
    }

    /// Sanitizes every name and separates siblings; no destination access.
    fn sanitized(manifest: &Manifest, profile: &FsProfile) -> Self {
        let rules = profile.rules;
        let limit = rules
            .max_component_bytes
            .clamp(16, crate::name::MAX_COMPONENT_BYTES);
        let mut entries: Vec<PlannedEntry> = manifest
            .entries()
            .iter()
            .map(|entry| {
                let kind = match entry.kind() {
                    EntryKind::File => Kind::File,
                    EntryKind::Directory => Kind::Directory,
                };
                let (local, changes) = sanitize_component(entry.name(), kind, &rules);
                PlannedEntry {
                    id: entry.id(),
                    parent: entry.parent(),
                    kind,
                    original: UntrustedName(entry.name().to_owned()),
                    base: LocalName(local.clone()),
                    local: LocalName(local),
                    changes,
                    warnings: Vec::new(),
                    rejection: None,
                }
            })
            .collect();
        // Siblings, in ID order: the first keeps its name, later ones that
        // collide take the lowest free suffix, avoiding every sibling's
        // own name.
        let mut groups: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            groups.entry(entry.parent).or_default().push(index);
        }
        let mut sibling_keys = BTreeMap::new();
        for (parent, members) in &groups {
            let reserved: BTreeSet<String> = members
                .iter()
                .filter_map(|&index| entries.get(index))
                .map(|entry| collision_key(&entry.base.0))
                .collect();
            let mut taken = BTreeSet::new();
            let mut next: BTreeMap<String, u32> = BTreeMap::new();
            for &index in members {
                let Some(entry) = entries.get_mut(index) else {
                    continue;
                };
                let key = collision_key(&entry.base.0);
                if taken.insert(key.clone()) {
                    continue;
                }
                let start = next.get(&key).copied().unwrap_or(2);
                let mut chosen = None;
                for n in start..=MAX_SUFFIX.saturating_mul(10) {
                    let candidate = with_suffix(&entry.base.0, n, entry.kind, limit);
                    let candidate_key = collision_key(&candidate);
                    if !reserved.contains(&candidate_key) && !taken.contains(&candidate_key) {
                        next.insert(key.clone(), n + 1);
                        taken.insert(candidate_key);
                        chosen = Some(candidate);
                        break;
                    }
                }
                match chosen {
                    Some(name) => {
                        entry.base = LocalName(name.clone());
                        entry.local = LocalName(name);
                        push_change(&mut entry.changes, Change::Collision);
                    }
                    None => entry.rejection = Some(Rejection::NoFreeName),
                }
            }
            for &index in members {
                if let Some(entry) = entries.get(index) {
                    sibling_keys.insert((*parent, collision_key(&entry.base.0)), entry.id);
                }
            }
        }
        for (entry, manifest_entry) in entries.iter_mut().zip(manifest.entries()) {
            entry.warnings = warnings(entry, manifest_entry.mime());
        }
        Self {
            entries,
            profile: *profile,
            sibling_keys,
        }
    }

    /// Gives each top-level entry the first of its candidates that the
    /// destination does not already hold, within [`MAX_LOOKUPS`].
    fn avoid_existing(
        &mut self,
        listed: Option<&BTreeSet<String>>,
        exists: &mut dyn FnMut(&str) -> bool,
    ) {
        let mut budget = MAX_LOOKUPS;
        let ids: Vec<u32> = self
            .entries
            .iter()
            .filter(|entry| entry.parent == 0 && entry.rejection.is_none())
            .map(|entry| entry.id)
            .collect();
        // Names given to earlier top-level entries: two entries whose
        // names both exist can otherwise pick the same suffixed name.
        let mut chosen = BTreeSet::new();
        for id in ids {
            let mut found = None;
            for (n, candidate) in self.candidates(id) {
                let key = collision_key(&candidate);
                if chosen.contains(&key) || listed.is_some_and(|listed| listed.contains(&key)) {
                    continue;
                }
                let Some(left) = budget.checked_sub(1) else {
                    break;
                };
                budget = left;
                if !exists(&candidate) {
                    chosen.insert(key);
                    found = Some((n, candidate));
                    break;
                }
            }
            let Some(entry) = self.entry_mut(id) else {
                continue;
            };
            match found {
                Some((n, name)) => {
                    if n > 1 {
                        push_change(&mut entry.changes, Change::Exists);
                    }
                    entry.local = LocalName(name);
                }
                None => entry.rejection = Some(Rejection::NoFreeName),
            }
        }
    }

    /// The names entry `id` may take, in order: its base name (for a
    /// top-level entry, before avoiding the destination's names), then
    /// suffixes `" (2)"` upward, skipping names that would collide with a
    /// sibling's. Paired with the suffix number (1 for the base name).
    pub(crate) fn candidates(&self, id: u32) -> impl Iterator<Item = (u32, String)> + '_ {
        let limit = self
            .profile
            .rules
            .max_component_bytes
            .clamp(16, crate::name::MAX_COMPONENT_BYTES);
        let entry = self.entry(id);
        (1..=MAX_SUFFIX).filter_map(move |n| {
            let entry = entry?;
            let name = if n == 1 {
                entry.base.0.clone()
            } else {
                with_suffix(&entry.base.0, n, entry.kind, limit)
            };
            let free = self
                .sibling_keys
                .get(&(entry.parent, collision_key(&name)))
                .is_none_or(|owner| *owner == id);
            free.then_some((n, name))
        })
    }

    fn check_paths(&mut self, root_len: usize) {
        let limit = self.profile.path;
        let mut lengths: BTreeMap<u32, usize> = BTreeMap::new();
        lengths.insert(0, root_len);
        for index in 0..self.entries.len() {
            let Some(entry) = self.entries.get(index) else {
                continue;
            };
            let parent_rejected = entry.parent != 0
                && self
                    .entry(entry.parent)
                    .is_none_or(|parent| parent.rejection.is_some());
            let parent_len = lengths.get(&entry.parent).copied().unwrap_or(usize::MAX);
            let length = parent_len
                .saturating_add(1)
                .saturating_add(limit.measure(&entry.local.0));
            let Some(entry) = self.entries.get_mut(index) else {
                continue;
            };
            lengths.insert(entry.id, length);
            if parent_rejected {
                entry.rejection = Some(Rejection::ParentRejected);
            } else if entry.rejection.is_none() && length > limit.max {
                entry.rejection = Some(Rejection::PathTooLong);
            } else if limit.warn_above.is_some_and(|warn| length > warn) {
                entry.warnings.push(Warning::LongPath);
            }
        }
    }

    /// Every entry, in ID order.
    #[must_use]
    pub fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }

    /// Entry `id`.
    #[must_use]
    pub fn entry(&self, id: u32) -> Option<&PlannedEntry> {
        let index = usize::try_from(id.checked_sub(1)?).ok()?;
        self.entries.get(index).filter(|entry| entry.id == id)
    }

    fn entry_mut(&mut self, id: u32) -> Option<&mut PlannedEntry> {
        let index = usize::try_from(id.checked_sub(1)?).ok()?;
        self.entries.get_mut(index).filter(|entry| entry.id == id)
    }

    /// The local path of entry `id`, from the destination root: one
    /// [`LocalName`] per level.
    #[must_use]
    pub fn local_path(&self, id: u32) -> Option<Vec<&LocalName>> {
        let mut path = Vec::new();
        let mut current = self.entry(id)?;
        loop {
            path.push(&current.local);
            if current.parent == 0 {
                break;
            }
            current = self.entry(current.parent)?;
        }
        path.reverse();
        Some(path)
    }

    /// Whether every listed file can be stored.
    #[must_use]
    pub fn accepts(&self, selection: &[u32]) -> bool {
        selection.iter().all(|&id| {
            self.entry(id)
                .is_some_and(|entry| entry.kind == Kind::File && entry.rejection.is_none())
        })
    }

    /// Whether at least one file can be stored.
    #[must_use]
    pub fn any_file_storable(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.kind == Kind::File && entry.rejection.is_none())
    }
}

impl fmt::Debug for DestinationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestinationPlan")
            .field("entries", &self.entries)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

fn push_change(changes: &mut Vec<Change>, change: Change) {
    if !changes.contains(&change) {
        changes.push(change);
    }
}

/// Name-based warnings (content is checked after verification, see
/// [`crate::detect`]).
fn warnings(entry: &PlannedEntry, mime: &str) -> Vec<Warning> {
    let mut warnings = Vec::new();
    let name = &entry.local.0;
    match entry.kind {
        Kind::File => {
            if let Some(risk) = final_extension(name).and_then(extension_risk) {
                warnings.push(Warning::Risky(risk));
            }
            if mime_mismatch(name, mime) {
                warnings.push(Warning::MimeMismatch);
            }
        }
        Kind::Directory => {
            if is_bundle_directory(name) {
                warnings.push(Warning::Bundle);
                if let Some(risk) = final_extension(name).and_then(extension_risk) {
                    warnings.push(Warning::Risky(risk));
                } else {
                    warnings.push(Warning::Risky(ExtensionRisk {
                        kind: crate::name::extension::RiskKind::Executable,
                        platforms: Platforms::MACOS,
                    }));
                }
            }
        }
    }
    if name.starts_with('.') {
        warnings.push(Warning::Hidden);
    }
    warnings
}

/// Extensions with one well-known MIME type.
const MIME_BY_EXTENSION: &[(&str, &str)] = &[
    ("pdf", "application/pdf"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("png", "image/png"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("heic", "image/heic"),
    ("mp4", "video/mp4"),
    ("mov", "video/quicktime"),
    ("mp3", "audio/mpeg"),
    ("txt", "text/plain"),
    ("zip", "application/zip"),
];

/// A MIME type claims a viewable type while the extension says otherwise:
/// a risky extension with an image, audio, video, text, or PDF type, or a
/// well-known extension with a different specific type.
fn mime_mismatch(name: &str, mime: &str) -> bool {
    if mime == "application/octet-stream" {
        return false;
    }
    let Some(extension) = final_extension(name) else {
        return false;
    };
    if extension_risk(extension).is_some() {
        return ["image/", "audio/", "video/", "text/plain"]
            .iter()
            .any(|prefix| mime.starts_with(prefix))
            || mime == "application/pdf";
    }
    MIME_BY_EXTENSION
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(extension))
        .is_some_and(|(_, expected)| *expected != mime)
}
