//! State of the unlocked vault view: data, filter, query and selection.

use crate::health::Report;
use crate::model::{Filter, ItemKind, SortKey, Vault, VaultItem};
use crate::ui::logic::selection_in_view;
use gpui_kit::UniformListScrollHandle;

/// Everything that describes what the vault list currently shows.
pub struct VaultViewState {
    /// The vault data.
    pub vault: Vault,
    /// Active sidebar filter.
    pub filter: Filter,
    /// Search query.
    pub query: String,
    /// Sort order.
    pub sort: SortKey,
    /// Whether the search box is active.
    pub searching: bool,
    /// Stable id of the selected item.
    pub selected_id: Option<String>,
    /// Last health audit result.
    pub audit_report: Option<Report>,
    /// Scroll position of the item list.
    pub scroll_handle: UniformListScrollHandle,
}

impl Default for VaultViewState {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultViewState {
    /// Create an empty, locked view.
    pub fn new() -> Self {
        Self {
            vault: Vault::new(),
            filter: Filter::All,
            query: String::new(),
            sort: SortKey::NameAsc,
            searching: false,
            selected_id: None,
            audit_report: None,
            scroll_handle: UniformListScrollHandle::new(),
        }
    }

    /// Items passing the current filter and query, in sort order.
    pub fn visible_items(&self) -> Vec<&VaultItem> {
        self.vault.view(&self.filter, &self.query, self.sort)
    }

    /// Request that the first row be placed at the top of the viewport.
    fn scroll_to_top(&mut self) {
        self.scroll_handle
            .scroll_to_item(0, gpui_kit::ScrollStrategy::Top);
    }

    /// Clear the selection and rewind the list to its first row.
    ///
    /// This is the single definition of "the selected row is no longer
    /// valid". Filter and sort changes, search edits and confirmation, item
    /// removal and vault reset all funnel through here, so every path that
    /// drops the selection leaves the same visible range behind.
    pub fn deselect_and_rewind(&mut self) {
        self.selected_id = None;
        self.scroll_to_top();
    }

    /// Reset the view when locking the vault.
    pub fn reset(&mut self) {
        self.vault = Vault::new();
        self.query.clear();
        self.filter = Filter::All;
        self.sort = SortKey::NameAsc;
        self.searching = false;
        self.audit_report = None;
        self.deselect_and_rewind();
    }

    /// Ensure the selected id still names a visible item.
    pub fn revalidate_selection(&mut self) -> bool {
        let visible = self.visible_items();
        let valid = selection_in_view(
            self.selected_id.as_deref(),
            visible.iter().map(|item| item.id.as_str()),
        );
        if !valid {
            self.deselect_and_rewind();
        }
        valid
    }

    /// Select a row by its index, returning whether it changed.
    pub fn select_index(&mut self, index: usize) -> bool {
        let visible = self.visible_items();
        let Some(item) = visible.get(index) else {
            return false;
        };
        let id = item.id.clone();
        if self.selected_id.as_deref() == Some(id.as_str()) {
            return false;
        }
        self.selected_id = Some(id);
        true
    }

    /// Compute the next selection index for a relative move, without mutating
    /// the selection itself.
    pub fn next_index(&self, delta: isize) -> Option<usize> {
        let visible = self.visible_items();
        if visible.is_empty() {
            return None;
        }
        let current = self
            .selected_id
            .as_deref()
            .and_then(|id| visible.iter().position(|item| item.id == id))
            .unwrap_or(0);
        Some((current as isize + delta).clamp(0, visible.len() as isize - 1) as usize)
    }

    /// Cycle to the next filter, clearing the selection and rewinding the list.
    pub fn cycle_filter(&mut self) {
        self.filter = match self.filter {
            Filter::All => Filter::Favorites,
            Filter::Favorites => Filter::Kind(ItemKind::Login),
            Filter::Kind(ItemKind::Login) => Filter::Kind(ItemKind::SecureNote),
            Filter::Kind(ItemKind::SecureNote) => Filter::Kind(ItemKind::Card),
            Filter::Kind(ItemKind::Card) => Filter::Kind(ItemKind::Identity),
            Filter::Kind(ItemKind::Identity) => Filter::Kind(ItemKind::SshKey),
            Filter::Kind(ItemKind::SshKey) => Filter::NoFolder,
            Filter::NoFolder | Filter::Folder(_) => Filter::All,
        };
        self.deselect_and_rewind();
    }

    /// Begin a fresh search.
    pub fn start_search(&mut self) {
        self.searching = true;
        self.query.clear();
        self.deselect_and_rewind();
    }

    /// Finish search or settings editing.
    pub fn finish_search(&mut self) {
        self.searching = false;
    }

    /// Append a character to the search query.
    pub fn push_query(&mut self, text: &str) {
        self.query.push_str(text);
        self.deselect_and_rewind();
    }

    /// Remove the last character from the search query.
    pub fn pop_query(&mut self) {
        self.query.pop();
        self.deselect_and_rewind();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::model::{ItemData, VaultItem};

    fn state_with_items() -> VaultViewState {
        let mut state = VaultViewState::new();
        state.vault.items.push(VaultItem::new(
            "a",
            "Alpha",
            ItemData::SecureNote {
                text: String::new(),
            },
        ));
        state.vault.items.push(VaultItem::new(
            "b",
            "Beta",
            ItemData::SecureNote {
                text: String::new(),
            },
        ));
        state
    }

    #[::core::prelude::v1::test]
    fn next_index_clamps_at_the_ends() {
        // Two visible rows: indices 0 and 1. A step far past either end must
        // land on a real row, not outside the list.
        let state = state_with_items();
        assert_eq!(state.visible_items().len(), 2);
        assert_eq!(state.next_index(0), Some(0));
        assert_eq!(state.next_index(1), Some(1));
        assert_eq!(state.next_index(1_000), Some(1), "upper clamp");
        assert_eq!(state.next_index(-1_000), Some(0), "lower clamp");

        // From the last row, a further step down stays on the last row.
        let mut state = state_with_items();
        state.selected_id = Some("b".into());
        assert_eq!(state.next_index(0), Some(1));
        assert_eq!(
            state.next_index(1),
            Some(1),
            "last row + 1 stays on the last row"
        );
        assert_eq!(state.next_index(1_000), Some(1));
        assert_eq!(state.next_index(-1), Some(0));
        assert_eq!(state.next_index(-1_000), Some(0));

        // From the first row, a step up stays on the first row.
        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        assert_eq!(state.next_index(-1), Some(0));
        assert_eq!(state.next_index(1), Some(1));

        // A single row clamps to itself; an empty view has no index at all.
        let mut single = VaultViewState::new();
        single.vault.items.push(VaultItem::new(
            "s",
            "Solo",
            ItemData::SecureNote {
                text: String::new(),
            },
        ));
        assert_eq!(single.next_index(1), Some(0));
        assert_eq!(single.next_index(-1), Some(0));
        assert_eq!(VaultViewState::new().next_index(1), None);
        assert_eq!(VaultViewState::new().next_index(-1), None);
    }

    #[::core::prelude::v1::test]
    fn selection_is_revalidated_after_filtering() {
        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        state.query = "Beta".into();
        assert!(!state.revalidate_selection());
        assert_eq!(state.selected_id, None);
    }

    #[::core::prelude::v1::test]
    fn push_query_appends_a_whole_ime_string() {
        let mut state = state_with_items();
        state.push_query("日本");
        state.push_query("語");
        assert_eq!(state.query, "日本語");
    }

    /// The deferred scroll request queued by `scroll_to_item`.
    ///
    /// Reading it keeps these tests window-independent: gpui's scroll handle
    /// stores the request in a public `RefCell`, so no layout pass is needed.
    fn scroll_request(state: &VaultViewState) -> Option<(usize, gpui_kit::ScrollStrategy)> {
        state
            .scroll_handle
            .0
            .borrow()
            .deferred_scroll_to_item
            .map(|request| (request.item_index, request.strategy))
    }

    #[::core::prelude::v1::test]
    fn cycle_filter_clears_selection() {
        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        state.cycle_filter();
        assert_eq!(state.selected_id, None);
        assert_eq!(state.filter, Filter::Favorites);
    }

    #[::core::prelude::v1::test]
    fn every_deselection_path_rewinds_to_the_first_row() {
        // One observable result shared by all deselection paths: no selection
        // and a deferred scroll to row 0 with the Top strategy.
        let expected = Some((0, gpui_kit::ScrollStrategy::Top));

        type DeselectPath = (&'static str, fn(&mut VaultViewState));
        let paths: Vec<DeselectPath> = vec![
            ("reset", |state| state.reset()),
            ("revalidate_selection", |state| {
                // "a" drops out of the visible set, invalidating the selection.
                state.query = "Beta".into();
                assert!(!state.revalidate_selection());
            }),
            ("cycle_filter", |state| state.cycle_filter()),
            ("start_search", |state| state.start_search()),
            ("push_query", |state| state.push_query("B")),
            ("pop_query", |state| state.pop_query()),
        ];

        for (name, apply) in paths {
            let mut state = state_with_items();
            state.selected_id = Some("a".into());
            // Start away from the top so the assertion proves the path really
            // rewinds instead of merely leaving an old request in place.
            state
                .scroll_handle
                .scroll_to_item(1, gpui_kit::ScrollStrategy::Nearest);
            assert_eq!(
                scroll_request(&state),
                Some((1, gpui_kit::ScrollStrategy::Nearest)),
                "{name}: dirty scroll setup"
            );

            apply(&mut state);

            assert_eq!(state.selected_id, None, "{name}: selection must be cleared");
            assert_eq!(
                scroll_request(&state),
                expected,
                "{name}: scroll must rewind"
            );
        }
    }

    #[::core::prelude::v1::test]
    fn cycling_from_a_folder_or_nofolder_returns_to_all() {
        let mut state = state_with_items();
        state.filter = Filter::Folder("f1".into());
        state.cycle_filter();
        assert_eq!(state.filter, Filter::All);

        state.filter = Filter::NoFolder;
        state.cycle_filter();
        assert_eq!(state.filter, Filter::All);
    }

    #[::core::prelude::v1::test]
    fn search_editing_updates_query_and_selection() {
        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        state.start_search();
        assert!(state.searching);
        assert_eq!(state.selected_id, None);
        state.push_query("B");
        state.push_query("e");
        assert_eq!(state.query, "Be");
        // view() lowercases the query before matches_query sees it.
        assert_eq!(state.visible_items().len(), 1);
        state.pop_query();
        assert_eq!(state.query, "B");
        state.finish_search();
        assert!(!state.searching);
    }
}
