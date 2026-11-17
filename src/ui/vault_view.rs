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

    /// Reset the view when locking the vault.
    pub fn reset(&mut self) {
        self.vault = Vault::new();
        self.query.clear();
        self.filter = Filter::All;
        self.sort = SortKey::NameAsc;
        self.searching = false;
        self.selected_id = None;
        self.audit_report = None;
        self.scroll_handle
            .scroll_to_item(0, gpui_kit::ScrollStrategy::Top);
    }

    /// Ensure the selected id still names a visible item.
    pub fn revalidate_selection(&mut self) -> bool {
        let visible = self.visible_items();
        let valid = selection_in_view(
            self.selected_id.as_deref(),
            visible.iter().map(|item| item.id.as_str()),
        );
        if !valid {
            self.selected_id = None;
            self.scroll_handle
                .scroll_to_item(0, gpui_kit::ScrollStrategy::Top);
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

    /// Cycle to the next filter and return the row the view should scroll to.
    pub fn cycle_filter(&mut self) -> usize {
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
        self.selected_id = None;
        0
    }

    /// Begin a fresh search.
    pub fn start_search(&mut self) {
        self.searching = true;
        self.query.clear();
        self.selected_id = None;
    }

    /// Finish search or settings editing.
    pub fn finish_search(&mut self) {
        self.searching = false;
    }

    /// Append a character to the search query.
    pub fn push_query(&mut self, text: &str) {
        self.query.push_str(text);
        self.selected_id = None;
    }

    /// Remove the last character from the search query.
    pub fn pop_query(&mut self) {
        self.query.pop();
        self.selected_id = None;
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
        let state = state_with_items();
        assert_eq!(state.next_index(1), Some(1));
        assert_eq!(state.next_index(-1), Some(0));

        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        assert_eq!(state.next_index(1), Some(1));
        assert_eq!(state.next_index(-1), Some(0));
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

    #[::core::prelude::v1::test]
    fn cycle_filter_clears_selection() {
        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        assert_eq!(state.cycle_filter(), 0);
        assert_eq!(state.selected_id, None);
        assert_eq!(state.filter, Filter::Favorites);
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
