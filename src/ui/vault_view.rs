//! State of the unlocked vault view: data, filter, query and selection.

use crate::health::Report;
use crate::model::{Filter, ItemKind, SortKey, Vault, VaultItem};
use crate::ui::logic::selection_in_view;
use gpui_kit::UniformListScrollHandle;

/// Everything that describes what the vault list currently shows.
pub(super) struct VaultViewState {
    /// The vault data.
    pub(super) vault: Vault,
    /// Active sidebar filter.
    pub(super) filter: Filter,
    /// Search query.
    pub(super) query: String,
    /// Sort order.
    pub(super) sort: SortKey,
    /// Whether the search box is active.
    pub(super) searching: bool,
    /// Stable id of the selected item.
    pub(super) selected_id: Option<String>,
    /// Last health audit result.
    pub(super) audit_report: Option<Report>,
    /// Scroll position of the item list.
    pub(super) scroll_handle: UniformListScrollHandle,
    /// Test-only record of `deselect_and_rewind` calls. Keeps the rewind
    /// contract observable without reading gpui-pre's private scroll state.
    #[cfg(test)]
    pub(super) rewind_calls: usize,
}

impl Default for VaultViewState {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultViewState {
    /// Create an empty, locked view.
    pub(super) fn new() -> Self {
        Self {
            vault: Vault::new(),
            filter: Filter::All,
            query: String::new(),
            sort: SortKey::NameAsc,
            searching: false,
            selected_id: None,
            audit_report: None,
            scroll_handle: UniformListScrollHandle::new(),
            #[cfg(test)]
            rewind_calls: 0,
        }
    }

    /// Items passing the current filter and query, in sort order.
    pub(super) fn visible_items(&self) -> Vec<&VaultItem> {
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
    pub(super) fn deselect_and_rewind(&mut self) {
        self.selected_id = None;
        self.scroll_to_top();
        #[cfg(test)]
        {
            self.rewind_calls += 1;
        }
    }

    /// Reset the view when locking the vault.
    #[cfg(test)]
    pub(super) fn reset(&mut self) {
        self.vault = Vault::new();
        self.query.clear();
        self.filter = Filter::All;
        self.sort = SortKey::NameAsc;
        self.searching = false;
        self.audit_report = None;
        self.deselect_and_rewind();
    }

    /// Ensure the selected id still names a visible item.
    pub(super) fn revalidate_selection(&mut self) -> bool {
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
    ///
    /// Selection only: this never rewinds the list. The caller decides whether
    /// to scroll (the click path uses the change flag together with the
    /// requested index), so choosing a row cannot jump back to the first one.
    pub(super) fn select_index(&mut self, index: usize) -> bool {
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

    /// Select a row by stable id (used when following an audit finding).
    ///
    /// Returns the visible-row index so the caller can scroll to it. An id
    /// that is filtered out is not silently replaced by the first row.
    /// Selection only: this never rewinds the list, so the caller owns the
    /// scroll decision just as it does for `select_index`.
    pub(super) fn select_id(&mut self, id: &str) -> Option<usize> {
        let index = {
            let visible = self.visible_items();
            visible.iter().position(|item| item.id == id)?
        };
        self.selected_id = Some(id.to_string());
        Some(index)
    }

    /// Compute the next selection index for a relative move, without mutating
    /// the selection itself.
    #[cfg(test)]
    pub(super) fn next_index(&self, delta: isize) -> Option<usize> {
        self.next_index_in(&self.visible_items(), delta)
    }

    /// Same computation with an already-computed visible list, so callers that
    /// also need the item at that index do not filter/sort twice.
    pub(super) fn next_index_in(&self, visible: &[&VaultItem], delta: isize) -> Option<usize> {
        if visible.is_empty() {
            return None;
        }
        let Some(current) = self
            .selected_id
            .as_deref()
            .and_then(|id| visible.iter().position(|item| item.id == id))
        else {
            // With no selection, Down starts at the first row and Up at the
            // last one, matching the audit panel's keyboard behaviour.
            return Some(if delta >= 0 { 0 } else { visible.len() - 1 });
        };
        // `delta` is caller-controlled (a key repeat can carry an extreme
        // value), so add saturatingly: `isize::MAX`/`MIN` must clamp to the
        // list edge instead of overflowing in a debug build.
        Some(
            (current as isize)
                .saturating_add(delta)
                .clamp(0, visible.len() as isize - 1) as usize,
        )
    }

    /// Cycle to the next filter, clearing the selection and rewinding the list.
    pub(super) fn cycle_filter(&mut self) {
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

    /// Begin a fresh search: enter search mode and drop the previous query.
    ///
    /// This is the single definition used by both the production
    /// `UiAction::StartSearch` branch in [`crate::ui::input`] and the tests.
    /// Keeping the query reset here (instead of inlining it at the call site)
    /// lets one test cover "starting a search discards the old query" for
    /// every caller.
    pub(super) fn start_search(&mut self) {
        self.searching = true;
        self.query.clear();
        self.deselect_and_rewind();
    }

    /// Finish search or settings editing.
    ///
    /// Confirming the query leaves no valid selection behind: use the shared
    /// deselection path so the list rewinds exactly like every other query
    /// edit (start, push, pop) and filter/sort changes do.
    pub(super) fn finish_search(&mut self) {
        self.searching = false;
        self.deselect_and_rewind();
    }

    /// Append a character to the search query.
    pub(super) fn push_query(&mut self, text: &str) {
        self.query.push_str(text);
        self.deselect_and_rewind();
    }

    /// Remove the last character from the search query.
    pub(super) fn pop_query(&mut self) {
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
                text: String::new().into(),
            },
        ));
        state.vault.items.push(VaultItem::new(
            "b",
            "Beta",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        state
    }

    #[test]
    fn next_index_clamps_at_the_ends() {
        // Two visible rows: indices 0 and 1. A step far past either end must
        // land on a real row, not outside the list.
        let state = state_with_items();
        assert_eq!(state.visible_items().len(), 2);
        assert_eq!(state.next_index(0), Some(0));
        assert_eq!(state.next_index(1), Some(0), "Down starts at the first row");
        assert_eq!(state.next_index(-1), Some(1), "Up starts at the last row");
        assert_eq!(state.next_index(1_000), Some(0), "upper clamp");
        assert_eq!(state.next_index(-1_000), Some(1), "lower clamp");

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
                text: String::new().into(),
            },
        ));
        assert_eq!(single.next_index(1), Some(0));
        assert_eq!(single.next_index(-1), Some(0));
        assert_eq!(VaultViewState::new().next_index(1), None);
        assert_eq!(VaultViewState::new().next_index(-1), None);
    }

    #[test]
    fn next_index_saturates_at_the_isize_bounds() {
        // A delta of isize::MAX/MIN must clamp to the last/first visible row;
        // a plain `current as isize + delta` overflows here in debug builds.
        let mut state = state_with_items();
        state.selected_id = Some("b".into()); // visible index 1 of [a, b]
        assert_eq!(state.next_index(isize::MAX), Some(1));
        assert_eq!(state.next_index(isize::MIN), Some(0));

        state.selected_id = Some("a".into()); // visible index 0
        assert_eq!(state.next_index(isize::MAX), Some(1));
        assert_eq!(state.next_index(isize::MIN), Some(0));

        // Without a selection the sign alone picks the starting edge; these
        // extremes must take the same branch as any other large delta.
        let mut no_selection = state_with_items();
        no_selection.selected_id = None;
        assert_eq!(no_selection.next_index(isize::MAX), Some(0));
        assert_eq!(no_selection.next_index(isize::MIN), Some(1));

        // A single-row view saturates to that row in both directions.
        let mut single = VaultViewState::new();
        single.vault.items.push(VaultItem::new(
            "s",
            "Solo",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        single.selected_id = Some("s".into());
        assert_eq!(single.next_index(isize::MAX), Some(0));
        assert_eq!(single.next_index(isize::MIN), Some(0));
    }

    #[test]
    fn selection_is_revalidated_after_filtering() {
        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        state.query = "Beta".into();
        assert!(!state.revalidate_selection());
        assert_eq!(state.selected_id, None);
    }

    #[test]
    fn push_query_appends_a_whole_ime_string() {
        let mut state = state_with_items();
        state.push_query("日本");
        state.push_query("語");
        assert_eq!(state.query, "日本語");
    }

    #[test]
    fn cycle_filter_clears_selection() {
        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        state.cycle_filter();
        assert_eq!(state.selected_id, None);
        assert_eq!(state.filter, Filter::Favorites);
    }

    #[test]
    fn cycle_filter_visits_all_eight_stages_before_wrapping() {
        use Filter::*;

        let mut state = state_with_items();
        state.selected_id = Some("a".into());
        let stages = vec![
            Favorites,
            Kind(ItemKind::Login),
            Kind(ItemKind::SecureNote),
            Kind(ItemKind::Card),
            Kind(ItemKind::Identity),
            Kind(ItemKind::SshKey),
            NoFolder,
            All,
        ];
        let mut before = state.rewind_calls;
        for expected in stages {
            state.cycle_filter();
            assert_eq!(
                state.filter, expected,
                "cycle_filter must advance through every filter stage"
            );
            assert_eq!(state.selected_id, None, "each stage clears the selection");
            assert_eq!(state.rewind_calls, before + 1, "each stage rewinds once");
            before = state.rewind_calls;
        }

        // A ninth press wraps back to the first stage of the cycle.
        state.cycle_filter();
        assert_eq!(state.filter, Favorites);
    }

    #[test]
    fn every_deselection_path_rewinds_to_the_first_row() {
        // One observable result shared by all deselection paths: no selection
        // and exactly one rewind request.

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
            ("finish_search", |state| state.finish_search()),
            ("push_query", |state| state.push_query("B")),
            ("pop_query", |state| state.pop_query()),
        ];

        for (name, apply) in paths {
            let mut state = state_with_items();
            state.selected_id = Some("a".into());
            let before = state.rewind_calls;

            apply(&mut state);

            assert_eq!(state.selected_id, None, "{name}: selection must be cleared");
            assert_eq!(state.rewind_calls, before + 1, "{name}: scroll must rewind");
        }
    }

    #[test]
    fn select_id_follows_a_stable_id_without_a_first_row_fallback() {
        let mut state = state_with_items();
        assert_eq!(state.select_id("b"), Some(1));
        assert_eq!(state.selected_id.as_deref(), Some("b"));
        assert_eq!(state.select_id("missing"), None);
        assert_eq!(state.selected_id.as_deref(), Some("b"));

        state.query = "Alpha".into();
        assert_eq!(
            state.select_id("b"),
            None,
            "a filtered-out id must not select row 0"
        );
        assert_eq!(state.selected_id.as_deref(), Some("b"));
    }

    #[test]
    fn select_index_reports_only_real_changes() {
        let mut state = state_with_items();

        // Out-of-range indices (including overflow-sized ones) are ignored.
        assert!(!state.select_index(2));
        assert!(!state.select_index(usize::MAX));
        assert_eq!(state.selected_id, None);

        // A real, not-yet-selected row reports the change.
        assert!(state.select_index(1));
        assert_eq!(state.selected_id.as_deref(), Some("b"));

        // Re-selecting the already selected row is not a change.
        assert!(!state.select_index(1));
        assert_eq!(state.selected_id.as_deref(), Some("b"));

        // Switching to a different visible row is a change.
        assert!(state.select_index(0));
        assert_eq!(state.selected_id.as_deref(), Some("a"));
    }

    #[test]
    fn select_index_and_select_id_delegate_scrolling_to_the_caller() {
        // `deselect_and_rewind` is the only selection helper that may rewind.
        // The two `select_*` helpers only change `selected_id` and hand back
        // the information a caller needs to scroll on its own (change flag /
        // visible-row index); they must never call the rewind path.
        let mut state = state_with_items();
        let before = state.rewind_calls;

        assert!(state.select_index(1));
        assert_eq!(state.selected_id.as_deref(), Some("b"));
        assert_eq!(
            state.rewind_calls, before,
            "select_index must leave scrolling to the click handler"
        );

        assert_eq!(state.select_id("a"), Some(0));
        assert_eq!(state.selected_id.as_deref(), Some("a"));
        assert_eq!(
            state.rewind_calls, before,
            "select_id returns the index for the caller to scroll to"
        );

        // Even no-op outcomes must not rewind.
        assert!(!state.select_index(usize::MAX));
        assert_eq!(state.select_id("missing"), None);
        assert_eq!(state.selected_id.as_deref(), Some("a"));
        assert_eq!(state.rewind_calls, before);

        // An empty view obeys the same contract.
        let mut empty = VaultViewState::new();
        assert!(!empty.select_index(0));
        assert_eq!(empty.select_id("anything"), None);
        assert_eq!(empty.rewind_calls, 0);

        // Contrast: the shared deselection path still rewinds exactly once,
        // so the assertion above is not vacuous.
        state.deselect_and_rewind();
        assert_eq!(state.selected_id, None);
        assert_eq!(state.rewind_calls, before + 1);
    }

    #[test]
    fn selection_indexes_address_the_visible_list_under_filter_and_sort() {
        let mut state = state_with_items(); // a=Alpha, b=Beta
        state.vault.items.push(VaultItem::new(
            "c",
            "Gamma",
            ItemData::SecureNote {
                text: String::new().into(),
            },
        ));
        // Hide Alpha behind the Favorites filter; keep Beta and Gamma visible.
        state.vault.items[1].favorite = true;
        state.vault.items[2].favorite = true;

        // Descending sort reverses the visible rows relative to insertion order.
        state.sort = SortKey::NameDesc;
        let ids: Vec<String> = state
            .visible_items()
            .iter()
            .map(|item| item.id.clone())
            .collect();
        assert_eq!(ids, vec!["c", "b", "a"]);

        // Row 0 is the first *visible* row, not the first inserted vault item.
        assert!(state.select_index(0));
        assert_eq!(state.selected_id.as_deref(), Some("c"));
        {
            let all = state.visible_items();
            let next = state.next_index_in(&all, 1).unwrap();
            assert_eq!(next, 1);
            assert_eq!(all[next].id, "b", "Down follows the sorted visible list");
            assert_eq!(state.next_index_in(&all, -1), Some(0));
        }

        // With the filter applied, index 1 must name the second surviving row.
        state.filter = Filter::Favorites;
        let visible_ids: Vec<String> = state
            .visible_items()
            .iter()
            .map(|item| item.id.clone())
            .collect();
        assert_eq!(visible_ids, vec!["c", "b"]);
        assert!(state.select_index(1));
        assert_eq!(state.selected_id.as_deref(), Some("b"));
        assert!(
            !state.select_index(2),
            "an index past the visible list must be ignored"
        );
        assert_eq!(state.selected_id.as_deref(), Some("b"));

        // A selection hidden by the filter is not located by its position in
        // the whole vault: the move starts from the first/last visible row.
        state.selected_id = Some("a".into());
        {
            let visible = state.visible_items();
            let down = state.next_index_in(&visible, 1).unwrap();
            assert_eq!(visible[down].id, "c");
            let up = state.next_index_in(&visible, -1).unwrap();
            assert_eq!(visible[up].id, "b");
        }

        // From a visible selection the relative move clamps inside that list.
        state.selected_id = Some("b".into());
        {
            let visible = state.visible_items();
            assert_eq!(state.next_index_in(&visible, 1), Some(1));
            assert_eq!(state.next_index_in(&visible, -1), Some(0));
        }
    }

    #[test]
    fn revalidate_selection_keeps_a_valid_selection_without_rewinding() {
        let mut state = state_with_items();
        state.selected_id = Some("b".into());
        let before = state.rewind_calls;

        assert!(state.revalidate_selection());
        assert_eq!(state.selected_id.as_deref(), Some("b"));
        assert_eq!(
            state.rewind_calls, before,
            "a still-valid selection must not rewind the list"
        );

        // The invalid branch stays the single rewind path.
        state.selected_id = Some("missing".into());
        assert!(!state.revalidate_selection());
        assert_eq!(state.selected_id, None);
        assert_eq!(state.rewind_calls, before + 1);
    }

    #[test]
    fn revalidate_selection_treats_no_selection_as_valid_without_side_effects() {
        // `selection_in_view(None, ..)` is deliberately true: actions that
        // need a row use `required_item_index` instead, so revalidation must
        // not select the first row or rewind on behalf of an absent selection.
        let mut state = state_with_items();
        state.selected_id = None;
        let before = state.rewind_calls;

        assert!(state.revalidate_selection());
        assert_eq!(state.selected_id, None);
        assert_eq!(
            state.rewind_calls, before,
            "an absent selection must not rewind the list"
        );

        // An empty view obeys the same contract.
        let mut empty = VaultViewState::new();
        assert!(empty.revalidate_selection());
        assert_eq!(empty.selected_id, None);
        assert_eq!(empty.rewind_calls, 0);
    }

    #[test]
    fn cycling_from_a_folder_or_nofolder_returns_to_all() {
        let mut state = state_with_items();
        state.filter = Filter::Folder("f1".into());
        state.cycle_filter();
        assert_eq!(state.filter, Filter::All);

        state.filter = Filter::NoFolder;
        state.cycle_filter();
        assert_eq!(state.filter, Filter::All);
    }

    #[test]
    fn start_search_discards_a_previous_query_and_its_selection() {
        // The production `UiAction::StartSearch` branch calls the same helper,
        // so this single test covers both the test-only caller and the app.
        let mut state = state_with_items();
        // A non-empty query that still matches "a": clearing it is observable
        // in `query` and in the restored, unfiltered visible list.
        state.query = "Alpha".into();
        state.selected_id = Some("a".into());
        assert_eq!(
            state.visible_items().len(),
            1,
            "precondition: query filters"
        );
        let before = state.rewind_calls;

        state.start_search();

        assert!(state.searching, "starting a search must enter search mode");
        assert_eq!(state.query, "", "a fresh search must drop the old query");
        assert_eq!(state.selected_id, None);
        assert_eq!(state.rewind_calls, before + 1);
        assert_eq!(
            state.visible_items().len(),
            2,
            "clearing the query must restore the unfiltered list"
        );
    }

    #[test]
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
        let before = state.rewind_calls;
        state.finish_search();
        assert!(!state.searching);
        assert_eq!(state.query, "B", "confirming must keep the query");
        assert_eq!(
            state.rewind_calls,
            before + 1,
            "confirming search rewinds through deselect_and_rewind"
        );
    }

    #[test]
    fn empty_query_backspace_rewinds_every_time() {
        // BackspaceSearch maps to `pop_query` even when the query is empty.
        // The no-op character removal must still drop the selection and rewind
        // the list, so repeated presses never leave a stale scroll position.
        let mut state = state_with_items();
        assert_eq!(state.query, "", "precondition: empty query");
        state.selected_id = Some("b".into());
        let before = state.rewind_calls;

        state.pop_query();

        assert_eq!(state.query, "", "an empty query stays empty");
        assert_eq!(
            state.selected_id, None,
            "even a no-op pop drops the selection"
        );
        assert_eq!(state.rewind_calls, before + 1, "an empty pop still rewinds");

        // The same holds without a selection and on repeated presses.
        let mut empty = VaultViewState::new();
        for expected in 1..=3 {
            empty.pop_query();
            assert_eq!(empty.query, "");
            assert_eq!(empty.rewind_calls, expected);
        }
    }

    #[test]
    fn reset_restores_every_view_field() {
        let mut state = state_with_items();
        state.query = "Alpha".into();
        state.filter = Filter::Favorites;
        state.sort = SortKey::NameDesc;
        state.searching = true;
        state.selected_id = Some("a".into());
        state.audit_report = Some(crate::health::Report::default());
        let before = state.rewind_calls;

        state.reset();

        assert!(state.vault.items.is_empty(), "reset drops the vault data");
        assert_eq!(state.query, "");
        assert_eq!(state.filter, Filter::All);
        assert_eq!(state.sort, SortKey::NameAsc);
        assert!(!state.searching);
        assert_eq!(state.selected_id, None);
        assert_eq!(state.audit_report, None);
        assert_eq!(state.rewind_calls, before + 1);

        // A reset view must be indistinguishable from a freshly created one.
        let fresh = VaultViewState::new();
        assert_eq!(state.filter, fresh.filter);
        assert_eq!(state.query, fresh.query);
        assert_eq!(state.sort, fresh.sort);
        assert_eq!(state.searching, fresh.searching);
        assert_eq!(state.selected_id, fresh.selected_id);
        assert_eq!(state.audit_report, fresh.audit_report);
        assert!(fresh.vault.items.is_empty());
    }
}
