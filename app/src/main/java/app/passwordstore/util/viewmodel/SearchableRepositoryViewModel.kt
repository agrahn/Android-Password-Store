/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.viewmodel

import android.app.Application
import android.content.SharedPreferences
import android.os.Parcelable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.annotation.VisibleForTesting
import androidx.lifecycle.AndroidViewModel
import androidx.recyclerview.selection.ItemDetailsLookup
import androidx.recyclerview.selection.ItemKeyProvider
import androidx.recyclerview.selection.Selection
import androidx.recyclerview.selection.SelectionPredicates
import androidx.recyclerview.selection.SelectionTracker
import androidx.recyclerview.selection.StorageStrategy
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import app.passwordstore.data.password.PasswordItem
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.data.repo.store.GPG_ID
import app.passwordstore.data.repo.store.StoreNode
import app.passwordstore.data.repo.store.extension
import app.passwordstore.data.repo.store.isHidden
import app.passwordstore.data.repo.store.isUnder
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.util.autofill.AutofillPreferences
import app.passwordstore.util.checkMainThread
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.settings.DirectoryStructure
import app.passwordstore.util.settings.PasswordSortOrder
import app.passwordstore.util.settings.PreferenceKeys
import com.github.androidpasswordstore.sublimefuzzy.Fuzzy
import dagger.hilt.android.lifecycle.HiltViewModel
import java.io.File
import java.text.Collator
import java.util.Locale
import javax.inject.Inject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.yield
import me.zhanghai.android.fastscroll.PopupTextProvider

private fun StoreNode.toPasswordItem() =
  if (isFile) {
    if (name == GPG_ID) PasswordItem.newGpgIdItem(name, this)
    else if (extension == "gpg") PasswordItem.newPassword(name, this)
    else PasswordItem.newOtherItem(name, this)
  } else PasswordItem.newCategory(name, this)

private fun PasswordItem.fuzzyMatch(filter: String): Int {
  val (_, score) = Fuzzy.fuzzyMatch(filter, longName)
  return score
}

private val CaseInsensitiveComparator = Collator.getInstance().apply { strength = Collator.PRIMARY }

// DirectoryStructure only reads path components and never touches the filesystem, so a relative
// File over the store-relative path gives it the same view for every backend.
private fun PasswordItem.relativeFile() = File(node.path)

private fun PasswordItem.Companion.makeComparator(
  typeSortOrder: PasswordSortOrder,
  directoryStructure: DirectoryStructure,
): Comparator<PasswordItem> {
  return when (typeSortOrder) {
      PasswordSortOrder.FOLDER_FIRST -> compareBy { it.type }
      // In order to let INDEPENDENT not distinguish between items based on their type, we
      // simply
      // declare them all equal at this stage.
      PasswordSortOrder.INDEPENDENT -> Comparator { _, _ -> 0 }
      PasswordSortOrder.FILE_FIRST -> compareByDescending { it.type }
      PasswordSortOrder.RECENTLY_USED -> PasswordSortOrder.RECENTLY_USED.comparator
    }
    .then(
      compareBy(nullsLast(CaseInsensitiveComparator)) {
        directoryStructure.getIdentifierFor(it.relativeFile())
      }
    )
    .then(
      compareBy(nullsLast(CaseInsensitiveComparator)) {
        directoryStructure.getUsernameFor(it.relativeFile())
      }
    )
}

val PasswordItem.stableId: String
  get() = node.path

enum class FilterMode {
  NoFilter,
  StrictDomain,
  Fuzzy,
  Exact,
}

enum class SearchMode {
  RecursivelyInSubdirectories,
  InCurrentDirectoryOnly,
}

enum class ListMode {
  FilesOnly,
  DirectoriesOnly,
  AllEntries,
}

@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class SearchableRepositoryViewModel
@Inject
constructor(
  application: Application,
  dispatcherProvider: DispatcherProvider,
  @SettingsPreferences private val settings: SharedPreferences,
) : AndroidViewModel(application) {

  private var _updateCounter = 0
  private val updateCounter: Int
    get() = _updateCounter

  private fun forceUpdateOnNextSearchAction() {
    _updateCounter++
  }

  private val root: StoreNode
    get() = PasswordRepository.storeRoot

  private val showHiddenContents
    get() = settings.getBoolean(PreferenceKeys.SHOW_HIDDEN_CONTENTS, false)

  private val defaultSearchMode
    get() =
      if (settings.getBoolean(PreferenceKeys.FILTER_RECURSIVELY, true)) {
        SearchMode.RecursivelyInSubdirectories
      } else {
        SearchMode.InCurrentDirectoryOnly
      }

  private val typeSortOrder
    get() = PasswordSortOrder.getSortOrder(settings)

  private val directoryStructure
    get() = AutofillPreferences.directoryStructure(getApplication())

  private val itemComparator
    get() = PasswordItem.makeComparator(typeSortOrder, directoryStructure)

  private data class SearchAction(
    val baseDirectory: StoreNode,
    val filter: String,
    val filterMode: FilterMode,
    val searchMode: SearchMode,
    val listMode: ListMode,
    // This counter can be increased to force a reexecution of the search action even if all
    // other arguments are left unchanged.
    val updateCounter: Int,
  )

  private fun makeSearchAction(
    baseDirectory: StoreNode,
    filter: String,
    filterMode: FilterMode,
    searchMode: SearchMode,
    listMode: ListMode,
  ): SearchAction {
    return SearchAction(
      baseDirectory = baseDirectory,
      filter = filter,
      filterMode = filterMode,
      searchMode = searchMode,
      listMode = listMode,
      updateCounter = updateCounter,
    )
  }

  private fun updateSearchAction(action: SearchAction) = action.copy(updateCounter = updateCounter)

  private val searchActionFlow =
    MutableStateFlow(
      makeSearchAction(
        baseDirectory = root,
        filter = "",
        filterMode = FilterMode.NoFilter,
        searchMode = SearchMode.InCurrentDirectoryOnly,
        listMode = ListMode.AllEntries,
      )
    )

  data class SearchResult(val passwordItems: List<PasswordItem>, val isFiltered: Boolean)

  val searchResult =
    searchActionFlow
      .mapLatest { searchAction ->
        checkMainThread()
        val listResultFlow =
          when (searchAction.searchMode) {
            SearchMode.RecursivelyInSubdirectories ->
              listFilesRecursively(searchAction.baseDirectory)
            SearchMode.InCurrentDirectoryOnly -> listFiles(searchAction.baseDirectory)
          }
        val prefilteredResultFlow =
          when (searchAction.listMode) {
            ListMode.FilesOnly ->
              listResultFlow.filter { it.isFile }.flowOn(dispatcherProvider.io())
            ListMode.DirectoriesOnly ->
              listResultFlow.filter { it.isDirectory }.flowOn(dispatcherProvider.io())
            ListMode.AllEntries -> listResultFlow
          }
        val passwordList =
          when (if (searchAction.filter == "") FilterMode.NoFilter else searchAction.filterMode) {
            FilterMode.NoFilter -> {
              prefilteredResultFlow
                .map { it.toPasswordItem() }
                .flowOn(dispatcherProvider.io())
                .toList()
                .sortedWith(itemComparator)
            }
            FilterMode.Fuzzy -> {
              prefilteredResultFlow
                .map {
                  val item = it.toPasswordItem()
                  Pair(item.fuzzyMatch(searchAction.filter), item)
                }
                .filter { it.first > 0 }
                .flowOn(dispatcherProvider.io())
                .toList()
                .sortedWith(
                  compareByDescending<Pair<Int, PasswordItem>> { it.first }
                    .thenBy(itemComparator) { it.second }
                )
                .map { it.second }
            }
            FilterMode.Exact -> {
              prefilteredResultFlow
                .filter { node ->
                  node.path.contains(searchAction.filter, ignoreCase = true)
                }
                .map { it.toPasswordItem() }
                .flowOn(dispatcherProvider.io())
                .toList()
                .sortedWith(itemComparator)
            }
            FilterMode.StrictDomain -> {
              check(searchAction.listMode == ListMode.FilesOnly) {
                "Searches with StrictDomain search mode can only list files"
              }
              val regex = generateStrictDomainRegex(searchAction.filter)
              if (regex != null) {
                prefilteredResultFlow
                  .filter { node -> regex.containsMatchIn(node.path) }
                  .map { it.toPasswordItem() }
                  .flowOn(dispatcherProvider.io())
                  .toList()
                  .sortedWith(itemComparator)
              } else {
                emptyList()
              }
            }
          }
        SearchResult(passwordList, isFiltered = searchAction.filterMode != FilterMode.NoFilter)
      }
      .flowOn(dispatcherProvider.io())

  private fun listFiles(dir: StoreNode): Flow<StoreNode> {
    return dir.children().filter(::shouldTake).asFlow()
  }

  private fun listFilesRecursively(dir: StoreNode): Flow<StoreNode> {
    return dir
      // Take top directory even if it is hidden.
      .walk { node -> node != dir && shouldTake(node) && node.isVisibleBelow(dir) }
      .asFlow()
      .map {
        yield()
        it
      }
  }

  /**
   * Whether every directory between this node and [dir], [dir] itself excluded, is one we would
   * descend into.
   *
   * [StoreNode.walk] filters what it returns, not what it descends into, so the pruning the old
   * `File.walkTopDown().onEnter { }` did has to be expressed here: an entry below a directory we
   * would not enter is not listed even though it passes [shouldTake] itself.
   */
  private fun StoreNode.isVisibleBelow(dir: StoreNode): Boolean {
    var ancestor = parent()
    while (ancestor != null && ancestor.path != dir.path) {
      if (!shouldTake(ancestor)) return false
      ancestor = ancestor.parent()
    }
    return true
  }

  private val _currentDir = MutableStateFlow(root)
  val currentDir = _currentDir.asStateFlow()

  data class NavigationStackEntry(val dir: StoreNode, val recyclerViewState: Parcelable?)

  private val navigationStack = ArrayDeque<NavigationStackEntry>()

  fun shouldTake(node: StoreNode): Boolean =
    with(node) {
      if (showHiddenContents) {
        return !name.startsWith(".git")
      }
      if (isDirectory) {
        !isHidden
      } else {
        !isHidden && extension == "gpg"
      }
    }

  fun navigateTo(
    newDirectory: StoreNode = root,
    listMode: ListMode = ListMode.AllEntries,
    recyclerViewState: Parcelable? = null,
    pushPreviousLocation: Boolean = true,
  ) {
    require(newDirectory.isUnder(root)) { "Trying to access target outside the repository" }
    if (!newDirectory.exists()) return
    require(newDirectory.isDirectory) { "Can only navigate to a directory" }
    if (pushPreviousLocation) {
      navigationStack.addFirst(NavigationStackEntry(_currentDir.value, recyclerViewState))
    }
    searchActionFlow.update {
      makeSearchAction(
        filter = "",
        baseDirectory = newDirectory,
        filterMode = FilterMode.NoFilter,
        searchMode = SearchMode.InCurrentDirectoryOnly,
        listMode = listMode,
      )
    }
    _currentDir.update { newDirectory }
  }

  val canNavigateBack
    get() = navigationStack.isNotEmpty()

  /**
   * Navigate back to the last location on the [navigationStack] and restore a cached scroll
   * position if possible.
   *
   * Returns the old RecyclerView's LinearLayoutManager state as a [Parcelable] if it was cached.
   */
  fun navigateBack(listMode: ListMode = ListMode.AllEntries): Parcelable? {
    if (!canNavigateBack) return null
    val (oldDir, oldRecyclerViewState) = navigationStack.removeFirst()
    navigateTo(oldDir, listMode, pushPreviousLocation = false)
    return oldRecyclerViewState
  }

  fun reset() {
    navigationStack.clear()
    forceUpdateOnNextSearchAction()
    navigateTo(pushPreviousLocation = false)
  }

  fun search(
    filter: String,
    baseDirectory: StoreNode? = null,
    filterMode: FilterMode = FilterMode.Exact,
    searchMode: SearchMode? = null,
    listMode: ListMode = ListMode.AllEntries,
  ) {
    require(baseDirectory?.isDirectory != false) { "Can only search in a directory" }
    searchActionFlow.update {
      makeSearchAction(
        filter = filter,
        baseDirectory = baseDirectory ?: _currentDir.value,
        filterMode = filterMode,
        searchMode = searchMode ?: defaultSearchMode,
        listMode = listMode,
      )
    }
  }

  fun forceRefresh() {
    forceUpdateOnNextSearchAction()
    // A store mode switch swaps the backend underneath the current node, and a node keeps the
    // backend it was created from, so resolve it again before re-listing.
    searchActionFlow.update { action ->
      val liveBase =
        try {
          PasswordRepository.nodeAt(action.baseDirectory.path)
        } catch (e: CancellationException) {
          throw e
        } catch (e: Exception) {
          root
        }
      updateSearchAction(action).copy(baseDirectory = liveBase)
    }
  }

  companion object {

    @VisibleForTesting
    fun generateStrictDomainRegex(domain: String): Regex? {
      // Valid domains do not contain path separators.
      if (domain.contains('/')) return null
      // Matches the start of a path component, which is either the start of the
      // string or a path separator.
      val prefix = """(?:^|/)"""
      val escapedFilter = Regex.escape(domain.replace("/", ""))
      // Matches either the filter literally or a strict subdomain of the filter term.
      // We allow a lot of freedom in what a subdomain is, as long as it is not an
      // email address.
      val subdomain = """(?:(?:[^/@]+\.)?$escapedFilter)"""
      // Matches the end of a path component, which is either the literal ".gpg" or a
      // path separator.
      val suffix = """(?:\.gpg|/)"""
      // Match any relative path with a component that is a subdomain of the filter.
      return Regex(prefix + subdomain + suffix, RegexOption.IGNORE_CASE)
    }
  }
}

private object PasswordItemDiffCallback : DiffUtil.ItemCallback<PasswordItem>() {

  override fun areItemsTheSame(oldItem: PasswordItem, newItem: PasswordItem) =
    oldItem.node.path == newItem.node.path

  override fun areContentsTheSame(oldItem: PasswordItem, newItem: PasswordItem) = oldItem == newItem
}

/**
 * A view holder whose bind suspends, so that a row recycled into a second bind does not keep the
 * result of the first one. Binding a folder row reads the directory it counts, and the late half of
 * an abandoned bind must not write that count into a row that already shows another entry.
 */
interface RebindableViewHolder {

  var bindJob: Job?
}

open class SearchableRepositoryAdapter<T : RecyclerView.ViewHolder>(
  private val layoutRes: Int,
  private val viewHolderCreator: (view: View) -> T,
  private val coroutineScope: CoroutineScope,
  private val dispatcherProvider: DispatcherProvider,
  private val viewHolderBinder:
    suspend T.(item: PasswordItem, dispatcherProvider: DispatcherProvider) -> Unit,
) : ListAdapter<PasswordItem, T>(PasswordItemDiffCallback), PopupTextProvider {

  fun <T : ItemDetailsLookup<String>> makeSelectable(
    recyclerView: RecyclerView,
    itemDetailsLookupCreator: (recyclerView: RecyclerView) -> T,
  ) {
    selectionTracker =
      SelectionTracker.Builder(
          "SearchableRepositoryAdapter",
          recyclerView,
          itemKeyProvider,
          itemDetailsLookupCreator(recyclerView),
          StorageStrategy.createStringStorage(),
        )
        .withSelectionPredicate(SelectionPredicates.createSelectAnything())
        .build()
        .apply {
          addObserver(
            object : SelectionTracker.SelectionObserver<String>() {
              override fun onSelectionChanged() {
                this@SearchableRepositoryAdapter.onSelectionChangedListener?.invoke(
                  requireSelectionTracker().selection
                )
              }
            }
          )
        }
  }

  private var onItemClickedListener: ((holder: T, item: PasswordItem) -> Unit)? = null

  open fun onItemClicked(
    listener: (holder: T, item: PasswordItem) -> Unit
  ): SearchableRepositoryAdapter<T> {
    check(onItemClickedListener == null) {
      "Only a single listener can be registered for onItemClicked"
    }
    onItemClickedListener = listener
    return this
  }

  private var onSelectionChangedListener: ((selection: Selection<String>) -> Unit)? = null

  open fun onSelectionChanged(
    listener: (selection: Selection<String>) -> Unit
  ): SearchableRepositoryAdapter<T> {
    check(onSelectionChangedListener == null) {
      "Only a single listener can be registered for onSelectionChanged"
    }
    onSelectionChangedListener = listener
    return this
  }

  private val itemKeyProvider =
    object : ItemKeyProvider<String>(SCOPE_MAPPED) {
      override fun getKey(position: Int) = getItem(position).stableId

      override fun getPosition(key: String) =
        (0 until itemCount).firstOrNull { getItem(it).stableId == key } ?: RecyclerView.NO_POSITION
    }

  private var selectionTracker: SelectionTracker<String>? = null

  fun requireSelectionTracker() = selectionTracker ?: throw NullPointerException()

  private val selectedNodes
    get() = requireSelectionTracker().selection.map { PasswordRepository.nodeAt(it) }

  fun getSelectedItems() = selectedNodes.map { it.toPasswordItem() }

  fun getPositionForNode(node: StoreNode) = itemKeyProvider.getPosition(node.path)

  final override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): T {
    val view = LayoutInflater.from(parent.context).inflate(layoutRes, parent, false)
    return viewHolderCreator(view)
  }

  final override fun onBindViewHolder(holder: T, position: Int) {
    val item = getItem(position)
    holder.apply {
      if (holder is RebindableViewHolder) holder.bindJob?.cancel()
      val job =
        coroutineScope.launch(dispatcherProvider.mainImmediate()) {
          viewHolderBinder.invoke(holder, item, dispatcherProvider)
        }
      if (holder is RebindableViewHolder) holder.bindJob = job
      selectionTracker?.let { itemView.isSelected = it.isSelected(item.stableId) }
      itemView.setOnClickListener {
        // Do not emit custom click events while the user is selecting items.
        if (selectionTracker?.hasSelection() != true) onItemClickedListener?.invoke(holder, item)
      }
    }
  }

  final override fun getPopupText(view: View, position: Int): String {
    return getItem(position).name[0].toString().uppercase(Locale.getDefault())
  }
}
