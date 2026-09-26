"""Offline file explorer shell. Recovered text is inserted by textContent only."""
from pathlib import Path

from .report import page


def file_browser_page(nav):
    body = nav + """
<header class="explorer-heading">
  <div><div class="eyebrow">EXPLORE YOUR RECOVERY</div><h1>File browser</h1>
  <p>Original folders, recovered content, and what’s still waiting.</p></div>
  <a class="gallery-link" href="media.html">Photos &amp; videos <span aria-hidden="true">↗</span></a>
</header>
<section id="explorer" aria-label="File browser">
  <aside id="sidebar" aria-label="Browse folders">
    <div class="sidebar-title">FILE STATE</div>
    <div id="file-states" role="group" aria-label="Filter file state"></div>
    <div class="sidebar-title tree-heading"><span>FOLDERS</span><button id="collapse-tree" title="Collapse folders" aria-label="Collapse folders">−</button></div>
    <div id="folder-tree" role="tree" aria-label="Original folders"></div>
    <div class="sidebar-foot">Paths from surviving metadata.<br>Carved files may have no original folder.</div>
  </aside>
  <div class="explorer-content">
    <div class="location-bar">
      <button id="toggle-sidebar" class="icon-button" aria-label="Toggle folders" aria-expanded="true" title="Toggle folder sidebar"></button>
      <button id="go-back" class="icon-button" aria-label="Back" title="Back (Alt + Left)"></button>
      <button id="go-forward" class="icon-button" aria-label="Forward" title="Forward (Alt + Right)"></button>
      <button id="go-up" class="icon-button" aria-label="Parent folder" title="Parent folder (Alt + Up)"></button>
      <nav id="breadcrumbs" aria-label="Folder path"></nav>
      <button id="toggle-details" class="icon-button" aria-label="Toggle details" aria-expanded="false" title="Toggle details pane"></button>
    </div>
    <div class="search-bar">
      <div class="search-field"><span id="search-icon" aria-hidden="true"></span><input id="search" type="search" aria-label="Search files" placeholder="Search names, paths, or file IDs" autocomplete="off"><button id="clear-search" aria-label="Clear search" title="Clear search" hidden>×</button></div>
      <select id="search-scope" aria-label="Search scope"><option value="folder">This folder</option><option value="subtree">Include subfolders</option><option value="all">All volumes</option></select>
    </div>
    <div class="filter-bar">
      <label>Recovery <select id="recovery-filter"><option value="all">Any status</option><option value="recovered">Has recovered content</option><option value="complete">Fully exported</option><option value="partial">Partial exports</option><option value="missing">No recovered content</option></select></label>
      <label>Type <select id="kind-filter"><option value="all">All types</option><option value="image">Photos</option><option value="video">Videos</option><option value="audio">Audio</option><option value="document">Documents</option><option value="archive">Archives</option><option value="crypto">Crypto candidates</option><option value="browser">Browser data</option><option value="other">Other files</option></select></label>
      <button id="reset-filters" class="text-button" hidden>Reset filters</button>
      <span id="active-view"></span>
    </div>
    <div id="state-note" class="state-note" hidden></div>
    <div class="listing-layout">
      <section class="listing" aria-label="Folder contents">
        <div id="list-scroll" tabindex="-1">
          <table id="file-table" aria-label="Files and folders">
            <colgroup><col class="col-name"><col class="col-state"><col class="col-size"><col class="col-modified"><col class="col-recovery"><col class="col-action"></colgroup>
            <thead><tr>
              <th scope="col" data-sort="name"><button>Name</button></th>
              <th scope="col" data-sort="state"><button>State</button></th>
              <th scope="col" data-sort="size"><button>Size</button></th>
              <th scope="col" data-sort="modified" class="modified-cell"><button>Modified</button></th>
              <th scope="col" data-sort="status"><button>Recovery</button></th>
              <th scope="col"><span class="sr-only">Actions</span></th>
            </tr></thead>
            <tbody id="file-rows"></tbody>
          </table>
          <div id="list-message" role="status" hidden></div>
        </div>
        <footer class="list-footer">
          <span id="summary" role="status" aria-live="polite"></span>
          <div id="pagination">
            <select id="page-size" aria-label="Items per page"><option value="50">50 / page</option><option value="100" selected>100 / page</option><option value="250">250 / page</option></select>
            <button id="previous-page" class="icon-button" aria-label="Previous page"></button>
            <label class="page-label">Page <input id="page-number" aria-label="Page number" type="number" min="1" value="1"> <span id="page-total"></span></label>
            <button id="next-page" class="icon-button" aria-label="Next page"></button>
          </div>
        </footer>
      </section>
      <aside id="inspector" aria-label="File details" hidden>
        <div class="inspector-heading"><strong>Details</strong><button id="close-details" class="icon-button" aria-label="Close details">×</button></div>
        <div id="detail-content"></div>
      </aside>
    </div>
  </div>
</section>
<p class="explorer-hint">Click to select · Double-click a folder to open · Arrow keys to move · Enter to open · / to search</p>
<noscript>The interactive browser needs JavaScript enabled. <a href="inventory.csv">Download the full inventory CSV</a>.</noscript>
<script src="dashboard-data/access.js"></script><script src="dashboard-data/inventory.js"></script><script src="dashboard-data/explorer.js"></script>
"""
    css = Path(__file__).with_name("static").joinpath("explorer.css").read_text()
    return page("Cold Digger · File browser", body, css=css, body_class="explorer-page")
