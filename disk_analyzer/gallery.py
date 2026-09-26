"""Media library shell shared by static reports and the local case server."""
from pathlib import Path
from .report import page


def media_browser_page(nav):
    body = nav + """
<header class="media-heading"><div><div class="eyebrow">YOUR RECOVERY / VISUAL LIBRARY</div><h1>Photos &amp; videos</h1><p>Explore photos and videos in their original folders.</p></div><a id="media-file-browser" href="files.html" class="media-link">Open file browser ↗</a></header>
<div id="access-note" role="status"></div>
<section id="media-library" aria-label="Media library">
 <aside id="media-sidebar" class="media-sidebar" aria-label="Media folders">
  <div class="sidebar-label">LIBRARY</div><div id="library-types"></div>
  <div class="sidebar-label album-heading"><span>FOLDERS</span><button id="collapse-media-tree" aria-label="Collapse all folders" title="Collapse all folders">−</button></div>
  <input id="album-search" type="search" aria-label="Find media folder" placeholder="Find a folder…">
  <div id="albums" role="tree" aria-label="Media folder hierarchy"></div>
  <p class="media-local-note">All previews stay local.<br>Folder names come from the disk’s surviving metadata.</p>
 </aside>
 <div class="library-main">
  <div class="media-location"><button id="toggle-media-folders" aria-controls="media-sidebar" aria-expanded="false">Folders</button><div class="media-navigation"><button id="media-back" aria-label="Back" title="Back (Alt + Left)">←</button><button id="media-forward" aria-label="Forward" title="Forward (Alt + Right)">→</button><button id="media-up" aria-label="Parent folder" title="Parent folder (Alt + Up)">↑</button></div><nav id="media-breadcrumbs" aria-label="Media folder path"></nav></div>
  <div class="media-toolbar"><input id="search" type="search" aria-label="Search media" placeholder="Search filenames, folders, or file IDs…"><select id="media-scope" aria-label="Folder scope"><option value="subtree">Include subfolders</option><option value="folder">This folder only</option></select><label class="density-control">Tile size <input id="tile-size" type="range" min="150" max="300" step="25" value="200"></label></div>
  <div class="media-filters">
   <select id="state" aria-label="File state"><option value="all">All file states</option><option value="allocated">Existing files</option><option value="deleted">Deleted files</option><option value="reallocated">Reallocated files</option><option value="unknown">Carved / unknown</option></select>
   <select id="availability" aria-label="Content availability"><option value="all">All content</option><option value="exported">Saved exports</option><option value="image">Not yet exported</option><option value="partial">Partial exports</option></select>
   <select id="media-sort" aria-label="Sort media"><option value="name">Name</option><option value="newest">Modified: newest</option><option value="oldest">Modified: oldest</option><option value="largest">Size: largest</option><option value="smallest">Size: smallest</option></select>
   <label class="duplicate-option"><input id="group-copies" type="checkbox"> Group identical files</label><button id="reset-media" hidden>Clear filters</button>
  </div>
  <div class="media-section-title"><div><h2 id="album-title">All media</h2><span id="summary" aria-live="polite"></span><p id="media-scope-note"></p></div></div>
  <div id="gallery-scroll"><section id="media-subfolders" aria-label="Subfolders" hidden><div class="subfolder-heading"><h3 id="subfolders-title">Folders</h3><span id="subfolders-count"></span></div><div id="media-folder-cards"></div><button id="more-media-folders" hidden>More folders</button></section><div id="results" class="media-grid"></div><div id="media-empty" hidden></div></div>
  <footer class="media-footer"><span id="page-range"></span><div><select id="media-page-size" aria-label="Items per page"><option value="48">48 / page</option><option value="96" selected>96 / page</option><option value="192">192 / page</option></select><button id="previous-page" aria-label="Previous page">‹</button><label>Page <input id="media-page" type="number" min="1" value="1" aria-label="Page number"> <span id="media-pages"></span></label><button id="next-page" aria-label="Next page">›</button></div></footer>
 </div>
</section>
<p class="media-hint">Open a tile to view · ← → next / previous · Space plays or pauses video · Double-click a photo for actual size</p>
<dialog id="viewer" aria-label="Media viewer">
 <header class="viewer-top"><div><strong id="viewer-name"></strong><span id="viewer-position"></span></div><div class="viewer-actions"><button id="zoom-media">Actual size</button><button id="fullscreen-media">Fullscreen</button><button id="info-media" aria-expanded="false">Details</button><a id="download-media" download hidden>Download original</a><button id="close-viewer" aria-label="Close viewer">×</button></div></header>
 <div class="viewer-body"><div class="viewer-canvas"><button id="previous-media" class="viewer-arrow" aria-label="Previous media">‹</button><div id="viewer-media"></div><button id="next-media" class="viewer-arrow" aria-label="Next media">›</button><div id="viewer-message" role="status" hidden></div></div><aside id="viewer-info" hidden></aside></div>
 <footer class="viewer-bottom"><p id="viewer-caption"></p><div id="filmstrip" aria-label="Nearby media"></div></footer>
</dialog>
<script src="dashboard-data/access.js"></script><script src="dashboard-data/media-folders.js"></script><script src="dashboard-data/media.js"></script><script src="dashboard-data/gallery.js"></script>
"""
    return page('Cold Digger · Photos & videos', body, css=Path(__file__).with_name('static').joinpath('gallery.css').read_text(), body_class='gallery-page')
