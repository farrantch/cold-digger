"use strict";
(() => {
  const manifest = window.DA_INVENTORY;
  if (!manifest) return;
  const access = window.DA_ACCESS;
  const folders = manifest.folders, $ = id => document.getElementById(id);
  const el = (tag, text, cls) => {
    const result = document.createElement(tag);
    if (text !== undefined) result.textContent = text;
    if (cls) result.className = cls;
    return result;
  };
  const paths = {
    folder: 'M3 7V5a1 1 0 0 1 1-1h5l2 3h9a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1Z',
    drive: 'M5 4h14l2 10v6H3v-6ZM3 14h18M7 17h.01M11 17h.01',
    file: 'M14 3H5v18h14V8ZM14 3v5h5M8 12h8M8 16h6',
    image: 'M3 3h18v18H3ZM3 17l6-7 5 6 3-3 4 4M16 7h.01',
    video: 'M3 5h13v14H3ZM16 10l5-3v10l-5-3',
    audio: 'M9 18V5l11-2v12M9 8l11-2M9 18c0 4-6 4-6 1s6-4 6-1M20 15c0 4-6 4-6 1s6-4 6-1',
    archive: 'M4 3h16v18H4ZM10 3v3h3v3h-3v3h3v3h-3v3h3',
    crypto: 'M8 11V7a4 4 0 0 1 8 0v4M5 11h14v10H5ZM12 15v2',
    browser: 'M3 4h18v16H3ZM3 9h18M6 6.5h.01M9 6.5h.01',
    search: 'M16 16l5 5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
    left: 'M14 5l-7 7 7 7', right: 'M10 5l7 7-7 7', down: 'M5 9l7 7 7-7',
    up: 'M5 14l7-7 7 7', download: 'M12 3v12M7 10l5 5 5-5M4 16v5h16v-5',
    sidebar: 'M3 4h18v16H3ZM9 4v16', details: 'M3 4h18v16H3ZM15 4v16',
    all: 'M3 3h7v7H3ZM14 3h7v7h-7ZM3 14h7v7H3ZM14 14h7v7h-7',
  };
  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', 'icon ' + name);
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS(svg.namespaceURI, 'path');
    path.setAttribute('d', paths[name] || paths.file); svg.append(path); return svg;
  }
  function button(text, action, cls) {
    const b = el('button', text, cls); b.type = 'button'; b.addEventListener('click', action); return b;
  }
  const count = n => Number(n || 0).toLocaleString();
  const counted = (n, noun) => `${count(n)} ${noun}${n === 1 ? '' : 's'}`;
  const size = n => n == null ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : n < 1073741824 ? `${(n / 1048576).toFixed(1)} MiB` : `${(n / 1073741824).toFixed(2)} GiB`;
  const labels = {all: 'All files', allocated: 'Existing', deleted: 'Deleted', reallocated: 'Reallocated', unknown: 'Carved / unknown'};
  const total = values => Object.values(values || {}).reduce((a, b) => a + b, 0);
  const stateCount = (f, state = route.state) => state === 'all' ? total(f.counts) : (f.counts?.[state] || 0);
  const visibleFolder = f => route.state === 'all' || stateCount(f) > 0 || f.dir_counts?.[route.state] > 0;
  const suffix = f => (f.name.match(/\.([^.]+)$/)?.[1] || '').toLowerCase();
  function kind(f) {
    if (f.isFolder) return f.parent === 'root' ? 'drive' : 'folder';
    const ext = suffix(f);
    if (/^(jpg|jpeg|png|gif|webp|bmp|tif|tiff|heic|heif|dng|cr2|nef)$/.test(ext)) return 'image';
    if (/^(mp4|mov|avi|mkv|mpg|mpeg|m4v|webm|3gp)$/.test(ext)) return 'video';
    if (/^(mp3|wav|flac|ogg|aac|m4a|wma|aiff|opus)$/.test(ext)) return 'audio';
    if (f.category === 'crypto') return 'crypto';
    if (['browser', 'browser_history'].includes(f.category)) return 'browser';
    if (/^(zip|7z|rar|tar|gz|bz2|xz|iso)$/.test(ext)) return 'archive';
    if (/^(txt|md|pdf|doc|docx|xls|xlsx|csv|ppt|pptx|odt|rtf|json|xml|html|htm)$/.test(ext)) return 'document';
    return 'other';
  }
  function recovery(f) {
    if (access.cached.has(f.id)) return access.label(f);
    if (f.status === 'partial') return 'Partial export';
    if (f.artifact && f.status === 'exported') return 'Exported';
    if (f.artifact) return 'Content available';
    return ({pending: 'Not exported', 'metadata-only': 'Metadata only', 'skipped-limit': 'Export limit', skipped: 'Skipped', error: 'Export failed', failed: 'Export failed', empty: 'Empty file'})[f.status] || f.status || 'Not exported';
  }
  function timestamp(n, full = false) {
    if (!Number.isFinite(n) || n <= 0) return '—';
    const date = new Date(n * 1000);
    if (Number.isNaN(date.getTime())) return '—';
    return full ? date.toISOString().replace('T', ' ').replace('.000Z', ' UTC') : date.toISOString().slice(0, 10);
  }
  function pathOf(id) {
    const parts = [];
    while (id && id !== 'root') { parts.unshift(folders[id].name); id = folders[id].parent; }
    return parts.join(' / ') || 'All volumes';
  }
  const defaults = {folder: 'root', state: 'all', q: '', scope: 'all', recovery: 'all', kind: 'all', sort: 'name', dir: 'asc', page: 0, limit: 100};
  function readRoute() {
    const p = new URLSearchParams(location.hash.slice(1)), value = {...defaults};
    for (const key of Object.keys(defaults)) if (p.has(key)) value[key] = p.get(key);
    if (labels[location.hash.slice(1)]) value.state = location.hash.slice(1);
    if (p.has('file')) { value.q = p.get('file'); value.scope = 'all'; value.state = 'all'; value.file = p.get('file'); }
    if (!Object.hasOwn(folders, value.folder)) value.folder = 'root';
    for (const [key, allowed] of Object.entries({state: Object.keys(labels), scope: ['folder', 'subtree', 'all'], recovery: ['all', 'recovered', 'complete', 'partial', 'missing'], kind: ['all', 'image', 'video', 'audio', 'document', 'archive', 'crypto', 'browser', 'other'], sort: ['name', 'state', 'size', 'modified', 'status'], dir: ['asc', 'desc']})) {
      if (!allowed.includes(value[key])) value[key] = defaults[key];
    }
    value.page = Math.max(0, Math.min(10000000, Math.floor(Number(value.page) || 0)));
    value.limit = [50, 100, 250].includes(Number(value.limit)) ? Number(value.limit) : 100;
    return value;
  }
  let route = readRoute(), entries = [], selected = null, generation = 0, debounce, revealAfterRefresh = null;
  const expanded = new Set(['root']), treeLimits = new Map();
  let historyIndex = 0, historyMax = 0;
  const historyKey = Math.random().toString(36).slice(2);
  function url(value) {
    const params = new URLSearchParams();
    for (const key of Object.keys(defaults)) if (value[key] !== defaults[key]) params.set(key, value[key]);
    return '#' + params.toString();
  }
  history.replaceState({explorer: historyKey, index: 0}, '', location.href);
  function navigate(patch, replace = false, reveal = null) {
    clearTimeout(debounce); revealAfterRefresh = reveal;
    const next = {...route, page: 0, ...patch}; delete next.file;
    if (replace) history.replaceState({explorer: historyKey, index: historyIndex}, '', url(next));
    else {
      historyIndex++; historyMax = historyIndex;
      history.pushState({explorer: historyKey, index: historyIndex}, '', url(next));
    }
    route = next; refresh();
  }
  function locationChanged() {
    clearTimeout(debounce);
    if (history.state?.explorer === historyKey) historyIndex = history.state.index;
    else {
      historyIndex++; historyMax = historyIndex;
      history.replaceState({explorer: historyKey, index: historyIndex}, '', location.href);
    }
    route = readRoute(); refresh();
  }
  // popstate also fires for fragment navigation; hashchange would refresh twice.
  addEventListener('popstate', locationChanged);
  function goFolder(id) {
    expanded.add(id);
    showDetails(false);
    navigate({folder: id, q: '', scope: id === 'root' ? 'all' : 'folder', recovery: 'all', kind: 'all'});
    $('explorer').classList.remove('mobile-folders');
  }
  function expandAncestors(id) {
    while (id) {
      const parent = folders[id].parent;
      if (parent) expanded.add(parent);
      id = parent;
    }
  }
  function renderStates() {
    $('file-states').replaceChildren();
    for (const [state, label] of Object.entries(labels)) {
      const b = button('', () => navigate({state}));
      b.dataset.state = state; b.setAttribute('aria-pressed', String(route.state === state));
      b.append(state === 'all' ? icon('all') : el('span', '', 'state-dot ' + state), el('span', label), el('span', count(state === 'all' ? total(manifest.counts) : manifest.counts[state]), 'state-count'));
      $('file-states').append(b);
    }
    $('active-view').textContent = labels[route.state];
    const note = ({deleted: 'Deleted paths come from surviving metadata. Select a file to see whether its content was recovered.', reallocated: 'These deleted entries point to reused blocks. Exported bytes may belong to a replacement file.', unknown: 'Carving can recover content without an original path. Deletion state and folder structure may be unknown.'})[route.state];
    $('state-note').hidden = !note; $('state-note').textContent = note || '';
  }
  function renderTree() {
    const root = el('ul');
    const ancestors = new Set(); let current = route.folder;
    while (current) { ancestors.add(current); current = folders[current].parent; }
    function add(parent, id, depth) {
      const f = folders[id], children = f.children.filter(key => visibleFolder(folders[key]) || ancestors.has(key));
      const li = el('li'), row = el('div', undefined, 'tree-row');
      li.setAttribute('role', 'none'); row.style.paddingLeft = `${depth * 13}px`;
      const toggle = button('', () => { expanded.has(id) ? expanded.delete(id) : expanded.add(id); renderTree(); }, 'tree-toggle');
      toggle.tabIndex = -1; toggle.setAttribute('aria-label', `${expanded.has(id) ? 'Collapse' : 'Expand'} ${f.name}`);
      if (children.length) toggle.append(icon(expanded.has(id) ? 'down' : 'right')); else toggle.disabled = true;
      const name = button('', () => goFolder(id), 'tree-item');
      name.setAttribute('role', 'treeitem'); name.setAttribute('aria-level', depth + 1);
      name.setAttribute('aria-selected', String(route.folder === id)); name.setAttribute('aria-label', f.name);
      name.tabIndex = route.folder === id ? 0 : -1; name.dataset.folder = id;
      if (children.length) name.setAttribute('aria-expanded', String(expanded.has(id)));
      name.title = pathOf(id);
      name.append(icon(id === 'root' ? 'all' : f.parent === 'root' ? 'drive' : 'folder'), el('span', f.name, 'tree-name'), el('span', count(stateCount(f)), 'tree-count'));
      name.addEventListener('keydown', event => {
        const buttons = [...$('folder-tree').querySelectorAll('.tree-item')], index = buttons.indexOf(name);
        let target;
        if (event.key === 'ArrowDown') target = buttons[index + 1];
        else if (event.key === 'ArrowUp') target = buttons[index - 1];
        else if (event.key === 'Home') target = buttons[0];
        else if (event.key === 'End') target = buttons.at(-1);
        else if (event.key === 'ArrowRight' && children.length) {
          if (!expanded.has(id)) { expanded.add(id); renderTree(); target = treeButton(id); }
          else target = treeButton(children[0]);
        } else if (event.key === 'ArrowLeft') {
          if (expanded.has(id)) { expanded.delete(id); renderTree(); target = treeButton(id); }
          else target = treeButton(f.parent);
        } else return;
        event.preventDefault(); target?.focus();
      });
      row.append(toggle, name); li.append(row); parent.append(li);
      if (expanded.has(id) && children.length) {
        const group = el('ul'); group.setAttribute('role', 'group'); li.append(group);
        const limit = treeLimits.get(id) || 100;
        const visible = children.slice(0, limit);
        // A deep link must reveal its branch without rendering every earlier sibling.
        const branch = children.find(child => ancestors.has(child));
        if (branch && !visible.includes(branch)) visible.push(branch);
        for (const child of visible) add(group, child, depth + 1);
        if (children.length > visible.length) {
          const more = el('li'); more.setAttribute('role', 'none');
          more.append(button(`Show more folders (${count(children.length - visible.length)})`, () => {treeLimits.set(id, limit + 100); renderTree();}, 'tree-more')); group.append(more);
        }
      }
    }
    add(root, 'root', 0); $('folder-tree').replaceChildren(root);
  }
  const treeButton = id => [...$('folder-tree').querySelectorAll('.tree-item')].find(n => n.dataset.folder === id);
  function renderLocation() {
    $('go-back').disabled = historyIndex <= 0; $('go-forward').disabled = historyIndex >= historyMax;
    $('go-up').disabled = route.folder === 'root';
    const chain = []; let id = route.folder;
    while (id) { chain.unshift(id); id = folders[id].parent; }
    $('breadcrumbs').replaceChildren();
    chain.forEach((key, index) => {
      if (index) $('breadcrumbs').append(el('span', '›', 'crumb-separator'));
      const crumb = button(folders[key].name, () => goFolder(key)); crumb.title = pathOf(key);
      if (key === route.folder) crumb.setAttribute('aria-current', 'location');
      $('breadcrumbs').append(crumb);
    });
    $('breadcrumbs').scrollLeft = $('breadcrumbs').scrollWidth;
    $('search').value = route.q; $('search-scope').value = route.scope;
    $('recovery-filter').value = route.recovery; $('kind-filter').value = route.kind;
    $('clear-search').hidden = !route.q; $('reset-filters').hidden = !isFiltered();
    $('search').placeholder = `Search ${route.scope === 'all' ? 'all volumes' : folders[route.folder].name}`;
  }
  const isFiltered = () => !!route.q.trim() || route.kind !== 'all' || route.recovery !== 'all';
  window.DA_CHUNKS = {};
  const pending = new Map(), lru = new Map();
  function loadChunk(id) {
    if (Object.hasOwn(window.DA_CHUNKS, id)) {
      lru.delete(id); lru.set(id, true); return Promise.resolve(window.DA_CHUNKS[id]);
    }
    if (pending.has(id)) return pending.get(id);
    const promise = new Promise((resolve, reject) => {
      const script = el('script'); let timer;
      function finish(error) {
        clearTimeout(timer); script.remove(); pending.delete(id);
        if (error) { delete window.DA_CHUNKS[id]; reject(error); return; }
        const data = window.DA_CHUNKS[id];
        if (!Array.isArray(data)) { delete window.DA_CHUNKS[id]; reject(new Error('Invalid inventory data. Regenerate the report.')); return; }
        lru.delete(id); lru.set(id, true);
        while (lru.size > 24) { const oldest = lru.keys().next().value; lru.delete(oldest); delete window.DA_CHUNKS[oldest]; }
        resolve(data);
      }
      script.src = `dashboard-data/inventory-${id}.js`;
      script.onload = () => finish();
      script.onerror = () => finish(new Error(`Could not read inventory part ${id + 1}. Keep the dashboard-data folder beside files.html, or regenerate the report.`));
      timer = setTimeout(() => { script.onload = script.onerror = null; finish(new Error('Inventory load timed out. Check that the case folder is available, then retry.')); }, 15000);
      document.body.append(script);
    });
    pending.set(id, promise); return promise;
  }
  function message(title, detail, retry = false) {
    $('list-message').hidden = false;
    $('list-message').replaceChildren(icon(retry ? 'file' : 'search'), el('strong', title), el('p', detail));
    if (retry) $('list-message').append(button('Retry', refresh));
    else if (isFiltered()) $('list-message').append(button('Clear search & filters', () => navigate({q: '', kind: 'all', recovery: 'all'})));
  }
  function fileMatches(f, allowed, query) {
    if (allowed && !allowed.has(f.folder)) return false;
    if (route.state !== 'all' && f.state !== route.state) return false;
    if (route.kind === 'crypto' ? f.category !== 'crypto' : route.kind === 'browser' ? !['browser', 'browser_history'].includes(f.category) : route.kind !== 'all' && kind(f) !== route.kind) return false;
    if (route.recovery === 'recovered' && !f.artifact) return false;
    if (route.recovery === 'complete' && (!f.artifact || f.status !== 'exported')) return false;
    if (route.recovery === 'partial' && (!f.artifact || f.status !== 'partial')) return false;
    if (route.recovery === 'missing' && f.artifact) return false;
    return !query || `${f.name} ${f.path} ${f.id}`.toLowerCase().includes(query);
  }
  async function refresh() {
    const token = ++generation, selectedBefore = selected?.id;
    expandAncestors(route.folder); renderStates(); renderTree(); renderLocation();
    treeButton(route.folder)?.scrollIntoView({block: 'nearest'});
    entries = []; selected = null; renderDetails();
    $('file-rows').replaceChildren(); $('list-scroll').scrollTop = 0;
    $('file-table').setAttribute('aria-busy', 'true');
    $('previous-page').disabled = $('next-page').disabled = true; $('page-number').disabled = true;
    $('summary').textContent = 'Loading…'; message('Loading folder…', 'Reading the saved inventory.');
    const query = route.q.trim().toLowerCase(), recursive = isFiltered() && route.scope !== 'folder';
    let allowed = new Set([route.folder]);
    if (recursive && route.scope === 'all') allowed = null;
    else if (recursive) {
      const stack = [route.folder];
      while (stack.length) for (const id of folders[stack.pop()].children) { allowed.add(id); stack.push(id); }
    }
    const chunks = allowed ? [...new Set([...allowed].flatMap(id => folders[id].chunks))] : Array.from({length: manifest.chunk_count}, (_, i) => i);
    const result = [], childIds = recursive ? (allowed ? [...allowed] : Object.keys(folders)) : folders[route.folder].children;
    if (route.kind === 'all' && route.recovery === 'all') for (const id of childIds) {
      const f = folders[id];
      if (id !== 'root' && id !== route.folder && visibleFolder(f) && (!query || `${f.name} ${pathOf(id)}`.toLowerCase().includes(query))) result.push({...f, isFolder: true, path: pathOf(id)});
    }
    let index = 0, completed = 0, failure;
    async function worker() {
      while (index < chunks.length && token === generation && !failure) {
        const id = chunks[index++];
        try {
          const rows = await loadChunk(id);
          if (token !== generation) return;
          for (const row of rows) if (fileMatches(row, allowed, query)) result.push(row);
          completed++; $('summary').textContent = `Reading inventory · ${count(completed)} / ${count(chunks.length)} parts`;
        } catch (error) { failure = error; }
      }
    }
    await Promise.all(Array.from({length: Math.min(4, chunks.length)}, worker));
    if (token !== generation) return;
    $('file-table').setAttribute('aria-busy', 'false'); $('page-number').disabled = false;
    if (failure) {
      $('summary').textContent = 'Inventory unavailable';
      message('Couldn’t load this view', failure.message, true); return;
    }
    entries = result; sortEntries();
    if (route.file) selected = entries.find(f => f.id === route.file) || null;
    else if (selectedBefore) selected = entries.find(f => f.id === selectedBefore) || null;
    renderRows(); renderDetails();
    if (selected && route.file) showDetails(true);
  }
  const collator = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'});
  function sortEntries() {
    const direction = route.dir === 'asc' ? 1 : -1;
    entries.sort((a, b) => {
      if (!!a.isFolder !== !!b.isFolder) return a.isFolder ? -1 : 1;
      let comparison = 0;
      if (route.sort === 'size' || route.sort === 'modified') {
        const left = a[route.sort], right = b[route.sort];
        if (left == null || right == null) comparison = left == null ? (right == null ? 0 : 1) : -1;
        else comparison = (left - right) * direction;
      } else {
        const left = route.sort === 'state' ? labels[a.state] || '' : route.sort === 'status' ? (a.isFolder ? '' : recovery(a)) : a.name;
        const right = route.sort === 'state' ? labels[b.state] || '' : route.sort === 'status' ? (b.isFolder ? '' : recovery(b)) : b.name;
        comparison = collator.compare(left, right) * direction;
      }
      return comparison || collator.compare(a.name, b.name) || collator.compare(a.id, b.id);
    });
  }
  function selectFile(f, focus = false) {
    selected = f;
    for (const row of $('file-rows').children) {
      const active = row.dataset.id === f.id;
      row.classList.toggle('selected', active); row.tabIndex = active ? 0 : -1;
      row.setAttribute('aria-selected', String(active));
      if (active && focus) { row.focus(); row.scrollIntoView({block: 'nearest'}); }
    }
    renderDetails(); showDetails(true);
  }
  function activate(f) {
    if (f.isFolder) goFolder(f.id);
    else { selectFile(f); const read=$('open-from-image'); if(read)read.click(); else $('detail-content').querySelector('video,a.primary-action')?.focus(); }
  }
  function download(f, compact = false) {
    const a = el('a', compact ? undefined : 'Download original', compact ? 'row-download' : 'primary-action');
    a.href = f.artifact || access.cached.get(f.id)?.url; a.download = f.name; a.setAttribute('aria-label', `Download ${f.name}`);
    if (compact) { a.append(icon('download')); a.title = 'Download original'; }
    a.addEventListener('click', event => event.stopPropagation()); a.addEventListener('dblclick', event => event.stopPropagation());
    return a;
  }
  function renderRows() {
    if (revealAfterRefresh) {
      const index = entries.findIndex(f => f.id === revealAfterRefresh);
      if (index >= 0) { selected = entries[index]; route.page = Math.floor(index / route.limit); }
      revealAfterRefresh = null;
    }
    const pages = Math.max(1, Math.ceil(entries.length / route.limit));
    route.page = Math.min(route.page, pages - 1);
    // Canonicalize a page that became out of range without adding a history entry.
    if (!route.file) history.replaceState({explorer: historyKey, index: historyIndex}, '', url(route));
    const start = route.page * route.limit, visible = entries.slice(start, start + route.limit);
    const hasSelection = visible.some(f => f.id === selected?.id);
    $('file-rows').replaceChildren(); $('list-message').hidden = true;
    const fragment = document.createDocumentFragment();
    for (const [offset, f] of visible.entries()) {
      const row = el('tr'); row.dataset.id = f.id; row.dataset.folder = f.isFolder ? f.id : '';
      row.tabIndex = f.id === selected?.id || (!hasSelection && offset === 0) ? 0 : -1;
      row.classList.toggle('selected', f.id === selected?.id);
      row.setAttribute('aria-selected', String(f.id === selected?.id));
      const nameCell = el('td'), name = el('div', undefined, 'file-name'), text = el('div', undefined, 'name-text');
      text.append(el('span', f.name, f.isFolder ? 'folder-name' : ''));
      if (isFiltered() && route.scope !== 'folder') text.append(el('span', f.isFolder ? pathOf(f.parent) : pathOf(f.folder), 'file-location'));
      name.append(icon(kind(f)), text); nameCell.append(name); nameCell.title = f.isFolder ? pathOf(f.id) : f.path;
      const state = el('td', f.isFolder ? (f.parent === 'root' ? 'Volume' : 'Folder') : labels[f.state], 'file-state ' + (f.state || ''));
      const bytes = el('td', f.isFolder ? '—' : size(f.size), 'file-size');
      const modified = el('td', f.isFolder ? '—' : timestamp(f.modified), 'modified-cell file-date');
      if (f.modified) modified.title = timestamp(f.modified, true);
      const status = el('td');
      status.append(el('span', f.isFolder ? counted(stateCount(f), 'file') : recovery(f), f.isFolder ? 'folder-count' : 'recovery-badge ' + (f.artifact ? f.status : f.status === 'error' ? 'error' : '')));
      if (f.isFolder) status.title = 'Files in this folder and its subfolders, for the selected state';
      const action = el('td'); if (!f.isFolder && (f.artifact || access.cached.has(f.id))) action.append(download(f, true));
      row.append(nameCell, state, bytes, modified, status, action);
      row.addEventListener('click', () => selectFile(f));
      row.addEventListener('dblclick', () => activate(f));
      row.addEventListener('keydown', event => {
        if (event.target !== row) return;
        if (event.key === 'Enter') { event.preventDefault(); activate(f); }
        else if (event.key === ' ') { event.preventDefault(); selectFile(f); }
        else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
          event.preventDefault();
          const index = event.key === 'Home' ? 0 : event.key === 'End' ? entries.length - 1 : start + offset + (event.key === 'ArrowDown' ? 1 : -1);
          if (!entries[index]) return;
          route.page = Math.floor(index / route.limit); selected = entries[index]; renderRows(); selectFile(selected, true);
        }
      });
      fragment.append(row);
    }
    $('file-rows').append(fragment);
    for (const th of document.querySelectorAll('#file-table th[data-sort]')) {
      th.removeAttribute('aria-sort'); if (th.dataset.sort === route.sort) th.setAttribute('aria-sort', route.dir === 'asc' ? 'ascending' : 'descending');
    }
    const folderCount = entries.filter(f => f.isFolder).length, fileCount = entries.length - folderCount;
    $('summary').textContent = entries.length ? `${count(start + 1)}–${count(start + visible.length)} of ${count(entries.length)} · ${counted(folderCount, 'folder')}, ${counted(fileCount, 'file')}` : '0 items';
    $('page-size').value = route.limit; $('page-number').value = route.page + 1; $('page-number').max = pages;
    $('page-total').textContent = `of ${count(pages)}`;
    $('previous-page').disabled = route.page === 0; $('next-page').disabled = route.page >= pages - 1;
    if (!entries.length) message(isFiltered() ? 'No matching items' : 'Nothing in this view', isFiltered() ? 'Try a shorter search, include subfolders, or clear the filters.' : route.state === 'all' ? 'This folder has no inventoried files or subfolders.' : `No ${labels[route.state].toLowerCase()} items in this folder. Choose another state or folder.`);
  }
  function showDetails(open) {
    $('inspector').hidden = !open; $('explorer').classList.toggle('details-open', open);
    $('toggle-details').setAttribute('aria-expanded', String(open));
    if (!open) $('detail-content').querySelector('video')?.pause();
  }
  function renderDetails() {
    const content = $('detail-content'); content.replaceChildren();
    if (!selected) {
      const symbol = el('div', undefined, 'detail-symbol'); symbol.append(icon('file'));
      content.append(symbol, el('h2', 'A closer look'), el('p', 'Select a file or folder to see its path, recovery status, and available preview.')); return;
    }
    const f = selected, type = kind(f), cached = access.cached.get(f.id), sourceUrl = f.artifact || cached?.url;
    const symbol = el('div', undefined, 'detail-symbol'); symbol.append(icon(type));
    content.append(symbol, el('h2', f.name), el('div', f.isFolder ? (f.parent === 'root' ? 'Disk volume' : 'Original folder') : `${labels[f.state]} · ${recovery(f)}`, 'detail-subtitle'));
    if (!f.isFolder && sourceUrl && ['image', 'video', 'audio'].includes(type)) {
      const preview = el(type === 'image' ? 'img' : type, undefined, 'detail-preview');
      preview.src = access.poster(f) || sourceUrl;
      if (type === 'image') { preview.alt = f.name; preview.loading = 'lazy'; }
      else { preview.src = sourceUrl; preview.controls = true; preview.preload = 'metadata'; if(type==='video' && access.poster(f))preview.poster=access.poster(f); }
      let triedOriginal = !access.poster(f) || type !== 'image';
      preview.addEventListener('error', () => {
        if (!triedOriginal) { triedOriginal = true; preview.src = sourceUrl; }
        else preview.replaceWith(el('p', 'This format cannot be previewed in this browser. Download the original to open it locally.'));
      });
      symbol.replaceWith(preview);
    }
    const actions = el('div', undefined, 'detail-actions');
    if (f.isFolder) actions.append(button('Open folder', () => goFolder(f.id)));
    else {
      if (sourceUrl) actions.append(download(f));
      if (!f.artifact && f.on_demand && access.session.image) {
        const read = button(cached ? 'Reopen from image' : 'Open from image', async () => {
          read.disabled = true; read.textContent = 'Opening…';
          try {
            await access.open(f, status => { read.textContent = `${status.status === 'queued' ? 'Waiting' : 'Reading'} · ${size(status.bytes || 0)}`; });
            if (selected?.id === f.id) { renderRows(); renderDetails(); }
          } catch(error) { read.disabled = false; read.textContent = 'Retry opening'; read.title = error.message; if(selected?.id===f.id)actions.append(el('p',error.message,'detail-warning')); }
        });
        read.id='open-from-image'; actions.append(read);
      }
      actions.append(button('Show in folder', () => {
        navigate({folder: f.folder, q: '', scope: 'folder', kind: 'all', recovery: 'all'}, false, f.id);
      }));
    }
    content.append(actions);
    const dl = el('dl');
    const field = (title, value, code = false) => {
      const dd = el('dd'); dd.append(el(code ? 'code' : 'span', value == null || value === '' ? '—' : String(value)));
      dl.append(el('dt', title), dd);
    };
    field('Original path', f.isFolder ? pathOf(f.id) : f.path);
    if (f.isFolder) {
      const volume = f.parent === 'root' ? manifest.volumes?.[f.name] : null;
      if (volume?.name) field('Volume name', volume.name);
      if (volume?.filesystem) field('Filesystem', volume.filesystem);
      field('Files including subfolders', count(stateCount(f)));
      for (const [state, label] of Object.entries(labels)) if (state !== 'all' && f.counts[state]) field(label, count(f.counts[state]));
    } else {
      field('Volume', f.volume || 'Unknown origin / carved'); field('Size in original metadata', `${size(f.size)} (${count(f.size)} bytes)`);
      field('Type', (suffix(f).toUpperCase() || 'Unknown') + (f.category ? ` · ${f.category}` : ''));
      if (f.modified) field('Modified (UTC)', timestamp(f.modified, true));
      if (f.created) field('Created (UTC)', timestamp(f.created, true));
    }
    content.append(dl);
    if (!f.isFolder) {
      if (!sourceUrl) content.append(el('p', 'Only the file’s metadata is saved here; “not exported” does not mean unreadable. ' + (access.session.image && f.on_demand ? 'Use Open from image to read this one file now.' : 'Start cold-digger serve CASE --image IMAGE for on-demand reads of files with surviving filesystem records.')));
      if (f.status === 'partial' || cached?.partial) content.append(el('p', 'Only part of this file was recovered. It may be damaged or fail to open.', 'detail-warning'));
      if (f.state === 'reallocated') content.append(el('p', 'The original blocks were reused. This content may belong to a different file.', 'detail-warning'));
      if (f.state === 'unknown') content.append(el('p', 'The original path and deletion state are not established for this file.'));
      const technical = el('details'); technical.append(el('summary', 'Recovery & evidence details'));
      const details = el('dl');
      for (const [label, value] of [['File ID', f.id], ['Filesystem record', f.inode], ['Export SHA-256', f.sha256], ['Saved artifact', f.artifact], ['Recovery status', f.status], ['Recovery notes', f.detail]]) {
        if (!value) continue;
        const dd = el('dd'); dd.append(el('code', value)); details.append(el('dt', label), dd);
      }
      technical.append(details); content.append(technical);
    }
  }
  function changePage(value) {
    route.page = Math.max(0, Math.min(Math.ceil(entries.length / route.limit) - 1, Number(value) || 0));
    renderRows(); $('list-scroll').scrollTop = 0;
  }
  for (const [id, name] of Object.entries({'toggle-sidebar': 'sidebar', 'go-back': 'left', 'go-forward': 'right', 'go-up': 'up', 'toggle-details': 'details', 'previous-page': 'left', 'next-page': 'right', 'search-icon': 'search'})) $(id).append(icon(name));
  $('go-back').onclick = () => history.back(); $('go-forward').onclick = () => history.forward();
  $('go-up').onclick = () => { if (folders[route.folder].parent) goFolder(folders[route.folder].parent); };
  $('toggle-sidebar').onclick = () => {
    const mobile = matchMedia('(max-width: 760px)').matches;
    const open = mobile ? $('explorer').classList.toggle('mobile-folders') : !$('explorer').classList.toggle('sidebar-hidden');
    $('toggle-sidebar').setAttribute('aria-expanded', String(open));
  };
  $('collapse-tree').onclick = () => { expanded.clear(); expanded.add('root'); renderTree(); };
  $('toggle-details').onclick = () => showDetails($('inspector').hidden);
  $('close-details').onclick = () => { showDetails(false); $('toggle-details').focus(); };
  $('search').addEventListener('input', () => {
    clearTimeout(debounce); generation++;
    const value = $('search').value; $('clear-search').hidden = !value;
    debounce = setTimeout(() => navigate({q: value}, true), 180);
  });
  $('clear-search').onclick = () => { navigate({q: ''}); $('search').focus(); };
  $('search-scope').onchange = () => navigate({scope: $('search-scope').value, q: $('search').value});
  for (const [id, key] of [['recovery-filter', 'recovery'], ['kind-filter', 'kind']]) {
    $(id).onchange = () => navigate({[key]: $(id).value, q: $('search').value, scope: route.scope === 'folder' ? 'subtree' : route.scope});
  }
  $('reset-filters').onclick = () => navigate({q: '', kind: 'all', recovery: 'all'});
  $('page-size').onchange = () => { route.limit = Number($('page-size').value); route.page = 0; renderRows(); $('list-scroll').scrollTop = 0; };
  $('previous-page').onclick = () => changePage(route.page - 1); $('next-page').onclick = () => changePage(route.page + 1);
  $('page-number').onchange = () => changePage(Math.floor(Number($('page-number').value)) - 1);
  for (const th of document.querySelectorAll('#file-table th[data-sort]')) th.querySelector('button').onclick = () => {
    route.dir = route.sort === th.dataset.sort && route.dir === 'asc' ? 'desc' : 'asc'; route.sort = th.dataset.sort; route.page = 0;
    sortEntries(); renderRows(); $('list-scroll').scrollTop = 0;
  };
  document.addEventListener('keydown', event => {
    const typing = ['INPUT', 'SELECT', 'TEXTAREA'].includes(event.target.tagName);
    if ((event.key === '/' && !typing) || ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f')) {
      event.preventDefault(); $('search').focus(); $('search').select();
    } else if (event.altKey && event.key === 'ArrowUp' && route.folder !== 'root') {
      event.preventDefault(); $('go-up').click();
    } else if (event.altKey && event.key === 'ArrowLeft' && historyIndex > 0) {
      event.preventDefault(); history.back();
    } else if (event.altKey && event.key === 'ArrowRight' && historyIndex < historyMax) {
      event.preventDefault(); history.forward();
    } else if (event.key === 'Escape') {
      if (typing && route.q) { navigate({q: ''}); $('search').focus(); }
      else showDetails(false);
    }
  });
  if (matchMedia('(max-width: 760px)').matches) $('toggle-sidebar').setAttribute('aria-expanded', 'false');
  access.ready.then(refresh);
})();
