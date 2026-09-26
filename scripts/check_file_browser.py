"""Offline browser regression checks against the synthetic report demo."""
import re
from playwright.sync_api import expect


def check_explorer(page, root):
    page.goto((root / 'files.html').as_uri())
    expect(page.locator('h1')).to_have_text('File browser')
    rows = page.locator('#file-rows > tr')
    expect(rows).to_have_count(2)
    expect(page.locator('#go-back')).to_be_disabled()
    expect(page.locator('#search-scope')).to_have_value('all')
    page.locator('#search').fill('wallet.json')
    expect(rows).to_have_count(1)
    page.locator('#clear-search').click()
    expect(rows).to_have_count(2)
    page.locator('#file-states button[data-state="deleted"]').click()
    page.get_by_role('treeitem', name='p1', exact=True).click()
    page.get_by_role('treeitem', name='Documents', exact=True).click()
    expect(rows).to_have_count(3)  # Archive, escaped filename, and the wallet fixture.
    wallet = rows.filter(has_text='wallet.json')
    wallet.click()
    expect(page.locator('#detail-content h2')).to_have_text('wallet.json')
    expect(page.locator('#detail-content')).to_contain_text('Deleted · Exported')
    expect(page.locator('#detail-content .primary-action')).to_have_attribute('download', 'wallet.json')
    page.screenshot(path=str(root / 'file-browser-details.png'), full_page=True)
    page.locator('#close-details').click()
    rows.filter(has_text='Archive').dblclick()
    expect(rows).to_have_count(100)
    expect(page.locator('#breadcrumbs button').last).to_have_text('Archive')
    expect(rows.first).to_contain_text('document-00000.txt')
    expect(page.locator('#file-table th[data-sort="name"]')).to_have_attribute('aria-sort', 'ascending')
    page.locator('#file-table th[data-sort="name"] button').click()
    expect(rows.first).to_contain_text('document-02499.txt')
    page.locator('#file-table th[data-sort="name"] button').click()
    page.locator('#next-page').click()
    expect(page.locator('#page-number')).to_have_value('2')
    expect(rows.first).to_contain_text('document-00300.txt')
    page.locator('#page-number').fill('9'); page.locator('#page-number').press('Enter')
    expect(rows).to_have_count(34)
    page.locator('#page-number').fill('1'); page.locator('#page-number').press('Enter')
    page.locator('#page-size').select_option('50')
    expect(rows).to_have_count(50)
    rows.last.focus(); page.keyboard.press('ArrowDown')
    expect(page.locator('#page-number')).to_have_value('2')
    expect(page.locator('#file-rows tr.selected')).to_contain_text('document-00150.txt')
    page.locator('#close-details').click()
    page.locator('#page-size').select_option('100')
    page.screenshot(path=str(root / 'deleted-files.png'), full_page=True)
    # Browser and in-app back/forward restore the folder and selected state.
    page.locator('#go-up').click()
    expect(page.locator('#breadcrumbs button').last).to_have_text('Documents')
    page.locator('#go-back').click()
    expect(page.locator('#breadcrumbs button').last).to_have_text('Archive')
    page.locator('#go-forward').click()
    expect(page.locator('#breadcrumbs button').last).to_have_text('Documents')
    # Search folder names, then search files across all volumes.
    page.locator('#search').fill('Archive')
    expect(rows).to_have_count(1)
    expect(rows).to_contain_text('Archive')
    page.locator('#search-scope').select_option('all')
    page.locator('#search').fill('onerror')
    expect(rows).to_have_count(1)
    expect(rows).to_contain_text('<img src=x onerror=alert(1)>.txt')
    expect(page.locator('#file-rows img')).to_have_count(0)
    page.reload()
    expect(page.locator('#search')).to_have_value('onerror')
    expect(rows).to_have_count(1)
    rows.click()
    expect(page.locator('#detail-content')).to_contain_text('Only the file’s metadata')
    page.get_by_role('button', name='Show in folder', exact=True).click()
    expect(page.locator('#search')).to_have_value('')
    expect(page.locator('#file-rows tr.selected')).to_contain_text('onerror')
    # Search an item on a later page, then reveal it in its original folder.
    page.locator('#search-scope').select_option('all')
    page.locator('#search').fill('document-02499')
    expect(rows).to_have_count(1); rows.click()
    page.get_by_role('button', name='Show in folder', exact=True).click()
    expect(page.locator('#page-number')).to_have_value('9')
    expect(page.locator('#file-rows tr.selected')).to_contain_text('document-02499')
    # Filtering from a parent includes subfolders automatically and visibly.
    page.get_by_role('treeitem', name='p1', exact=True).click()
    page.locator('#kind-filter').select_option('image')
    expect(page.locator('#search-scope')).to_have_value('subtree')
    expect(rows).to_have_count(28)
    page.locator('#recovery-filter').select_option('missing')
    expect(rows).to_have_count(0)
    expect(page.locator('#list-message')).to_contain_text('No matching items')
    page.locator('#recovery-filter').select_option('recovered')
    expect(rows).to_have_count(28)
    rows.first.click()
    expect(page.locator('#detail-content img')).to_be_visible()
    assert page.locator('#detail-content img').evaluate('img => img.complete && img.naturalWidth > 0')
    page.screenshot(path=str(root / 'file-browser-preview.png'), full_page=True)
    # Switching to available files leaves the current folder and filters intact.
    page.locator('#file-states button[data-state="allocated"]').click()
    expect(rows).to_have_count(28)
    expect(rows.first).to_contain_text('Photo-000.png')
    page.locator('#reset-filters').click()
    page.get_by_role('treeitem', name='All volumes', exact=True).click()
    page.locator('#file-states button[data-state="unknown"]').click()
    expect(rows).to_have_count(1)
    rows.dblclick()
    expect(rows).to_have_count(1)
    expect(rows).to_contain_text('f00001.png')
    # Existing evidence links still reveal the exact file, without a scan.
    page.goto((root / 'files.html').as_uri() + '#file=E' + __import__('hashlib').sha256(b'deleted/Documents/wallet.json').hexdigest()[:20])
    expect(rows).to_have_count(1)
    expect(page.locator('#inspector')).to_be_visible()
    expect(page.locator('#detail-content h2')).to_have_text('wallet.json')
    # Small screens have an explicit folder drawer and no page overflow.
    page.set_viewport_size({'width': 390, 'height': 844})
    page.locator('#close-details').click()
    page.locator('#toggle-sidebar').click()
    expect(page.locator('#sidebar')).to_be_visible()
    page.get_by_role('treeitem', name='All volumes', exact=True).click()
    expect(page.locator('#sidebar')).to_be_hidden()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.screenshot(path=str(root / 'file-browser-mobile.png'), full_page=True)
    page.set_viewport_size({'width': 1440, 'height': 1100})


def make_stress_case(root):
    """Large synthetic inventory, with no disk image, scan, or private content."""
    import hashlib
    import json
    from disk_analyzer.store import Store
    from disk_analyzer.report import write_report
    from scripts.make_demo import png

    store = Store(root)
    ids = {}
    def add(path, state='allocated', size=1, mode='r/rrw-r--r--', volume='p1', payload=None, extension='.txt', status='exported'):
        ident = 'E' + hashlib.sha256((volume + state + path).encode()).hexdigest()[:20]
        ids[path] = ident
        store.file({'id': ident, 'volume': volume, 'inode': ident, 'path': path, 'size': size,
                    'deleted': state, 'category': 'other', 'priority': 5,
                    'metadata': json.dumps({'mode': mode, 'mtime': 1688169600 + size, 'crtime': 1688169600})})
        if payload is not None:
            digest = hashlib.sha256(payload).hexdigest()
            artifact = 'artifacts/' + digest + extension
            (root / artifact).write_bytes(payload)
            store.file_status(ident, status, detail='Synthetic recovery note', artifact=artifact, sha256=digest)
    try:
        store.put('version', 'synthetic'); store.put('status', 'complete')
        for v in ('p1', 'p2'):
            store.volume({'id': v, 'name': 'Synthetic volume ' + v, 'start': 0, 'length': 1,
                          'signature': 'demo', 'filesystem_status': 'complete'})
        for i in range(52000): add(f'/Bulk/item-{i:05d}.txt', size=i + 1)
        for i in range(350): add(f'/Many/folder-{i:04d}/note.txt', state='deleted')
        add('/EmptyDeleted', state='deleted', mode='d/drwxr-xr-x')
        add('/Mixed/02-small.txt', size=2, payload=b'ok')
        add('/Mixed/03-middle.txt', size=128)
        add('/Mixed/10-large.bin', size=4 * 1024**3, state='reallocated', payload=b'partial', extension='.bin', status='partial')
        add('/Mixed/photo.png', state='deleted', size=len(png()), payload=png(), extension='.png')
        store.db.execute("UPDATE files SET category='crypto' WHERE id=?", (ids['/Mixed/photo.png'],))
        add('/Mixed/untrusted.html', size=64, payload=b'<script>throw new Error("Recovered HTML executed")</script>', extension='.html')
        add('/Mixed/unsupported.heic', size=28, payload=b'Unrenderable synthetic fixture', extension='.heic')
        add('\\Users\\Example\\Documents\\other-volume.txt', volume='p2', state='deleted')
        write_report(store)
    finally:
        store.close()
    return ids


def check_stress_explorer(page, root, ids):
    page.goto((root / 'files.html').as_uri())
    rows = page.locator('#file-rows > tr')
    page.get_by_role('treeitem', name='p1', exact=True).click()
    page.get_by_role('treeitem', name='Many', exact=True).click()
    expect(rows).to_have_count(100)
    # Hundreds of child folders stay paginated in the list and incremental in the tree.
    assert page.get_by_role('treeitem').count() < 120
    expect(page.locator('#summary')).to_contain_text('350')
    page.locator('#folder-tree .tree-more').click()
    assert 200 <= page.get_by_role('treeitem').count() < 220
    page.locator('#page-number').fill('4'); page.locator('#page-number').press('Enter')
    expect(rows).to_have_count(50)
    rows.filter(has_text='folder-0349').dblclick()
    expect(rows).to_have_count(1)
    expect(page.get_by_role('treeitem', name='folder-0349')).to_be_visible()
    assert page.get_by_role('treeitem').count() < 225  # Revealing a late child doesn't render all siblings.
    page.locator('#file-states button[data-state="deleted"]').click()
    page.get_by_role('treeitem', name='EmptyDeleted', exact=True).click()
    expect(rows).to_have_count(0)
    expect(page.locator('#list-message')).to_contain_text('Nothing in this view')
    # Scope and provenance work across more than one volume, including Windows paths.
    page.locator('#search-scope').select_option('all')
    page.locator('#search').fill('other-volume')
    expect(rows).to_have_count(1)
    rows.click()
    expect(page.locator('#detail-content')).to_contain_text('p2')
    page.get_by_role('button', name='Show in folder', exact=True).click()
    expect(page.locator('#breadcrumbs')).to_contain_text('p2')
    expect(page.locator('#file-rows tr.selected')).to_contain_text('other-volume.txt')
    # More than 24 data chunks exercises eviction and complete results with bounded DOM.
    page.locator('#file-states button[data-state="all"]').click()
    page.locator('#search-scope').select_option('all')
    page.locator('#search').fill('item-')
    expect(page.locator('#file-table')).to_have_attribute('aria-busy', 'false', timeout=30000)
    expect(page.locator('#summary')).to_contain_text('52,000', timeout=30000)
    expect(rows).to_have_count(100)
    assert page.evaluate('Object.keys(window.DA_CHUNKS).length') <= 24
    page.locator('#search').fill('other-volume')
    expect(rows).to_have_count(1)
    # A query abandoned immediately must never overwrite the newer result.
    page.locator('#search').fill('item-')
    page.wait_for_timeout(200)
    page.locator('#search').fill('02-small')
    expect(rows).to_have_count(1)
    expect(rows).to_contain_text('02-small.txt')
    rows.click(); page.get_by_role('button', name='Show in folder', exact=True).click()
    expect(rows).to_have_count(6)
    page.locator('#file-table th[data-sort="size"] button').click()
    expect(rows.first).to_contain_text('02-small.txt')
    page.locator('#file-table th[data-sort="size"] button').click()
    expect(rows.first).to_contain_text('10-large.bin')
    rows.first.click()
    expect(page.locator('#detail-content')).to_contain_text('4.00 GiB')
    expect(page.locator('#detail-content')).to_contain_text('Partial export')
    expect(page.locator('#detail-content')).to_contain_text('original blocks were reused')
    page.locator('#file-table th[data-sort="modified"] button').click()
    expect(rows.first).to_contain_text('02-small.txt')
    expect(rows.first.locator('.modified-cell')).to_have_text('2023-07-01')
    page.locator('#recovery-filter').select_option('partial')
    expect(rows).to_have_count(1); expect(rows).to_contain_text('10-large.bin')
    page.locator('#recovery-filter').select_option('complete')
    expect(rows).to_have_count(4)
    page.locator('#reset-filters').click()
    for category in ('crypto', 'image'):
        page.locator('#kind-filter').select_option(category)
        expect(rows).to_have_count(2 if category == 'image' else 1)
        rows.filter(has_text='photo.png').click()
        expect(page.locator('#detail-content img')).to_be_visible()
    page.locator('#reset-filters').click()
    rows.filter(has_text='untrusted.html').click()
    expect(page.locator('#detail-content iframe, #detail-content object, #detail-content embed')).to_have_count(0)
    expect(page.locator('#detail-content .primary-action')).to_have_attribute('download', 'untrusted.html')
    rows.filter(has_text='unsupported.heic').click()
    expect(page.locator('#detail-content')).to_contain_text('cannot be previewed')
    # Missing chunks produce a visible error, no partial list, and a working retry.
    import json
    manifest = json.loads((root / 'dashboard-data/inventory.js').read_text().split('=', 1)[1].rstrip(';\n'))
    mixed = next(f for f in manifest['folders'].values() if f['name'] == 'Mixed')
    chunk = root / f"dashboard-data/inventory-{mixed['chunks'][0]}.js"
    original = chunk.read_bytes()
    try:
        chunk.unlink()
        page.goto('about:blank')
        page.goto((root / 'files.html').as_uri() + '#folder=' + mixed['id'])
        expect(page.locator('#list-message')).to_contain_text('Couldn’t load this view')
        expect(rows).to_have_count(0)
    finally:
        chunk.write_bytes(original)
    page.get_by_role('button', name='Retry', exact=True).click()
    expect(rows).to_have_count(6)
