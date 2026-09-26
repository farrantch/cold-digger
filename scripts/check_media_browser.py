"""Synthetic gallery interaction and local on-demand browser tests."""
from playwright.sync_api import expect


def check_media(page,root):
    page.goto((root/'media.html').as_uri())
    expect(page.locator('h1')).to_have_text('Photos & videos')
    tiles=page.locator('.media-tile')
    expect(tiles).to_have_count(58)
    page.locator('#media-page-size').select_option('48');expect(tiles).to_have_count(48)
    page.locator('#next-page').click();expect(tiles).to_have_count(10)
    page.locator('.media-button').first.click()
    expect(page.locator('#viewer')).to_be_visible();expect(page.locator('#viewer-position')).to_have_text('49 / 58')
    page.keyboard.press('ArrowLeft');expect(page.locator('#viewer-position')).to_have_text('48 / 58')
    page.locator('#zoom-media').click();expect(page.locator('#viewer-media')).to_have_class('actual-size')
    page.locator('#zoom-media').click();page.locator('#info-media').click()
    expect(page.locator('#viewer-info')).to_contain_text('Original path')
    page.locator('#close-viewer').click();expect(page.locator('#media-page')).to_have_value('1')
    page.locator('#library-types [data-type="video"]').click();expect(tiles).to_have_count(1)
    page.locator('.media-button').click()
    expect(page.locator('#viewer-media video')).to_be_visible()
    page.locator('#viewer-media video').evaluate('async el => { await el.play(); el.currentTime=.5; }')
    page.screenshot(path=str(root/'video-viewer.png'),full_page=True)
    page.locator('#close-viewer').click();page.locator('#library-types [data-type="all"]').click()
    page.locator('#group-copies').check();expect(tiles).to_have_count(2)
    page.locator('.media-tile').filter(has_text='57 copies').locator('.media-button').click()
    expect(page.locator('#viewer-info')).to_contain_text('57 identical copies')
    page.locator('#close-viewer').click();page.locator('#group-copies').uncheck()
    page.locator('#state').select_option('deleted');expect(tiles).to_have_count(29)
    page.locator('#availability').select_option('image');expect(tiles).to_have_count(0)
    expect(page.locator('#media-empty')).to_contain_text('No media in this view')
    page.locator('#reset-media').click();page.locator('#search').fill('Photo-00')
    expect(tiles).to_have_count(10)
    page.reload();expect(page.locator('#search')).to_have_value('Photo-00');expect(tiles).to_have_count(10)
    page.locator('#reset-media').click()
    page.locator('#album-search').fill('Pictures / Album')
    page.locator('#albums .media-folder-name').filter(has_text='Album').click();expect(tiles).to_have_count(48)
    expect(page.locator('#summary')).to_contain_text('56 photos')
    page.locator('#media-page-size').select_option('96');expect(tiles).to_have_count(56)
    page.screenshot(path=str(root/'gallery.png'),full_page=True)
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.locator('#toggle-media-folders').click()
    expect(page.locator('.media-sidebar')).to_be_visible()
    page.locator('#albums .media-folder-name').filter(has_text='Album').click()
    expect(page.locator('.media-sidebar')).to_be_hidden()
    page.locator('.media-button').first.click();expect(page.locator('#viewer')).to_be_visible()
    page.screenshot(path=str(root/'gallery-mobile.png'),full_page=True)
    page.locator('#close-viewer').click();page.set_viewport_size({'width':1440,'height':1100})


def check_media_hierarchy(page, root):
    """Exercise real folder relationships, route history and bounded expansion."""
    import hashlib
    import json
    from disk_analyzer.report import write_report
    from disk_analyzer.store import Store
    from scripts.make_demo import png

    store = Store(root)
    payload = png(); digest = hashlib.sha256(payload).hexdigest()
    artifact = 'artifacts/' + digest + '.png'; (root / artifact).write_bytes(payload)
    records = [
        ('p1', '/Photos/cover.png', 'allocated'),
        ('p1', '/Photos/Trips/2022/earlier.png', 'allocated'),
        ('p1', '/Photos/Trips/2023/deleted.png', 'deleted'),
        ('p1', '/Photos/Trips/2023/Nested/deeper.png', 'allocated'),
        ('p1', '/Photos/Trips/2023-archive/outside.png', 'allocated'),
        ('p1', '/Photos/Trips/<img src=x onerror=alert(1)>/escaped.png', 'allocated'),
        ('p2', '\\Photos\\Trips\\2023\\other-volume.png', 'allocated'),
        (None, 'carved.png', 'unknown'),
    ] + [('p1', f'/Many/Folder-{n:03d}/photo.png', 'allocated') for n in range(130)]
    try:
        store.put('image', {'path': 'Synthetic media navigation fixture'})
        for volume, name in [('p1', 'Windows disk'), ('p2', 'Backup disk')]:
            store.volume({'id': volume, 'name': name, 'filesystem': 'ntfs', 'signature': 'ntfs',
                          'start':0, 'length':1000000, 'filesystem_status':'complete'})
        for volume, path, state in records:
            ident = 'E' + hashlib.sha256(str((volume,path)).encode()).hexdigest()[:20]
            store.file({'id':ident, 'volume':volume, 'inode':'42', 'path':path, 'size':len(payload),
                        'deleted':state, 'category':'media', 'priority':2, 'metadata':json.dumps({'mode':'r/rrw-r--r--'})})
            store.file_status(ident, 'exported', artifact=artifact, sha256=digest)
        write_report(store)
    finally:
        store.close()

    def read_data(name):
        return json.loads((root / 'dashboard-data' / name).read_text().split('=',1)[1].rstrip(';\n'))
    folders = read_data('media-folders.js')['folders']
    media = read_data('media.js')
    def folder(path):
        return next(f['folder'] for f in media if f['path'] == path)
    year = folder('/Photos/Trips/2023/deleted.png')
    trips = folders[year]['parent']; photos = folders[trips]['parent']; volume = folders[photos]['parent']
    def tree(ident):
        return page.locator(f'.media-tree-item[data-folder="{ident}"]')
    def card(ident):
        return page.locator(f'.media-folder-card[data-folder="{ident}"]')
    tiles = page.locator('.media-tile')
    page.goto((root/'media.html').as_uri())
    expect(page.locator('#media-up')).to_be_disabled()
    expect(page.locator('.media-tree-item')).to_have_count(4)
    card(volume).click(); card(photos).click()
    expect(tiles).to_have_count(6)
    expect(page.locator('#album-title')).to_have_text('Photos')
    card(trips).click(); card(year).click()
    expect(tiles).to_have_count(2)  # Includes Nested; excludes 2023-archive and the other volume.
    expect(page.locator('#media-breadcrumbs')).to_have_text('All folders/Windows disk/Photos/Trips/2023')
    expect(tree(year)).to_have_attribute('aria-selected','true')
    expect(page.locator('#media-file-browser')).to_have_attribute('href',f'files.html#folder={year}&scope=folder')
    page.locator('#media-scope').select_option('folder'); expect(tiles).to_have_count(1)
    page.locator('#media-up').click(); expect(tiles).to_have_count(0)
    expect(page.locator('#media-empty')).to_contain_text('Open a subfolder')
    page.locator('#media-empty').get_by_role('button',name='Include subfolders').click(); expect(tiles).to_have_count(5)
    page.locator('#media-back').click(); expect(tiles).to_have_count(0)
    page.locator('#media-back').click(); expect(page.locator('#album-title')).to_have_text('2023'); expect(tiles).to_have_count(1)
    page.locator('#media-forward').click(); expect(page.locator('#album-title')).to_have_text('Trips')
    page.reload(); expect(page.locator('#media-scope')).to_have_value('folder')
    expect(page.locator('#media-forward')).to_be_enabled()
    page.locator('#media-forward').click(); expect(tiles).to_have_count(5)
    page.locator('#media-breadcrumbs').get_by_role('button',name='Photos',exact=True).click(); expect(tiles).to_have_count(6)
    page.locator('#state').select_option('deleted'); expect(tiles).to_have_count(1)
    page.locator('#reset-media').click(); expect(page.locator('#album-title')).to_have_text('Photos'); expect(tiles).to_have_count(6)
    page.locator('#search').fill('deeper'); expect(tiles).to_have_count(1)
    page.reload(); expect(tiles).to_have_count(1); expect(page.locator('#search')).to_have_value('deeper')
    page.locator('#reset-media').click()
    page.locator('#album-search').fill('2023')
    expect(page.locator('#albums .media-folder-name')).to_contain_text(['All folders','Windows disk','Photos','Trips','2023','Nested','2023-archive','Backup disk','Photos','Trips','2023'])
    tree(year).locator(':scope > .media-tree-row .media-folder-name').click()
    expect(page.locator('#album-search')).to_have_value('')
    page.screenshot(path=str(root/'hierarchy-desktop.png'),full_page=True)
    tree(year).focus(); page.keyboard.press('ArrowRight')
    expect(tree(year)).to_have_attribute('aria-expanded','true')
    page.keyboard.press('ArrowRight'); page.keyboard.press('Enter')
    expect(page.locator('#album-title')).to_have_text('Nested'); expect(tiles).to_have_count(1)
    page.keyboard.press('Alt+ArrowUp'); expect(page.locator('#album-title')).to_have_text('2023')
    page.locator('#media-breadcrumbs').get_by_role('button',name='All folders',exact=True).click()
    page.locator('#collapse-media-tree').click(); expect(page.locator('.media-tree-item')).to_have_count(4)
    page.locator('#album-search').fill('Folder-129')
    last = folder('/Many/Folder-129/photo.png')
    tree(last).locator(':scope > .media-tree-row .media-folder-name').click()
    expect(tiles).to_have_count(1)
    assert page.locator('.media-tree-item').count() < 75
    expect(tree(last)).to_have_attribute('aria-selected','true')
    page.reload(); expect(tree(last)).to_be_visible()
    assert page.locator('.media-tree-item').count() < 75
    page.locator('#media-up').click(); expect(page.locator('.media-folder-card')).to_have_count(12)
    page.locator('#more-media-folders').click(); expect(page.locator('.media-folder-card')).to_have_count(24)
    page.locator('#albums .more-tree-folders').click()
    assert 120 < page.locator('.media-tree-item').count() < 140
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.locator('#toggle-media-folders').click(); expect(page.locator('.media-sidebar')).to_be_visible()
    page.locator('#album-search').fill('2023'); tree(year).locator(':scope > .media-tree-row .media-folder-name').click()
    expect(page.locator('.media-sidebar')).to_be_hidden(); expect(tiles).to_have_count(2)
    page.screenshot(path=str(root/'hierarchy-mobile.png'),full_page=True)
    page.locator('.media-button').first.click(); expect(page.locator('#viewer')).to_be_visible()
    page.locator('#media-back').evaluate('el => el.click()')
    expect(page.locator('#viewer')).to_be_hidden(); expect(page.locator('#album-title')).to_have_text('Many')
    page.set_viewport_size({'width':1440,'height':1100})


def check_on_demand(page,root,allowed):
    import threading
    import time
    from unittest.mock import patch
    from tests.test_serve import demo_case
    from disk_analyzer.serve import BrowseService, CaseServer
    case,image,ident=demo_case(root)
    # The browser test simulates extraction; unit integration separately exercises
    # real icat on a synthetic multipartition disk, including deleted files.
    def extract(service,key,row,volume,sector):
        with service.lock:job=service.jobs[key];job['status']='reading'
        time.sleep(.2);job['path'].write_bytes(image.read_bytes())
        with service.lock:job.update(status='ready',bytes=image.stat().st_size)
    with patch('disk_analyzer.serve.shutil.which',return_value='/fixture/icat'),patch.object(BrowseService,'extract',extract):
        service=BrowseService(case,image)
        try:
            with CaseServer(service,0) as server:
                allowed.append(server.url)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    page.goto(server.url+'media.html')
                    expect(page.locator('#access-note')).to_contain_text('connected')
                    expect(page.locator('.media-tile')).to_have_count(1)
                    expect(page.locator('.tile-meta')).to_contain_text('On image')
                    page.locator('.media-button').click()
                    expect(page.locator('#viewer-media img')).to_be_visible()
                    expect(page.locator('#viewer-caption')).to_contain_text('Read from image')
                    assert page.locator('#viewer-media img').evaluate('el=>el.complete && el.naturalWidth>0')
                    page.locator('#close-viewer').click()
                    page.goto(server.url+'files.html#file='+ident)
                    expect(page.locator('#open-from-image')).to_be_visible()
                    page.locator('#open-from-image').click()
                    expect(page.locator('#detail-content img')).to_be_visible()
                    expect(page.locator('#detail-content')).to_contain_text('Opened from image')
                    page.screenshot(path=str(root/'on-demand.png'),full_page=True)
                finally:server.shutdown();thread.join(5)
        finally:service.close()


def check_video_conversion(page, root, allowed):
    import threading
    from tests.test_serve import video_case
    from disk_analyzer.serve import BrowseService, CaseServer
    case,files=video_case(root); service=BrowseService(case)
    try:
        with CaseServer(service,0) as server:
            allowed.append(server.url)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                page.goto(server.url+'media.html#type=video')
                for f in files:
                    suffix=f['artifact'].rsplit('.',1)[1]
                    def open_preview():
                        page.get_by_role('button',name='Open legacy.'+suffix,exact=True).click()
                        # Some browsers accept this MOV's native codec. Exercise the
                        # explicit conversion action as well as AVI's automatic fallback.
                        if suffix=='mov':
                            if page.locator('#viewer-info').is_hidden():page.locator('#info-media').click()
                            convert=page.get_by_role('button',name='Create playable preview',exact=True)
                            if convert.count():convert.click()
                        expect(page.locator('#viewer-caption')).to_contain_text('Converted MP4 preview',timeout=30000)
                    open_preview()
                    video=page.locator('#viewer-media video')
                    expect(video).to_have_attribute('src','api/video-content/'+f['id'])
                    video.evaluate('async el => { await el.play(); el.currentTime=.5; }')
                    page.wait_for_function('document.querySelector("#viewer-media video").currentTime >= .5')
                    expect(page.locator('#download-media')).to_have_attribute('href',f['artifact'])
                    expect(page.locator('#download-media')).to_have_attribute('download','legacy.'+suffix)
                    response=page.request.get(server.url+'api/video-content/'+f['id'],headers={'Range':'bytes=0-31'})
                    assert response.status==206
                    assert response.headers['content-type']=='video/mp4'
                    assert response.headers['content-disposition'].startswith('inline')
                    assert b'ftyp' in response.body()
                    original=page.request.get(server.url+f['artifact'])
                    assert original.body()==f['payload']
                    page.locator('#close-viewer').click()
                    # Opening it again reuses the completed viewing copy.
                    open_preview()
                    page.locator('#close-viewer').click()
                page.goto((case/'media.html').as_uri()+'#type=video')
                page.get_by_role('button',name='Open legacy.avi',exact=True).click()
                expect(page.locator('#viewer-message')).to_contain_text('cold-digger serve')
                expect(page.locator('#download-media')).to_be_visible()
                page.locator('#close-viewer').click()
            finally:server.shutdown();thread.join(5)
    finally:service.close()
