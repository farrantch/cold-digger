import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from disk_analyzer.serve import BrowseService, CaseServer, byte_range
from disk_analyzer.store import Store
from disk_analyzer.identity import stat_identity
from disk_analyzer.pipeline import DEFAULTS, inventory
from disk_analyzer.layout import discover
from disk_analyzer.report import write_report
from scripts.make_demo import make_demo, png


def demo_case(root):
    image = root / 'source.img'; image.write_bytes(png())
    case = root / 'case'; case.mkdir(); store = Store(case)
    store.put('image', dict(stat_identity(image.stat()), path=str(image)))
    store.put('layout', {'sector_size':512})
    store.volume({'id':'p1','start':0,'length':image.stat().st_size,'signature':'test','filesystem_status':'complete'})
    ident = 'E' + 'a'*20
    store.file({'id':ident,'volume':'p1','inode':'12','path':'/photo.png','size':image.stat().st_size,
                'deleted':'deleted','category':'media','priority':2,'metadata':json.dumps({'mode':'r/rrw-r--r--'})})
    write_report(store); store.close()
    return case, image, ident


def video_case(root):
    from tests.test_preview import legacy_video
    case,image,_=demo_case(root); store=Store(case); files=[]
    try:
        for number,suffix in enumerate(('avi','mov')):
            source=legacy_video(root,suffix); payload=source.read_bytes(); digest=hashlib.sha256(payload).hexdigest()
            ident='E'+str(number+1)*20; artifact='artifacts/'+digest+'.'+suffix
            (case/artifact).write_bytes(payload)
            store.file({'id':ident,'volume':'p1','inode':'42','path':'/Clips/legacy.'+suffix,
                        'size':len(payload),'deleted':'deleted','category':'media','priority':2,
                        'metadata':json.dumps({'mode':'r/rrw-r--r--'})})
            store.file_status(ident,'exported',artifact=artifact,sha256=digest)
            files.append({'id':ident,'artifact':artifact,'payload':payload})
        write_report(store)
    finally:store.close()
    return case,files


class ServeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'),'FFmpeg required')
    def test_video_conversion_shares_cache_and_preserves_original_downloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            case,files=video_case(Path(tmp)); service=BrowseService(case,max_file_bytes=1024**2,cache_bytes=1024**2)
            try:
                first=files[0]['id']; service.request_video(first)
                until=time.monotonic()+15
                while service.video_status(first)['status'] in ('queued','converting') and time.monotonic()<until:time.sleep(.05)
                self.assertEqual(service.video_status(first)['status'],'ready',service.video_status(first))
                with service.video_content(first) as (stream,row):
                    self.assertIn(b'ftyp',stream.read(32)); self.assertEqual(row['status'],'exported')
                    with self.assertRaisesRegex(ValueError,'cache is busy'):service.request_video(files[1]['id'])
                # The next conversion can now evict the unpinned viewing copy.
                service.request_video(files[1]['id'])
                self.assertEqual(service.video_status(first)['status'],'missing')
                for f in files:
                    self.assertEqual((case/f['artifact']).read_bytes(),f['payload'])
                with service.content(first) as (stream,_):self.assertEqual(stream.read(),files[0]['payload'])
            finally:service.close()
            self.assertFalse(service.cache.exists())

    def test_conversion_pins_on_demand_source_and_coalesces_duplicate_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            case,_,ident=demo_case(Path(tmp)); store=Store(case)
            store.db.execute("UPDATE files SET path='/clip.avi' WHERE id=?",(ident,)); store.close()
            service=BrowseService(case,max_file_bytes=1024,cache_bytes=1500)
            path=service.cache/ident; path.write_bytes(b'cached video')
            service.jobs[ident]={'status':'ready','path':path,'reserved':12,'bytes':12,'readers':0,'partial':True,'source':'image'}
            started=threading.Event(); finish=threading.Event()
            def convert(source,target,**kwargs):
                started.set(); finish.wait(5); self.assertTrue(source.is_file());target.write_bytes(b'preview')
            try:
                with patch.object(service,'check_image'),patch('disk_analyzer.serve.shutil.which',return_value='/fixture/tool'), \
                     patch('disk_analyzer.serve.create_video_preview',side_effect=convert) as conversion:
                    service.request_video(ident); self.assertTrue(started.wait(5))
                    service.request_video(ident)
                    self.assertEqual(service.jobs[ident]['readers'],1)
                    with service.lock,self.assertRaisesRegex(ValueError,'cache is busy'):service.reserve_cache(1000)
                    finish.set()
                    until=time.monotonic()+5
                    while service.video_status(ident)['status']!='ready' and time.monotonic()<until:time.sleep(.02)
                    self.assertEqual(service.video_status(ident)['status'],'ready')
                    self.assertTrue(service.video_status(ident)['partial'])
                    self.assertEqual(conversion.call_count,1)
            finally:
                finish.set(); service.close()

    def test_ranges_are_bounded_and_support_seek_and_suffix_requests(self):
        self.assertEqual(byte_range(None, 8), (0,7,False))
        self.assertEqual(byte_range('bytes=2-5', 8), (2,5,True))
        self.assertEqual(byte_range('bytes=5-', 8), (5,7,True))
        self.assertEqual(byte_range('bytes=-3', 8), (5,7,True))
        self.assertEqual(byte_range('bytes=0-999', 8), (0,7,True))
        for value in ('bytes=8-', 'bytes=3-1', 'bytes=-0', 'bytes=0-1,4-5', 'garbage'):
            with self.assertRaises(ValueError): byte_range(value,8)
        with self.assertRaises(ValueError): byte_range('bytes=0-',0)

    def test_http_export_ranges_and_private_path_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            case,image,ident = demo_case(Path(tmp))
            payload=b'<html>Recovered active content</html>'; digest=hashlib.sha256(payload).hexdigest()
            store=Store(case); relative='artifacts/'+digest+'.html'; (case/relative).write_bytes(payload)
            store.file_status(ident,'exported',artifact=relative,sha256=digest); store.close()
            service=BrowseService(case)
            try:
                with CaseServer(service,0) as server:
                    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                    try:
                        def get(path,headers=None,method='GET'):
                            return urlopen(Request(server.url+path,headers=headers or {},method=method),timeout=10)
                        with get(relative,{'Range':'bytes=2-7'}) as response:
                            self.assertEqual(response.status,206); self.assertEqual(response.read(),payload[2:8])
                            self.assertEqual(response.headers['Content-Type'],'application/octet-stream')
                            self.assertTrue(response.headers['Content-Disposition'].startswith('attachment'))
                            self.assertEqual(response.headers['Content-Range'],f'bytes 2-7/{len(payload)}')
                            self.assertIsNone(response.headers.get('Access-Control-Allow-Origin'))
                        with get(relative,method='HEAD') as response:
                            self.assertEqual(response.read(),b'');self.assertEqual(int(response.headers['Content-Length']),len(payload))
                        for path in ('case.sqlite','private/anything','logs/a','../case.sqlite','%2e%2e/case.sqlite','dashboard-data/../../case.sqlite'):
                            with self.assertRaises(HTTPError):get(path)
                        for headers in ({'Origin':'https://example.org'},{'Host':'attacker.example'},{'Sec-Fetch-Site':'cross-site'}):
                            with self.assertRaises(HTTPError):get('api/session',headers)
                        with self.assertRaises(HTTPError):urlopen(server.origin+'/media.html')
                        with self.assertRaises(HTTPError):get('api/open/'+ident,method='POST')
                        with get('api/open/'+ident,{'X-Disk-Analyzer':'open'},'POST') as response:
                            self.assertEqual(json.load(response)['status'],'ready')
                        with get(relative,{'Range':'bytes=9999-'}) as response: self.fail('Invalid range accepted')
                    except HTTPError as exc:
                        self.assertEqual(exc.code,416)
                    finally:
                        server.shutdown();thread.join(5)
            finally:service.close()

    def test_missing_source_invalid_record_and_changed_identity_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            case,image,ident=demo_case(Path(tmp)); service=BrowseService(case)
            try:
                with self.assertRaisesRegex(ValueError,'--image'):service.request(ident)
                with self.assertRaises(ValueError):service.file('../../private')
                with self.assertRaises(ValueError):service.asset('https://example.org/secret')
            finally:service.close()
            with patch('disk_analyzer.serve.shutil.which',return_value='/test/icat'):
                service=BrowseService(case,image,max_file_bytes=1,cache_bytes=1)
                try:
                    with self.assertRaisesRegex(ValueError,'per-file limit'):service.request(ident)
                    image.write_bytes(b'changed')
                    with self.assertRaisesRegex(ValueError,'metadata changed'):service.request(ident)
                finally:service.close()
                with self.assertRaisesRegex(ValueError,'metadata changed'):BrowseService(case,image)

    @unittest.skipUnless(all(shutil.which(x) for x in ('icat','fls','fsstat','mkfs.ext2','debugfs')), 'Requires real Sleuth Kit and ext2 tools')
    def test_real_on_demand_deleted_files_on_both_partitions_without_scan_or_export_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);image=make_demo(root);case=root/'case';case.mkdir()
            before=hashlib.sha256(image.read_bytes()).hexdigest()
            store=Store(case);store.put('image',dict(stat_identity(image.stat()),path=str(image)))
            layout=discover(image);store.put('layout',layout)
            for volume in layout['volumes']:store.volume(volume)
            with patch('disk_analyzer.pipeline.recover_files', side_effect=lambda *args: None):
                inventory(store,image,DEFAULTS,layout)
            rows=[dict(r) for r in store.db.execute("SELECT * FROM files WHERE path IN ('/photo.png','/deleted-key.txt','/forgotten.payload')")]
            self.assertEqual(len(rows),4)
            stages=store.db.execute('SELECT count(*) FROM stages').fetchone()[0];store.close()
            service=BrowseService(case,image)
            cache=service.cache
            try:
                for row in rows:
                    service.request(row['id'])
                    until=time.monotonic()+15
                    while service.status(row['id'])['status'] in ('queued','reading') and time.monotonic()<until:time.sleep(.05)
                    self.assertEqual(service.status(row['id'])['status'],'ready',service.status(row['id']))
                    self.assertFalse(service.status(row['id'])['partial'])
                    with service.content(row['id']) as (stream,_):
                        self.assertEqual(stream.read(),(root/row['path'].lstrip('/')).read_bytes())
                with sqlite3.connect(case/'case.sqlite') as db:
                    self.assertEqual(db.execute('SELECT count(*) FROM files WHERE artifact IS NOT NULL').fetchone()[0],0)
                    self.assertEqual(db.execute('SELECT count(*) FROM stages').fetchone()[0],stages)
                self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),before)
                self.assertEqual(list((case/'artifacts').iterdir()),[])
            finally:service.close()
            self.assertFalse(cache.exists())
