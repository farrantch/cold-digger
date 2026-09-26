"""Loopback case browser with lazy, read-only filesystem extraction and byte ranges."""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import mimetypes
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote, unquote, urlsplit

from .dashboard import safe_asset
from .identity import metadata_matches, stat_identity, verify_image
from .preview import create_preview, create_video_preview, IMAGES, VIDEOS
from .process import terminate
from .report import clean


class BrowseService:
    def __init__(self, root, image=None, *, max_file_bytes=4 * 1024**3, cache_bytes=8 * 1024**3, timeout=900):
        self.root = Path(root).resolve()
        if max_file_bytes <= 0 or cache_bytes < max_file_bytes or timeout <= 0:
            raise ValueError('Cache size must cover the positive per-file limit; timeout must be positive')
        self.max_file_bytes, self.cache_bytes, self.timeout = max_file_bytes, cache_bytes, timeout
        self.image = Path(image).resolve(strict=True) if image else None
        self.identity = None
        if self.image:
            if not self.image.is_file() or not self.image.stat().st_size:
                raise ValueError('The source image must be a nonempty regular file')
            previous = self.meta('image')
            if not previous or not all(key in previous for key in ('size', 'mtime_ns')):
                raise ValueError('The case has no saved image identity; cannot read from this image')
            self.identity = verify_image(self.image, self.image.stat(), previous, 'quick')
            if not shutil.which('icat'):
                raise ValueError('Install sleuthkit (icat) to read files from the image')
        self.lock = threading.RLock()
        self.jobs = OrderedDict()
        self.video_jobs = OrderedDict()
        self.stopping = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='image-read')
        self.video_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='video-preview')
        cache_parent = (self.root / 'private').resolve(strict=True)
        if self.root not in cache_parent.parents:
            raise ValueError('The private cache directory must be inside the case')
        self.temp = tempfile.TemporaryDirectory(prefix='browser-cache-', dir=cache_parent)
        self.cache = Path(self.temp.name)
        self.preview_lock = threading.Lock()
        self.previews = OrderedDict()

    @contextmanager
    def connect(self):
        db = sqlite3.connect((self.root / 'case.sqlite').as_uri() + '?mode=ro', uri=True)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def meta(self, key):
        with self.connect() as db:
            row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
            return json.loads(row[0]) if row else None

    def file(self, ident):
        if not re.fullmatch(r'E[0-9a-f]{20}', ident):
            raise ValueError('Unknown file ID')
        with self.connect() as db:
            row = db.execute('SELECT * FROM files WHERE id=?', (ident,)).fetchone()
            if not row:
                raise ValueError('Unknown file ID')
            return dict(row)

    def asset(self, relative):
        if not safe_asset(relative):
            raise ValueError('Invalid asset')
        path = (self.root / relative).resolve(strict=True)
        if self.root not in path.parents or not path.is_file():
            raise ValueError('Asset unavailable')
        return path

    def check_image(self):
        if not self.image:
            raise ValueError('Start serve with --image to read this file on demand')
        if not metadata_matches(self.identity, stat_identity(self.image.stat())):
            raise ValueError('Source image metadata changed; stop the browser and check the image')

    def reserve_cache(self, reserve):
        """Called under lock; reads and converted videos share one byte budget."""
        caches = (self.video_jobs, self.jobs)
        while sum(j['reserved'] for cache in caches for j in cache.values()) + reserve > self.cache_bytes:
            for cache in caches:
                victim = next((key for key, j in cache.items()
                               if j['status'] in ('ready', 'error') and not j['readers']), None)
                if victim is not None:
                    old = cache.pop(victim); old['path'].unlink(missing_ok=True)
                    break
            else:
                raise ValueError('The preview cache is busy; close a video and retry, or increase --cache-bytes')

    def request(self, ident):
        row = self.file(ident)
        if row['artifact']:
            try:
                self.asset(row['artifact'])
                return {'status': 'ready', 'partial': row['status'] == 'partial', 'source': 'export', 'bytes': self.asset(row['artifact']).stat().st_size}
            except (ValueError, OSError):
                pass
        self.check_image()
        mode = json.loads(row['metadata']).get('mode', '')
        if not re.fullmatch(r'\d+(?:-\d+){0,2}', row['inode'] or '') or not mode.startswith(('r', '-')):
            raise ValueError('No readable filesystem record; carving alone cannot reconstruct this file')
        if not 0 <= row['size'] <= self.max_file_bytes:
            raise ValueError('This file exceeds the on-demand per-file limit; increase --max-file-bytes')
        with self.connect() as db:
            volume = db.execute('SELECT data FROM volumes WHERE id=?', (row['volume'],)).fetchone()
        if not volume:
            raise ValueError('The original partition is not mapped')
        volume = json.loads(volume[0]); sector = (self.meta('layout') or {}).get('sector_size')
        if sector not in (512, 4096) or not isinstance(volume.get('start'), int) or volume['start'] < 0 or volume['start'] % sector:
            raise ValueError('The partition offset or sector size is not usable')
        if volume['start'] >= self.identity['size']:
            raise ValueError('Partition offset is outside the source image')
        with self.lock:
            if ident in self.jobs and self.jobs[ident]['status'] != 'error':
                self.jobs.move_to_end(ident)
                return self.status(ident)
            if sum(j['status'] in ('queued', 'reading') for j in self.jobs.values()) >= 8:
                raise ValueError('Several files are already opening; wait for one to finish')
            reserve = max(1, min(self.max_file_bytes, row['size'] + 1))
            self.reserve_cache(reserve)
            self.jobs[ident] = {'status': 'queued', 'reserved': reserve, 'path': self.cache / ident,
                                'readers': 0, 'bytes': 0, 'partial': False, 'source': 'image'}
            self.pool.submit(self.extract, ident, row, volume, sector)
            return self.status(ident)

    def extract(self, ident, row, volume, sector):
        with self.lock:
            job = self.jobs[ident]; job['status'] = 'reading'
        process = None
        try:
            self.check_image()
            if shutil.disk_usage(self.cache).free < job['reserved'] + 64 * 1024**2:
                raise ValueError('Not enough temporary disk space to open this file')
            argv = [shutil.which('icat'), '-b', str(sector), '-o', str(volume['start'] // sector), '-i', 'raw']
            if row['deleted'] != 'allocated':
                argv.append('-r')
            argv.extend([str(self.image), row['inode']])
            with job['path'].open('wb') as output:
                process = subprocess.Popen([sys.executable, '-m', 'disk_analyzer.browse_worker', str(job['reserved']), *argv],
                                           stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                           start_new_session=True, env=dict(os.environ, LC_ALL='C', TZ='UTC'))
                started = time.monotonic()
                while process.poll() is None:
                    with self.lock:
                        job['bytes'] = job['path'].stat().st_size
                    if self.stopping.wait(.1) or time.monotonic() - started > self.timeout:
                        terminate(process)
                        raise ValueError('File read stopped or timed out; retry with a larger --read-timeout if needed')
            self.check_image()
            length = job['path'].stat().st_size
            if not length and (row['size'] or process.returncode):
                raise ValueError('Sleuth Kit could not read this record. Deleted data may have been overwritten')
            with self.lock:
                job.update(status='ready', bytes=length, reserved=length,
                           partial=bool(process.returncode or length != row['size']))
        except Exception as exc:
            if process and process.poll() is None:
                terminate(process)
            with self.lock:
                job['path'].unlink(missing_ok=True)
                job.update(status='error', reserved=0, error=str(exc) if isinstance(exc, ValueError) else 'The file could not be read from this image')

    def status(self, ident):
        with self.lock:
            job = self.jobs.get(ident)
            if not job:
                return {'status': 'missing'}
            return {key: value for key, value in job.items() if key in ('status', 'bytes', 'partial', 'source', 'error')}

    @contextmanager
    def content(self, ident):
        row = self.file(ident)
        if row['artifact']:
            try:
                path = self.asset(row['artifact'])
            except (ValueError, OSError):
                path = None
            if path:
                with path.open('rb') as stream:
                    yield stream, row
                return
        self.check_image()
        with self.lock:
            job = self.jobs.get(ident)
            if not job or job['status'] != 'ready':
                raise ValueError('Open the file first; its temporary cache may have expired')
            job['readers'] += 1; self.jobs.move_to_end(ident)
        try:
            with job['path'].open('rb') as stream:
                yield stream, row
        finally:
            with self.lock:
                job['readers'] -= 1

    def thumbnail(self, ident):
        row = self.file(ident)
        thumb = f'thumbnails/{ident}.jpg'
        try:
            return self.asset(thumb).read_bytes()
        except (OSError, ValueError):
            pass
        # The grid may preview an export/cache; it never triggers image extraction.
        with self.preview_lock:
            if ident in self.previews:
                self.previews.move_to_end(ident)
                return self.previews[ident]
            suffix = Path(row['path']).suffix.lower()
            if suffix not in IMAGES | VIDEOS:
                raise ValueError('No preview for this file type')
            target = self.cache / 'poster.jpg'
            try:
                with self.content(ident) as (stream, _):
                    # /proc/self/fd is not inherited into FFmpeg; the cache/export path
                    # remains pinned by content() for the duration of this operation.
                    source = Path(stream.name)
                    create_preview(source, target, 'video' if suffix in VIDEOS else 'image')
                data = target.read_bytes()
                if len(data) > 2 * 1024**2:
                    raise ValueError('Preview too large')
                self.previews[ident] = data
                while len(self.previews) > 128:
                    self.previews.popitem(last=False)
                return data
            except Exception as exc:
                raise ValueError('Preview unavailable; open or download the original') from exc
            finally:
                target.unlink(missing_ok=True)

    def request_video(self, ident):
        row = self.file(ident)
        if Path(row['path']).suffix.lower() not in VIDEOS and Path(row['artifact'] or '').suffix.lower() not in VIDEOS:
            raise ValueError('This entry is not a supported video file')
        if not shutil.which('ffmpeg') or not shutil.which('ffprobe'):
            raise ValueError('Install FFmpeg and ffprobe to create playable video previews')
        pinned = None
        try:
            with self.lock:
                if self.stopping.is_set():
                    raise ValueError('The local browser is stopping')
                if ident in self.video_jobs and self.video_jobs[ident]['status'] != 'error':
                    self.video_jobs.move_to_end(ident)
                    return self.video_status(ident)
                if sum(j['status'] in ('queued', 'converting') for j in self.video_jobs.values()) >= 4:
                    raise ValueError('Several videos are already converting; wait for one to finish')
                # Hold the source open and pin any extraction cache through queueing
                # and conversion, so cache eviction cannot remove the input.
                pinned = self.content(ident)
                stream, source_row = pinned.__enter__()
                if os.fstat(stream.fileno()).st_size > self.max_file_bytes:
                    raise ValueError('This video exceeds --max-file-bytes; download the original to play it locally')
                limit = min(512 * 1024**2, self.max_file_bytes)
                self.reserve_cache(limit)
                self.video_jobs[ident] = {'status':'queued', 'reserved':limit,
                    'path':self.cache / ('video-' + ident + '.mp4'), 'readers':0, 'bytes':0,
                    'partial':source_row['status'] == 'partial' or bool(self.jobs.get(ident, {}).get('partial')),
                    'source':'preview'}
                self.video_pool.submit(self.convert_video, ident, Path(stream.name), pinned, limit)
                pinned = None  # The worker now owns the context, including its file handle.
                return self.video_status(ident)
        finally:
            if pinned:
                pinned.__exit__(None, None, None)

    def convert_video(self, ident, source, pinned, limit):
        with self.lock:
            job = self.video_jobs[ident]; job['status'] = 'converting'
        def progress(length):
            with self.lock:
                job['bytes'] = length
        try:
            create_video_preview(source, job['path'], max_bytes=limit, timeout=self.timeout,
                                 stopping=self.stopping, progress=progress)
            with self.lock:
                length = job['path'].stat().st_size
                job.update(status='ready', bytes=length, reserved=length)
        except Exception as exc:
            with self.lock:
                job['path'].unlink(missing_ok=True)
                job.update(status='error', reserved=0,
                           error=str(exc) if isinstance(exc, ValueError) else 'The video preview could not be created')
        finally:
            pinned.__exit__(None, None, None)

    def video_status(self, ident):
        self.file(ident)
        with self.lock:
            job = self.video_jobs.get(ident)
            return {key:value for key,value in job.items()
                    if key in ('status','bytes','partial','source','error')} if job else {'status':'missing'}

    @contextmanager
    def video_content(self, ident):
        row = self.file(ident)
        with self.lock:
            job = self.video_jobs.get(ident)
            if not job or job['status'] != 'ready':
                raise ValueError('Create the video preview first; its temporary cache may have expired')
            job['readers'] += 1; self.video_jobs.move_to_end(ident)
        try:
            with job['path'].open('rb') as stream:
                yield stream, row
        finally:
            with self.lock:
                job['readers'] -= 1

    def close(self):
        self.stopping.set()
        # Drain queued video jobs so every pinned source context is released.
        self.video_pool.shutdown(wait=True)
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.temp.cleanup()


def byte_range(value, length):
    if value is None:
        return 0, length - 1, False
    match = re.fullmatch(r'bytes=(\d*)-(\d*)', value)
    if not match or not any(match.groups()) or length == 0:
        raise ValueError('Invalid range')
    first, last = match.groups()
    if not first:
        if int(last) <= 0:
            raise ValueError('Invalid range')
        start, end = max(0, length - int(last)), length - 1
    else:
        start, end = int(first), min(int(last), length - 1) if last else length - 1
    if start >= length or end < start:
        raise ValueError('Range outside file')
    return start, end, True


PAGES = {'report.html', 'files.html', 'media.html', 'crypto.html', 'evidence.html', 'details.html',
         'browser-history.html', 'browser-history.json', 'findings.json', 'inventory.csv'}
INLINE = {'.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp',
          '.bmp': 'image/bmp', '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.mov': 'video/quicktime', '.webm': 'video/webm',
          '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg', '.wav': 'audio/wav'}


class CaseServer(ThreadingHTTPServer):
    daemon_threads = False
    def __init__(self, service, port=8765):
        self.service = service
        self.token = secrets.token_urlsafe(32)
        super().__init__(('127.0.0.1', port), Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'
        self.url = f'{self.origin}/{self.token}/'


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    # Suppress request paths: they contain the per-session access token.
    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; media-src 'self' data:; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        super().end_headers()

    def route(self):
        if self.headers.get('Host') != urlsplit(self.server.origin).netloc:
            raise ValueError('Invalid host')
        if self.headers.get('Origin') not in (None, self.server.origin) or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            raise ValueError('Cross-origin requests are not allowed')
        path = unquote(urlsplit(self.path).path)
        prefix = '/' + self.server.token + '/'
        if not path.startswith(prefix):
            raise ValueError('Use the private URL printed by serve')
        relative = path[len(prefix):]
        if '\\' in relative or any(p in ('.', '..') for p in relative.split('/')):
            raise ValueError('Invalid path')
        return relative or 'media.html'

    def json(self, value, code=200):
        data = json.dumps(value).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(data))); self.end_headers()
        if self.command != 'HEAD':
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_POST(self):
        try:
            path = self.route()
            if not path.startswith(('api/open/', 'api/video/')) or self.headers.get('X-Disk-Analyzer') != 'open':
                raise ValueError('Invalid open request')
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Length', '0') != '0':
                raise ValueError('Request body not accepted')
            if path.startswith('api/video/'):
                self.json(self.server.service.request_video(path.removeprefix('api/video/')))
            else:
                self.json(self.server.service.request(path.removeprefix('api/open/')))
        except (ValueError, OSError) as exc:
            self.json({'error': str(exc) if isinstance(exc, ValueError) else 'File unavailable'}, 400)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        try:
            relative = self.route(); service = self.server.service
            if relative == 'api/session':
                self.json({'enabled': True, 'image': bool(service.image), 'max_file_bytes': service.max_file_bytes,
                           'video_previews':bool(shutil.which('ffmpeg') and shutil.which('ffprobe'))}); return
            if relative.startswith('api/video-status/'):
                self.json(service.video_status(relative.removeprefix('api/video-status/'))); return
            if relative.startswith('api/video-content/'):
                ident = relative.removeprefix('api/video-content/')
                with service.video_content(ident) as (stream, row):
                    name = clean(Path(row['path'].replace('\\', '/')).stem) + '-preview.mp4'
                    self.send_stream(stream, name, recovered=True)
                return
            if relative.startswith('api/status/'):
                ident = relative.removeprefix('api/status/'); service.file(ident)
                self.json(service.status(ident)); return
            if relative.startswith('api/content/'):
                ident = relative.removeprefix('api/content/')
                with service.content(ident) as (stream, row):
                    name = clean(row['path'].replace('\\', '/').split('/')[-1])
                    self.send_stream(stream, name, recovered=True)
                return
            if relative.startswith('api/thumbnail/'):
                data = service.thumbnail(relative.removeprefix('api/thumbnail/'))
                self.send_response(200); self.send_header('Content-Type', 'image/jpeg'); self.send_header('Content-Length', str(len(data))); self.end_headers()
                if self.command != 'HEAD': self.wfile.write(data)
                return
            asset = safe_asset(relative)
            if not (relative in PAGES or re.fullmatch(r'dashboard-data/[a-z0-9-]+\.js', relative) or asset):
                raise ValueError('File is not part of this dashboard')
            path = (service.root / relative).resolve(strict=True)
            if service.root not in path.parents or not path.is_file():
                raise ValueError('File unavailable')
            with path.open('rb') as stream:
                self.send_stream(stream, path.name, recovered=relative.startswith('artifacts/'))
        except (ValueError, OSError) as exc:
            if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
                return
            self.json({'error': str(exc) if isinstance(exc, ValueError) else 'File unavailable'}, 404)

    def send_stream(self, stream, name, *, recovered=False):
        length = os.fstat(stream.fileno()).st_size
        try:
            start, end, partial = byte_range(self.headers.get('Range'), length)
        except ValueError:
            self.send_response(416); self.send_header('Content-Range', f'bytes */{length}'); self.send_header('Content-Length', '0'); self.end_headers(); return
        suffix = Path(name).suffix.lower()
        content_type = INLINE.get(suffix, 'application/octet-stream') if recovered else (mimetypes.guess_type(name)[0] or 'application/octet-stream')
        self.send_response(206 if partial else 200)
        self.send_header('Content-Type', content_type); self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Length', str(max(0, end - start + 1)))
        if partial: self.send_header('Content-Range', f'bytes {start}-{end}/{length}')
        if recovered:
            attachment = suffix not in INLINE or 'download' in urlsplit(self.path).query
            self.send_header('Content-Disposition', ('attachment' if attachment else 'inline') + "; filename*=UTF-8''" + quote(name, safe=''))
        self.end_headers()
        if self.command == 'HEAD': return
        stream.seek(start); remaining = end - start + 1
        while remaining > 0:
            data = stream.read(min(1024**2, remaining))
            if not data: break
            self.wfile.write(data); remaining -= len(data)
