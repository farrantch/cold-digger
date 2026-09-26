"""Bounded local media previews. No playlist or network inputs are accepted."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import time
import warnings

from .process import terminate

IMAGES = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tif', '.tiff', '.heic', '.heif', '.dng', '.cr2', '.nef'}
VIDEOS = {'.mp4', '.mov', '.avi', '.mkv', '.mpg', '.mpeg', '.m4v', '.webm', '.3gp'}
FORMATS = 'mov,matroska,webm,avi,mpeg,mpegvideo,m4v'


def create_video_preview(source, target, *, max_bytes=512 * 1024**2, timeout=900,
                         stopping=None, progress=None):
    """Create a bounded H.264/AAC MP4 copy, leaving recovered content untouched.

    The caller owns/pins source and target for the entire operation. Failed,
    cancelled and size-limited outputs are removed, never published as playable.
    """
    source, target = Path(source), Path(target)
    if source.resolve() == target.resolve():
        raise ValueError('A video preview must be separate from its original')
    if max_bytes <= 0 or timeout <= 0:
        raise ValueError('Video preview limits must be positive')
    ffmpeg, ffprobe = shutil.which('ffmpeg'), shutil.which('ffprobe')
    if not ffmpeg or not ffprobe:
        raise ValueError('Install FFmpeg and ffprobe to create playable video previews')
    common = ['-v', 'error', '-protocol_whitelist', 'file,pipe', '-format_whitelist', FORMATS]
    process = None
    started = time.monotonic()
    try:
        if stopping and stopping.is_set():
            raise ValueError('Video preview stopped')
        info = subprocess.run([ffprobe, *common, '-select_streams', 'v:0',
                               '-show_entries', 'stream=width,height', '-of', 'json', str(source)],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=min(25, timeout), check=True)
        streams = json.loads(info.stdout).get('streams', [])
        if not streams:
            raise ValueError('No readable video stream was found')
        width, height = streams[0].get('width', 0), streams[0].get('height', 0)
        if width < 2 or height < 2 or width * height > 40_000_000:
            raise ValueError('Video frame dimensions exceed playback preview limits')
        if shutil.disk_usage(target.parent).free < max_bytes + 64 * 1024**2:
            raise ValueError('Not enough temporary disk space for a playable video preview')
        # A separate worker applies RLIMIT_FSIZE safely in this threaded server.
        # Do not use -fs: FFmpeg may report success for a truncated clip.
        argv = [sys.executable, '-m', 'disk_analyzer.browse_worker', str(max_bytes), ffmpeg,
                '-nostdin', '-xerror', *common, '-threads', '2', '-filter_threads', '1',
                '-i', str(source), '-map', '0:v:0', '-map', '0:a:0?', '-sn', '-dn',
                '-map_metadata', '-1', '-map_chapters', '-1',
                '-vf', "scale=w='min(1280,iw)':h='min(720,ih)':force_original_aspect_ratio=decrease:force_divisible_by=2",
                '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '23', '-pix_fmt', 'yuv420p',
                '-threads', '2', '-c:a', 'aac', '-b:a', '128k', '-ac', '2',
                '-movflags', '+faststart', '-f', 'mp4', '-y', str(target)]
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True,
                                   env=dict(os.environ, LC_ALL='C', TZ='UTC'))
        while process.poll() is None:
            if stopping and stopping.is_set():
                raise ValueError('Video preview stopped')
            if time.monotonic() - started > timeout:
                raise ValueError('Video conversion timed out; download the original to play it locally')
            if shutil.disk_usage(target.parent).free < 64 * 1024**2:
                raise ValueError('Not enough temporary disk space for the video preview')
            if progress:
                progress(target.stat().st_size if target.exists() else 0)
            time.sleep(.1)
        length = target.stat().st_size if target.exists() else 0
        if length >= max_bytes:
            raise ValueError('Video preview exceeded the size limit; download the original to play it locally')
        if process.returncode or not length:
            raise ValueError('This video could not be converted. It may be damaged or use an unsupported codec')
        if progress:
            progress(length)
        return {'bytes': length, 'format': 'mp4', 'video_codec': 'h264'}
    except BaseException as exc:
        if process and process.poll() is None:
            terminate(process)
        target.unlink(missing_ok=True)
        if isinstance(exc, (subprocess.SubprocessError, json.JSONDecodeError)):
            raise ValueError('The video could not be read for conversion; it may be damaged or unsupported') from exc
        raise


def create_preview(source, target, kind):
    """Return observed dimensions/duration; raise for unsupported or damaged data."""
    if kind == 'image':
        from PIL import Image, ImageOps
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(source) as original:
                info = {'width': original.width, 'height': original.height, 'format': original.format}
                picture = ImageOps.exif_transpose(original)
                picture.thumbnail((640, 480))
                picture.convert('RGB').save(target, 'JPEG', quality=82)
        return info
    if not shutil.which('ffmpeg') or not shutil.which('ffprobe'):
        raise ValueError('FFmpeg and ffprobe are required for video posters')
    common = ['-v', 'error', '-protocol_whitelist', 'file,pipe', '-format_whitelist', FORMATS]
    result = subprocess.run(['ffprobe', *common, '-show_entries', 'format=duration:stream=width,height,codec_type',
                             '-of', 'json', str(source)], capture_output=True, timeout=25, check=True)
    if len(result.stdout) > 1024**2:
        raise ValueError('Media metadata is too large')
    info = json.loads(result.stdout)
    video = next(s for s in info.get('streams', []) if s.get('codec_type') == 'video')
    width, height = video.get('width', 0), video.get('height', 0)
    if width <= 0 or height <= 0 or width * height > 40_000_000:
        raise ValueError('Video frame dimensions exceed preview limits')
    duration = float(info.get('format', {}).get('duration', 0))
    # Decode a near-start frame, so opening a long clip doesn't scan its duration.
    subprocess.run(['ffmpeg', '-nostdin', *common, '-threads', '1', '-ss', str(min(1, max(0, duration / 4))),
                    '-i', str(source), '-map', '0:v:0', '-frames:v', '1', '-vf', 'scale=640:480:force_original_aspect_ratio=decrease',
                    '-threads', '1', '-f', 'image2', '-y', str(target)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=True)
    return {'width': width, 'height': height, 'duration': duration}
