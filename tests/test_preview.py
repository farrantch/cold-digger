import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

from disk_analyzer.preview import create_preview, create_video_preview


def legacy_video(root, suffix='avi', audio=True):
    target=Path(root)/('legacy.'+suffix)
    command=['ffmpeg','-v','error','-f','lavfi','-i','testsrc2=size=320x240:rate=15:duration=1']
    if audio:
        command+=['-f','lavfi','-i','sine=frequency=440:duration=1']
    command+=['-c:v','mpeg4' if suffix=='avi' else 'mjpeg','-threads','1']
    if audio:
        command+=['-c:a','pcm_s16le']
    subprocess.run(command+[str(target)],check=True)
    return target


@unittest.skipUnless(shutil.which('ffmpeg') and shutil.which('ffprobe'),'FFmpeg required for video posters')
class PreviewTests(unittest.TestCase):
    def test_video_poster_and_metadata_without_mutating_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);video=root/'video.mp4';poster=root/'poster.jpg'
            subprocess.run(['ffmpeg','-v','error','-f','lavfi','-i','color=c=teal:s=320x240:d=1',
                            '-c:v','libx264','-pix_fmt','yuv420p',str(video)],check=True)
            before=video.read_bytes()
            info=create_preview(video,poster,'video')
            self.assertEqual((info['width'],info['height']),(320,240))
            self.assertGreater(info['duration'],0)
            self.assertTrue(poster.read_bytes().startswith(b'\xff\xd8'))
            self.assertEqual(video.read_bytes(),before)

    def test_playlist_disguised_as_video_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'playlist.mp4'
            source.write_text('#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXTINF:1,\nhttp://127.0.0.1:1/not-a-video\n#EXT-X-ENDLIST\n')
            with self.assertRaises(subprocess.CalledProcessError):create_preview(source,root/'poster.jpg','video')
            self.assertFalse((root/'poster.jpg').exists())

    def test_avi_and_mov_become_playable_copies_with_audio_and_seekable_mp4(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for suffix in ('avi','mov'):
                with self.subTest(suffix=suffix):
                    source=legacy_video(root,suffix); before=source.read_bytes(); target=root/(suffix+'.mp4')
                    create_video_preview(source,target)
                    info=json.loads(subprocess.run(['ffprobe','-v','error','-show_entries',
                        'stream=codec_name,codec_type,pix_fmt:format=duration','-of','json',str(target)],
                        capture_output=True,check=True).stdout)
                    self.assertEqual({s['codec_name'] for s in info['streams']},{'h264','aac'})
                    self.assertEqual(info['streams'][0]['pix_fmt'],'yuv420p')
                    self.assertAlmostEqual(float(info['format']['duration']),1,places=1)
                    payload=target.read_bytes()
                    self.assertLess(payload.index(b'moov'),payload.index(b'mdat'))
                    self.assertEqual(source.read_bytes(),before)

    def test_silent_video_and_failed_preview_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=legacy_video(root,audio=False); target=root/'preview.mp4'
            create_video_preview(source,target)
            self.assertTrue(target.is_file()); target.unlink()
            for limits in ({'max_bytes':1024},{'timeout':.001},{'stopping':threading.Event()}):
                if 'stopping' in limits: limits['stopping'].set()
                with self.subTest(limits=limits),self.assertRaises(ValueError):
                    create_video_preview(source,target,**limits)
                self.assertFalse(target.exists())
            source.write_text('#EXTM3U\nhttp://127.0.0.1:1/not-a-video\n')
            with self.assertRaises(ValueError): create_video_preview(source,target)
            self.assertFalse(target.exists())

    def test_preview_cannot_overwrite_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'original.mov'; source.write_bytes(b'original')
            with self.assertRaises(ValueError):create_video_preview(source,source)
            self.assertEqual(source.read_bytes(),b'original')
