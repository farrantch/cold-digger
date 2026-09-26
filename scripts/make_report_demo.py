"""Build a synthetic dashboard case without scanning an image or using real data."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess

from disk_analyzer.content import classify, path_hits
from disk_analyzer.detect import structured_hits
from disk_analyzer.report import write_report
from disk_analyzer.store import Store
from scripts.make_demo import png


def make_report_demo(root, records=2500):
    root=Path(root)
    if root.exists() and any(root.iterdir()):
        raise ValueError("Demo requires an empty directory")
    root.mkdir(parents=True,exist_ok=True)
    store=Store(root)
    def add(path,state="allocated",payload=None,suffix=".bin"):
        ident="E"+hashlib.sha256((state+path).encode()).hexdigest()[:20]
        category,priority=classify(path,state)
        store.file({"id":ident,"volume":"p1" if state!="unknown" else None,"inode":ident,"path":path,
                    "size":len(payload) if payload is not None else 8192,"deleted":state,"category":category,"priority":priority,
                    "metadata":json.dumps({"mode":"r/rrw-r--r--"})})
        artifact=None
        if payload is not None:
            digest=hashlib.sha256(payload).hexdigest();artifact="artifacts/"+digest+suffix
            (root/artifact).write_bytes(payload)
            store.file_status(ident,"exported",artifact=artifact,sha256=digest)
        return ident,artifact
    try:
        store.put("version","0.1.0");store.put("status","interrupted")
        store.put("image",{"path":"Synthetic demonstration / no source disk","hash_mode":"quick","sha256":None})
        store.put("layout",{"scheme":"demo","sector_size":512,"gaps":[]})
        store.volume({"id":"p1","name":"Example Windows volume","start":32256,"length":100000000,
                      "signature":"ntfs","filesystem":"ntfs","filesystem_status":"complete"})
        for stage in ("identity","layout","raw","filesystem"):
            store.stage(stage,"complete","Synthetic fixture only")
        store.stage("carving","pending","Example scan still has work to do")
        for i in range(records):
            add(f"/Documents/Archive/document-{i:05d}.txt","deleted" if i%3==0 else "allocated")
        add('/Documents/<img src=x onerror=alert(1)>.txt',"deleted")
        for i in range(56):
            add(f"/Pictures/Album/Photo-{i:03d}.png","deleted" if i%2 else "allocated",png(),".png")
        add("f00001.png","unknown",png(),".png")
        for i in range(97):
            path=f"/System/Help/history-{i}.dat"
            for hit in path_hits(path):store.finding(hit,{"method":"filesystem-path","path":path,"deleted":"allocated"})
        wallet={"version":3,"address":"7e5f4552091a69125d5dfcb7b8c2659029395bdf","crypto":{
                "cipher":"aes-128-ctr","ciphertext":"11"*32,"mac":"22"*32,"cipherparams":{"iv":"33"*16},
                "kdf":"scrypt","kdfparams":{"salt":"44"*32,"dklen":32,"n":16384,"r":8,"p":1}}}
        payload=json.dumps(wallet).encode();ident,artifact=add("/Documents/wallet.json","deleted",payload,".json")
        for hit in structured_hits(payload):
            store.finding(hit,{"method":"filesystem-content","file_id":ident,"artifact":artifact,"path":"/Documents/wallet.json","file_offset":0,"length":len(payload),"deleted":"deleted"})
        if shutil.which("ffmpeg"):
            video=root/"private"/"synthetic-video.mp4"
            subprocess.run(["ffmpeg","-v","error","-f","lavfi","-i","color=c=teal:s=320x240:d=1","-c:v","libx264","-pix_fmt","yuv420p","-movflags","+faststart",str(video)],check=True)
            add("/Videos/Synthetic clip.mp4","deleted",video.read_bytes(),".mp4")
        write_report(store)
    finally:store.close()
    return root/"report.html"


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("output",type=Path)
    print(make_report_demo(parser.parse_args().output))
