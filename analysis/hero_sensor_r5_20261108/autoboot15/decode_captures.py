"""Restore exact log bytes from R5AUTO KVM screenshots; never execute QR contents."""
from pathlib import Path
import argparse,hashlib,json,re,sys,zlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
PATTERN=re.compile(rb'HERO-R5AUTO-QR1\nT=([0-9]{1,6});C=([0-9A-F]{8});P=([0-9]{1,3})/([0-9]{1,3});O=([0-9]{1,6});N=([0-9]{1,3});D=([0-9A-F]{8})\n\n')
CHUNK=512
def parse_frame(raw):
    m=PATTERN.match(raw)
    if not m:raise ValueError('Not a R5AUTO KVM frame')
    t,c,p,pages,off,n,d=m.groups();t,p,pages,off,n=map(int,(t,p,pages,off,n));c=int(c,16);d=int(d,16)
    data=raw[m.end():]
    if not (1<=t<=262144 and pages==(t+CHUNK-1)//CHUNK and 1<=p<=pages and
            off==(p-1)*CHUNK and n==min(CHUNK,t-off) and len(data)==n):raise ValueError('Invalid frame bounds or length')
    if zlib.crc32(data)!=d:raise ValueError('Page CRC mismatch')
    return {'total':t,'crc':c,'page':p,'pages':pages,'offset':off,'data':data}
def assemble(raw_frames,require_snapshot=True):
    frames=[parse_frame(raw) for raw in raw_frames]
    if not frames:raise ValueError('No frames')
    first=frames[0];key=(first['total'],first['crc']);parts={}
    for f in frames:
        if (f['total'],f['crc'])!=key:raise ValueError('Mixed captures: different log sessions')
        p=f['page']
        if p in parts and parts[p]!=f['data']:raise ValueError('Conflicting duplicate page')
        parts[p]=f['data']
    missing=sorted(set(range(1,first['pages']+1))-parts.keys())
    if missing:raise ValueError('Missing pages: '+', '.join(map(str,missing)))
    data=b''.join(parts[p] for p in sorted(parts))
    if len(data)!=first['total'] or zlib.crc32(data)!=first['crc']:raise ValueError('Whole log length/CRC mismatch')
    complete=(data.startswith(b'HERO-R5AUTO-SUMMARY\r\nRUN=') and data.endswith(b'END SUMMARY - full raw TX/RX available with A/V/F\r\n')) or (data.startswith(b'HERO-R5AUTO-FULL\r\nRUN=') and data.endswith((b'END FULL AUDIT\r\n',b'END PREFLIGHT - NO CORE LOADED / NO KCS OR CONFIGURATION WRITES\r\n')))
    if require_snapshot and not complete:
        raise ValueError('Not a complete R5AUTO snapshot')
    return data,{'pages':first['pages'],'bytes':len(data),'crc32':f'{first["crc"]:08X}','sha256':hashlib.sha256(data).hexdigest()}
def read_image(path):
    from PIL import Image
    import zxingcpp
    with Image.open(path) as img:
        if img.width*img.height>32_000_000:raise ValueError('Image is too large')
        results=zxingcpp.read_barcodes(img.convert('RGB'),formats=zxingcpp.BarcodeFormat.QRCode)
    found=[bytes(r.bytes) for r in results if bytes(r.bytes).startswith(b'HERO-R5AUTO-QR1\n')]
    if len(found)!=1:raise ValueError(f'{path}: expected one R5AUTO QR code, found {len(found)}')
    parse_frame(found[0]);return found[0]
def main():
    p=argparse.ArgumentParser();p.add_argument('screenshots',nargs='+');p.add_argument('--output',required=True);a=p.parse_args()
    files=[]
    for value in a.screenshots:
        path=Path(value)
        files+=sorted(path.glob('*.png')) if path.is_dir() else [path]
    data,meta=assemble([read_image(path) for path in files]);dest=Path(a.output)
    if dest.exists():
        if dest.read_bytes()!=data:raise FileExistsError('Refusing to overwrite '+str(dest))
    else:
        dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('xb') as f:f.write(data)
    print(json.dumps({'output':str(dest),**meta},indent=2))
if __name__=='__main__':main()
