"""Independently decode already captured .15 PNGs and match complete raw logs."""
from pathlib import Path
import hashlib,json,re,sys,zlib
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;LIVE=HERE.parent;ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from PIL import Image
import zxingcpp
FRAME=re.compile(rb'(HERO-P6-HOST15-S22-QR1|HERO-R5AUTO-QR1)\nT=([0-9]{1,7});C=([0-9A-F]{8});P=([0-9]{1,4})/([0-9]{1,4});O=([0-9]{1,7});N=([0-9]{1,3});D=([0-9A-F]{8})\n\n')
def sha(b):return hashlib.sha256(b).hexdigest()
def verify(name):
    assert re.fullmatch(r'[a-zA-Z0-9-]+',name)
    folder=LIVE/'captures'/name;manifest=json.loads((folder/'manifest.json').read_text())
    frames=[];screens=[];key=None
    for path in sorted(folder.glob('*.png')):
        with Image.open(path) as image:
            assert image.width*image.height<=32000000
            hits=[bytes(x.bytes) for x in zxingcpp.read_barcodes(image.convert('RGB'),formats=zxingcpp.BarcodeFormat.QRCode) if FRAME.match(bytes(x.bytes))]
        assert len(hits)==1,(name,path.name,len(hits))
        raw=hits[0];m=FRAME.match(raw);prefix,t,c,p,pages,offset,n,d=m.groups()
        t,p,pages,offset,n=map(int,(t,p,pages,offset,n));c=int(c,16);d=int(d,16);data=raw[m.end():]
        assert 0<t<=2097152 and pages==(t+511)//512 and 1<=p<=pages
        assert offset==(p-1)*512 and n==min(512,t-offset)==len(data) and zlib.crc32(data)==d
        current=(prefix,t,c,pages)
        assert key is None or key==current
        key=current;frames.append((p,data))
        assert raw==(folder/(path.stem+'.qr.bin')).read_bytes()
        digest=sha(path.read_bytes())
        assert digest==next(x['sha256'] for x in manifest['screens'] if x['page']==p)
        screens.append({'page':p,'path':path.relative_to(ROOT).as_posix(),'sha256':digest})
    assert key and len(frames)==key[3] and sorted(p for p,_ in frames)==list(range(1,key[3]+1))
    data=b''.join(b for p,b in sorted(frames))
    assert len(data)==key[1] and zlib.crc32(data)==key[2]
    assert data==(LIVE/(name+'.TXT')).read_bytes()
    assert manifest['pages']==len(frames) and manifest['bytes']==len(data)
    assert manifest['crc32']==f'{key[2]:08X}' and manifest['sha256']==sha(data)
    result={'passed':True,'source':(LIVE/(name+'.TXT')).relative_to(ROOT).as_posix(),
            'bytes':len(data),'pages':len(frames),'crc32':f'{key[2]:08X}','sha256':sha(data),
            'screens':screens,'independent_png_decode':True,'matched_parent_raw_frames_and_manifest':True,
            'no_hardware_access':True}
    (HERE/(name+'-qr-review.json')).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return {k:v for k,v in result.items() if k!='screens'}
if __name__=='__main__':print(json.dumps([verify(n) for n in sys.argv[1:]],indent=2))
