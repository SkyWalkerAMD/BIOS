"""Compare original screenshot pixels, independently of image-viewer presentation."""
from pathlib import Path
import hashlib,json,re,struct,zlib
HERE=Path(__file__).resolve().parent
OLD=HERE.parent/'native_provider_persistence_simulation/runs/20261103_155325'
NEW=HERE/'runs/20261103_160209'
sha=lambda b:hashlib.sha256(b).hexdigest()
def pixels(path):
 raw=path.with_suffix('.ppm').read_bytes();head=re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s',raw);assert head
 w,h=map(int,head.groups());rgb=raw[head.end():];assert len(rgb)==w*h*3
 png=path.read_bytes();assert png[:8]==b'\x89PNG\r\n\x1a\n';pos=8;parts=[]
 while pos<len(png):
    n=struct.unpack_from('>I',png,pos)[0];kind=png[pos+4:pos+8];data=png[pos+8:pos+8+n];crc=struct.unpack_from('>I',png,pos+8+n)[0]
    assert zlib.crc32(kind+data)&0xffffffff==crc
    if kind==b'IDAT':parts.append(data)
    pos+=n+12
 scan=zlib.decompress(b''.join(parts));assert len(scan)==h*(1+w*3)
 assert all(scan[y*(w*3+1)]==0 for y in range(h))
 decoded=b''.join(scan[y*(w*3+1)+1:(y+1)*(w*3+1)]for y in range(h));assert decoded==rgb
 return w,h,rgb
def region(data,x,y,w,h):
 width,height,rgb=data;assert x+w<=width and y+h<=height
 return b''.join(rgb[(row*width+x)*3:(row*width+x+w)*3]for row in range(y,y+h))
def white(raw):return sum(1 for i in range(0,len(raw),3)if raw[i]>220 and raw[i+1]>220 and raw[i+2]>220)
paths={'old_enroll':OLD/'boot1/enroll_a-prompt.png','old_unlock':OLD/'boot2/unlock_b-prompt.png',
       'new_unlock':NEW/'boot2/unlock_b-prompt.png','new_wrong':NEW/'boot1/wrong_a-prompt.png'}
images={k:pixels(p)for k,p in paths.items()};checks=[]
for name,rect in [('Ai Tweaker common title prefix',(239,104,88,20)),('ESC cancels common help prefix',(239,142,88,20))]:
 a=region(images['old_enroll'],*rect);b=region(images['old_unlock'],*rect)
 assert a==b and white(a)>100,(name,white(a),white(b))
 checks.append({'region':name,'rectangle_xywh':rect,'enroll_and_unlock_pixels_identical':True,'nonbackground_white_pixels':white(a),'rgb_sha256':sha(a)})
assert paths['old_unlock'].read_bytes()==paths['new_unlock'].read_bytes()==paths['new_wrong'].read_bytes()
report={'status':'ORIGINAL_SCREENSHOT_PREFIXES_PRESENT_IDENTICAL_PIXELS_NO_RENDERING_FIX_DEMONSTRATED',
 'images':{k:{'path':str(p),'png_sha256':sha(p.read_bytes()),'white_pixels':white(images[k][2]),'png_rgb_equals_original_ppm':True}for k,p in paths.items()},
 'checks':checks,'conclusion':'The old and proposed-refresh unlock screenshots are byte-identical. Their common title/help-prefix regions match the full original enrollment screen and contain foreground glyph pixels. Different apparent prefixes or blank image-viewer presentations cannot be actual differences in these files.',
 'limits':'This corrects the screenshot interpretation only. It does not validate the full ASUS GUI or all possible console firmware implementations.',
 'test_source_sha256':sha(Path(__file__).read_bytes())}
(HERE/'raw_screenshot_verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'status':report['status'],'checks':checks}))
