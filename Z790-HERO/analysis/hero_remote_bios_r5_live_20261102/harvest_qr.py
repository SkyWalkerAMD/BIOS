"""Collect a currently open R5 QR snapshot using only viewer page navigation."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,shutil,subprocess,sys,time
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('r2decoder',ROOT/'analysis/hero_remote_bios_r5/decode_captures.py')
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
p=argparse.ArgumentParser();p.add_argument('name');p.add_argument('--page',type=int,required=True);p.add_argument('--resume',action='store_true');a=p.parse_args()
assert a.name.replace('-','').replace('_','').isalnum()
dest=OUT/'captures'/a.name;dest.mkdir(parents=True,exist_ok=True)
def command(key=None):
    cmd=[sys.executable,'-X','utf8',str(OUT/'control.py'),'key' if key else 'capture']
    if key:cmd+=[key,'--wait-ms','1600']
    cmd+=['--page',str(a.page)]
    r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',check=True)
    m=json.loads(r.stdout);assert not m.get('pending');return Path(m['image'])
def read_frame(image,expected=None):
    for retry in range(6):
        try:
            raw=decoder.read_image(image);f=decoder.parse_frame(raw)
            if expected is None or f['page']==expected:return image,raw,f
            if f['page']>expected:raise RuntimeError('Unexpected page skip')
        except ValueError:pass
        time.sleep(.8);image=command()
    raise RuntimeError('QR did not settle or expected page not reached; no extra page key sent')
frames=[];rows=[]
existing=sorted(dest.glob('*.qr.bin'))
assert a.resume or not existing,'Use --resume to retain a partial capture'
first=None
for index,source in enumerate(existing,1):
    raw=source.read_bytes();f=decoder.parse_frame(raw)
    if first is None:first=f
    assert f['page']==index and (f['total'],f['crc'],f['pages'])==(first['total'],first['crc'],first['pages'])
    saved=dest/f'{index:03d}.png';assert saved.exists()
    assert decoder.read_image(saved)==raw,'Retained screenshot does not match frame'
    frames.append(raw)
    rows.append(dict(page=index,source='retained',sha256=hashlib.sha256(saved.read_bytes()).hexdigest()))
image,raw,f=read_frame(command())
if first is None:
    first=f
    assert first['page']==1,'Start on page 1 of the intended R5 snapshot'
assert first['pages']<=256
assert (f['total'],f['crc'],f['pages'])==(first['total'],first['crc'],first['pages']),'Snapshot changed; do not mix sessions'
assert f['page']<=len(frames)+1,'Missing page before current viewer position'
while f['page']<=len(frames) and len(frames)<first['pages']:
    assert raw==frames[f['page']-1],'Displayed duplicate differs from retained page'
    image,raw,f=read_frame(command('N'),f['page']+1)
for page in range(len(frames)+1,first['pages']+1):
    assert f['page']==page and (f['total'],f['crc'],f['pages'])==(first['total'],first['crc'],first['pages'])
    saved=dest/f'{page:03d}.png';shutil.copyfile(image,saved)
    (dest/f'{page:03d}.qr.bin').write_bytes(raw);frames.append(raw)
    rows.append(dict(page=page,source=image.relative_to(OUT).as_posix(),sha256=hashlib.sha256(saved.read_bytes()).hexdigest()))
    print(f'PAGE {page}/{first["pages"]} CRC verified',flush=True)
    if page<first['pages']:image,raw,f=read_frame(command('N'),page+1)
data,meta=decoder.assemble(frames)
target=OUT/(a.name+'.TXT');assert not target.exists() or target.read_bytes()==data
target.write_bytes(data)
(dest/'manifest.json').write_text(json.dumps(dict(**meta,screens=rows),indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(output=target.as_posix(),**meta)),flush=True)
