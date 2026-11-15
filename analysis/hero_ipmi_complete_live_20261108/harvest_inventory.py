"""Capture only an already-open inventory QR viewer; validate every page and total CRC."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,shutil,subprocess,sys,time
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
p=argparse.ArgumentParser();p.add_argument('name');p.add_argument('--page',type=int,required=True);p.add_argument('--kind',choices=['i1','i2','i2b','i2c','i3','i3b','i3d','r3','r3auto','r4','r4auto','i4','i5b','i5c','i5d','i5n','p6ram','p6ram2','p6ram3','p6ram4','p6a1'],default='i1');p.add_argument('--keepalive-page',type=int);a=p.parse_args()
decoder_path=ROOT/'analysis/hero_inventory_collect_20261108'/('decode_captures.py' if a.kind=='i1' else 'firmware_probe/i2-build/decode_captures.py')
if a.kind=='i3':decoder_path=ROOT/'analysis/hero_inventory_publish_20261108/decode_captures.py'
if a.kind=='i3b':decoder_path=ROOT/'analysis/hero_inventory_publish_i3b_20261108/decode_captures.py'
if a.kind=='i3d':decoder_path=ROOT/'analysis/hero_inventory_publish_i3d_20261108/decode_captures.py'
if a.kind=='i2b':decoder_path=ROOT/'analysis/hero_inventory_collect_20261108/firmware_probe/i2b-build/decode_captures.py'
if a.kind=='i2c':decoder_path=ROOT/'analysis/hero_fw_i2c_20261108/decode_captures.py'
if a.kind=='r3':decoder_path=ROOT/'analysis/hero_sensor_r3_20261108/decode_captures.py'
if a.kind=='r3auto':decoder_path=ROOT/'analysis/hero_r3_autoboot_test_20261108/decode_captures.py'
if a.kind=='r4':decoder_path=ROOT/'analysis/hero_sensor_r4_20261108/decode_captures.py'
if a.kind=='r4auto':decoder_path=ROOT/'analysis/hero_sensor_r4_20261108/autoboot/decode_captures.py'
if a.kind=='i4':decoder_path=ROOT/'analysis/hero_pcie_collect_i4_20261108/decode_captures.py'
if a.kind=='i5b':decoder_path=ROOT/'analysis/hero_inventory_i5_20261108/binding_probe/decode_captures.py'
if a.kind=='i5c':decoder_path=ROOT/'analysis/hero_inventory_i5_20261108/capture_fix/decode_captures.py'
if a.kind=='i5d':decoder_path=ROOT/'analysis/hero_inventory_i5_20261108/ip4_start_fix/decode_captures.py'
if a.kind=='i5n':decoder_path=ROOT/'analysis/hero_inventory_i5_20261108/bds_observer/decode_captures.py'
if a.kind=='p6ram':decoder_path=ROOT/'analysis/hero_p6_ramcheck_20261108/decode_captures.py'
if a.kind=='p6ram2':decoder_path=ROOT/'analysis/hero_p6_ramcheck2_20261108/decode_captures.py'
if a.kind=='p6ram3':decoder_path=ROOT/'analysis/hero_p6_ramcheck3_20261108/decode_captures.py'
if a.kind=='p6ram4':decoder_path=ROOT/'analysis/hero_p6_ramcheck4_20261108/decode_captures.py'
if a.kind=='p6a1':decoder_path=ROOT/'analysis/hero_p6_a1_diagnostic_20261108/decode_captures.py'
spec=importlib.util.spec_from_file_location('inventory_decoder',decoder_path)
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
assert a.name.replace('-','').replace('_','').isalnum()
dest=OUT/'captures'/a.name;dest.mkdir(parents=True,exist_ok=True)
assert not list(dest.glob('*.qr.bin')),'Existing capture: do not mix sessions'
def command(action,value):
    args=[sys.executable,'-X','utf8',str(OUT/'control.py'),action,value,'--page',str(a.page)]
    if action=='key':args+=['--wait-ms','800']
    r=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',check=True)
    assert '"ok": true' in r.stdout and 'pending' not in r.stdout,r.stdout
def capture(expected=None):
    for retry in range(5):
        name=a.name+'-working.png';command('capture',name);image=OUT/'screens'/name
        try:
            raw=decoder.read_image(image);f=decoder.parse_frame(raw)
            if expected is None or f['page']==expected:return image,raw,f
            if f['page']>expected:raise RuntimeError('Unexpected page skip; stopped')
        except ValueError:pass
        time.sleep(.5)
    raise RuntimeError('QR not settled; no extra page key sent')
image,raw,f=capture();first=f
assert first['page']==1 and first['pages']<=(4096 if a.kind in ('i3b','i3d','i4','p6a1') else 544 if a.kind in ('p6ram','p6ram2','p6ram3','p6ram4') else 256)
frames=[];rows=[]
for page in range(1,first['pages']+1):
    assert f['page']==page and (f['total'],f['crc'],f['pages'])==(first['total'],first['crc'],first['pages'])
    saved=dest/f'{page:03d}.png';shutil.copyfile(image,saved)
    (dest/f'{page:03d}.qr.bin').write_bytes(raw);frames.append(raw)
    rows.append(dict(page=page,sha256=hashlib.sha256(saved.read_bytes()).hexdigest()))
    print(f'PAGE {page}/{first["pages"]} CRC verified',flush=True)
    if a.keepalive_page is not None and page%40==0 and page<first['pages']:
        # Sequential with KVM commands; renew the ordinary web session during
        # long captures. No power operation, key, or inventory write is sent.
        # A same-hash navigation can be served entirely by the browser and
        # does not renew the BMC session. Use the observed page client so its
        # normal CSRF/session headers are retained; never export credentials.
        expression="""(async()=>{if(typeof window.jQuery!=='function')throw Error('Page client unavailable');
          return await new Promise(resolve=>window.jQuery.ajax({
            url:'/api/host_inventory/host_interface_system_info',type:'GET',dataType:'json',timeout:10000,
            success:(_data,_status,x)=>resolve({status:x.status,session_read:true}),
            error:x=>resolve({status:x.status,session_read:false})}));})()"""
        cmd=dict(action='evaluate',page=a.keepalive_page,expression=expression)
        keep=subprocess.run([sys.executable,'-X','utf8',str(OUT/'command.py'),json.dumps(cmd)],capture_output=True,text=True,encoding='utf-8',check=True)
        result=json.loads(keep.stdout[keep.stdout.index('{'):])
        assert result.get('ok') and result.get('result',{}).get('status')==200 and result['result'].get('session_read'), 'Web session changed; stop without further KVM keys'
    if page<first['pages']:command('key','N');image,raw,f=capture(page+1)
data,meta=decoder.assemble(frames)
target=OUT/(a.name+'.TXT');assert not target.exists() or target.read_bytes()==data
target.write_bytes(data)
(dest/'manifest.json').write_text(json.dumps(dict(**meta,screens=rows),indent=2)+'\n')
print(json.dumps(dict(output=target.as_posix(),**meta)),flush=True)
