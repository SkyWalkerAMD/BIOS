"""Own-directory snapshot of the13-instance explicit composite parser fixture.

Never executes a frozen module's main/run-report functions. The native parser
uses the earlier two RAM-only bounds experiments; only its data is imported by
the future UI VM, whose original AMITSE executable remains unpatched at those
two sites. This is not a claim of complete original startup.
"""
from pathlib import Path
import sys,importlib.util,hashlib,json,zipfile,time
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
source=B/'hardware_parser07/replay_hardware.py'
spec=importlib.util.spec_from_file_location('ui08_hardware_parser_model',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 started=time.monotonic();v=m.HardwareVM(changed=False,strict_bounds=True)
 assert v.run()==0 and not v.pool_guard_error
 table=v.rq(m.TSE+0xbaaf0);blob=v.rq(m.TSE+0xbabc0);cb=v.rq(m.TSE+0xbab08);count=v.rd(table)
 assert count==396;pages=[]
 def extent(p,n):return any(a<=p and p+n<=a+z for a,z in v.live.items()) or v.static<=p and p+n<=v.static+v.static_extent
 for i in range(count):
  raw=blob+v.rd(table+4+4*i);assert extent(raw,32)
  hii=v.rq(raw);form=v.rw(raw+10);nc=v.rd(raw+28);assert nc<=4096 and extent(raw,32+nc*4)
  row={'index':i,'raw':raw,'hii':hii,'form':form,'module':v.package_models.get(hii,{}).get('module'),'controls':[]}
  if hii in v.package_models:
   for j in range(nc):
    d=cb+v.rd(raw+32+4*j);assert extent(d,64);op=v.rq(d+40)
    if not op:
     row['controls'].append({'raw':d,'raw_hex':bytes(v.u.mem_read(d,64)).hex(),'type':v.rw(d+20),
       'opcode':0,'ifr':None,'question':None,'unresolved':'NULL_IFR_POINTER_NATIVE_PLACEHOLDER'});continue
    assert extent(op,2)
    n=bytes(v.u.mem_read(op+1,1))[0]&127;assert 2<=n<=127 and extent(op,n)
    data=bytes(v.u.mem_read(op,n));row['controls'].append({'raw':d,'raw_hex':bytes(v.u.mem_read(d,64)).hex(),
      'type':v.rw(d+20),'opcode':op,'ifr':data.hex(),'question':int.from_bytes(data[6:8],'little')if n>=13 else None})
  pages.append(row)
 packages=[]
 state={'format':'W8900603-13-instance-composite-native-parser-data-v1','pool_base':0x10000000,'pool_bytes':v.next-0x10000000,
  'static_base':v.static,'static_bytes':v.static_extent,'tse_base':m.TSE,'pages':pages,
  'globals':{hex(r):v.rq(m.TSE+r)for r in(0xbaaf0,0xbabc0,0xbab08,0xbaae8)},
  'original_AMITSE_sha256':v.original_sha,'original_SPF_sha256':v.static_sha,
  'RAM_only_parser_bounds':m.PATCHES,'live_allocations':v.live,'models':[
   'Composite13 HII instances from different physical captures; handles remain model identities.',
   'UEFI allocation,strings,variable and callback-owner lookup services are explicit models.',
   'Two original parser branch comparisons changed in emulator RAM only; no boot claim.',
   'GUI VM imports data only, never these modified executable bytes.'],
  'native_parser_status':0,'hardware_actions':0,'firmware_changes':0}
 path=H/'parser13_snapshot.zip'
 with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED,compresslevel=6)as z:
  z.writestr('pool.bin',bytes(v.u.mem_read(0x10000000,v.next-0x10000000)))
  z.writestr('static.bin',bytes(v.u.mem_read(v.static,v.static_extent)))
  for i,(handle,p)in enumerate(sorted(v.package_models.items())):
   name=f'packages/{i:02d}.bin';z.writestr(name,p['data']);packages.append({'handle':handle,'module':p['module'],'guid':p['guid'],'forms':p['forms'],'member':name,'sha256':sha(p['data'])})
  state['packages']=packages;z.writestr('state.json',json.dumps(state,separators=(',',':')))
 result={'snapshot':{'path':path.relative_to(R).as_posix(),'bytes':path.stat().st_size,'sha256':sha(path.read_bytes())},
  'source_sha256':sha(Path(__file__).read_bytes()),'upstream_source_sha256':sha(source.read_bytes()),
  'pages':count,'instances':len(packages),'control_records':sum(len(p['controls'])for p in pages),
  'bound_control_opcodes':sum(bool(c['ifr'])for p in pages for c in p['controls']),
  'null_ifr_placeholders':sum(not c['ifr']for p in pages for c in p['controls']),'seconds':round(time.monotonic()-started,3),
  'all_outputs_owned_directory':True,'frozen_main_executed':False,'limits':state['models']}
 (H/'snapshot_preparation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
